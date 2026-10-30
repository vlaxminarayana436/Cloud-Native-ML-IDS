import random
import sys

import pytest
import agent
import policy_enforcer as firewall
from app.access import evaluate


def test_sentinel_requires_explicit_mode(monkeypatch, capsys):
    monkeypatch.delenv('AGENT_MODE', raising=False)
    monkeypatch.setattr(sys, 'argv', ['agent.py'])
    with pytest.raises(SystemExit) as exc:
        agent.main()
    assert exc.value.code == 2
    assert 'Choose --mode live or --mode synthetic' in capsys.readouterr().err


def test_synthetic_flows_are_labeled_and_well_formed():
    for _ in range(50):
        row = agent.demo_flow('example', random.Random(_))
        assert row['traffic_source'] == 'synthetic' and row['agent_id'] == 'example'
        assert row['byte_count'] > 0 and row['packet_count'] > 0


def test_commander_traffic_excluded_both_directions():
    hosts = {'10.0.0.5'}
    assert agent.is_commander_flow('10.0.0.6','10.0.0.5',1234,8000,hosts,8000)
    assert agent.is_commander_flow('10.0.0.5','10.0.0.6',8000,1234,hosts,8000)
    assert not agent.is_commander_flow('10.0.0.5','10.0.0.6',80,1234,hosts,8000)


def test_live_flow_window_and_queue_overflow_accounting():
    row = agent.Flow(('8.8.8.8','10.0.0.4',4444,443,'TCP'), 100, 100)
    row.add(100, 60, 'S'); row.add(101, 70, 'A')
    flows = {row.key:row}; sent = []
    assert agent.flush_due_flows(flows, 102, 'sentinel', 5, 5, lambda event: sent.append(event) or True) == 0
    assert not sent
    assert agent.flush_due_flows(flows, 106, 'sentinel', 5, 5, lambda event: sent.append(event) or True) == 0
    assert not flows and sent[0]['traffic_source'] == 'capture'
    assert sent[0]['packet_count'] == 2 and sent[0]['iat_mean'] == 1
    flows = {row.key:row}
    assert agent.flush_due_flows(flows, 106, 'sentinel', 5, 5, lambda _: False) == 1


def test_enforcer_address_and_scope_guards():
    for value in ['127.0.0.1','0.0.0.0','224.0.0.2','169.254.1.1','::1','bad']:
        assert firewall.safe_block_host(value) is None
    assert firewall.safe_block_host('8.8.8.8') == '8.8.8.8/32'
    assert firewall.network('0.0.0.0/0') is None
    assert firewall.network('10.1.2.0/24', private=True) == '10.1.2.0/24'
    assert firewall.network('8.8.8.0/24', private=True) is None
    assert firewall.port_arg('8000-8002') == '8000:8002'
    assert firewall.port_arg('0-5') is None


def test_enforcer_compilation_is_opt_in_and_respects_scope():
    bundle = {'settings':{'enabled':True,'mode':'monitor','egress_enabled':False},'trusted_networks':[{'cidr':'10.1.1.0/24','enabled':True}], 'resources':[{'name':'API','destination_cidr':'192.168.1.10/32','protocol':'TCP','ports':['443'],'enabled':True}]}
    assert firewall.compile_access(bundle) == ([], [])
    bundle['settings']['mode'] = 'enforce'
    incoming, forward = firewall.compile_access(bundle)
    assert ['-s','10.1.1.0/24','-d','192.168.1.10/32','-p','tcp','--dport','443','-j','RETURN'] in incoming
    assert ['-d','192.168.1.10/32','-p','tcp','--dport','443','-j','DROP'] in incoming
    assert incoming == forward
    bundle['resources'][0]['destination_cidr'] = '0.0.0.0/0'
    assert firewall.compile_access(bundle) == ([], [])


def test_enforcer_only_receives_active_explicitly_eligible_ipv4(monkeypatch):
    class Response:
        def raise_for_status(self): pass
        def json(self): return [
            {'ip':'8.8.8.8','active':True,'enforceable':True},
            {'ip':'1.1.1.1','active':True,'enforceable':False},
            {'ip':'9.9.9.9','active':False,'enforceable':True},
            {'ip':'127.0.0.1','active':True,'enforceable':True},
            {'ip':'2001:4860:4860::8888','active':True,'enforceable':True},
        ]
    class Session:
        def get(self, *args, **kwargs): return Response()
    calls = []
    worker = firewall.Enforcer(Session(), 'http://example/api/v1', blocklist=True)
    monkeypatch.setattr(worker, 'sync_hook', lambda key, rules, established: calls.append((key,rules,established)) or True)
    worker.refresh()
    assert len(calls) == 2
    assert all(rules == [['-s','8.8.8.8/32','-j','DROP']] and not established for _,rules,established in calls)


def test_policy_egress_only_applies_to_managed_source():
    policy = {'settings':{'enabled':True,'mode':'enforce','egress_enabled':True,'egress_cidrs':['192.168.4.0/24']}, 'trusted_networks':[], 'resources':[]}
    base = {'src_ip':'192.168.4.10','dst_ip':'8.8.8.8','protocol':'TCP','dst_port':443}
    assert evaluate(base, policy)['decision'] == 'unregistered_egress'
    assert evaluate({**base, 'src_ip':'192.168.5.10'}, policy)['decision'] == 'allow'
    assert evaluate({**base, 'dst_ip':'10.0.0.1'}, policy)['decision'] == 'allow'
