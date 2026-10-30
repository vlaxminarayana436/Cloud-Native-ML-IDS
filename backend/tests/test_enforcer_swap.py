"""iptables behavior is mocked: these tests never change host firewall rules."""
import policy_enforcer as firewall


def configured_worker():
    worker = firewall.Enforcer(None, 'http://example', blocklist=True)
    return worker, worker.hooks['block_in']


def test_failed_staged_chain_does_not_replace_active_chain(monkeypatch):
    worker, (hook, dispatch, active, stage) = configured_worker()
    calls = []
    def fake(args):
        calls.append(args)
        if args == ['-C', dispatch, '-j', active]: return True
        if args[:2] == ['-A', stage] and '-s' in args: return False
        return True
    monkeypatch.setattr(firewall, 'run_iptables', fake)
    assert worker.sync_hook('block_in', [['-s','8.8.8.8/32','-j','DROP']], False) is False
    assert not any(args[:2] == ['-R',dispatch] for args in calls)
    assert ['-F',active] not in calls


def test_complete_staging_replaces_dispatch_without_flushing_active(monkeypatch):
    worker, (hook, dispatch, active, stage) = configured_worker()
    calls = []
    def fake(args):
        calls.append(args)
        return True
    monkeypatch.setattr(firewall, 'run_iptables', fake)
    assert worker.sync_hook('block_in', [['-s','8.8.8.8/32','-j','DROP']], False)
    assert ['-R',dispatch,'1','-j',stage] in calls
    assert ['-F',active] not in calls
    assert calls.index(['-A',stage,'-j','RETURN']) < calls.index(['-R',dispatch,'1','-j',stage])
