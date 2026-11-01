from __future__ import annotations
import time
from ipaddress import ip_address
from typing import Literal
from pydantic import BaseModel, Field, field_validator, model_validator
from .access import ports, private_cidr, trusted_cidr

class Flow(BaseModel):
    timestamp:float=Field(default_factory=time.time,allow_inf_nan=False)
    agent_id:str=Field(default='unreported-agent',min_length=1,max_length=100)
    traffic_source:Literal['capture','synthetic','unknown']='unknown'
    src_ip:str; dst_ip:str
    src_port:int|None=Field(default=None,ge=0,le=65535); dst_port:int|None=Field(default=None,ge=0,le=65535)
    protocol:str='TCP'
    flow_duration:float=Field(ge=0,le=1e12,allow_inf_nan=False); packet_count:int=Field(ge=0,le=10**12); byte_count:int=Field(ge=0,le=10**12)
    iat_mean:float=Field(ge=0,le=1e12,allow_inf_nan=False); average_packet_size:float=Field(ge=0,le=1e12,allow_inf_nan=False)
    syn_count:int=Field(ge=0,le=10**12); ack_count:int=Field(ge=0,le=10**12); syn_ack_ratio:float=Field(ge=0,le=1e12,allow_inf_nan=False)
    @field_validator('src_ip','dst_ip')
    @classmethod
    def validate_ip(cls,value): return str(ip_address(value))
    @field_validator('protocol')
    @classmethod
    def protocol_name(cls,value): return value.strip().upper() or 'OTHER'

class Heartbeat(BaseModel):
    agent_id:str=Field(min_length=1,max_length=100); traffic_source:Literal['capture','synthetic','unknown']; interface:str|None=Field(default=None,max_length=150)

class Block(BaseModel):
    ip:str; reason:str=Field(default='Manual review',max_length=160)
    @field_validator('ip')
    @classmethod
    def validate_ip(cls,value):
        address=ip_address(value)
        if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local or address.is_reserved: raise ValueError('Local, unspecified, multicast and reserved addresses cannot be blocked')
        return str(address)

class Network(BaseModel):
    label:str=Field(min_length=2,max_length=80); cidr:str; kind:Literal['office','vpn','employee','partner','other']='office'
    @field_validator('label')
    @classmethod
    def clean_label(cls,value):
        value=' '.join(value.split())
        if len(value)<2: raise ValueError('Enter a network label')
        return value
    @field_validator('cidr')
    @classmethod
    def cidr_scope(cls,value): return trusted_cidr(value)

class Resource(BaseModel):
    name:str=Field(min_length=2,max_length=80); destination_cidr:str; protocol:Literal['TCP','UDP','ANY']='TCP'; ports:list[str]|str
    @field_validator('name')
    @classmethod
    def clean_name(cls,value):
        value=' '.join(value.split())
        if len(value)<2: raise ValueError('Enter a resource name')
        return value
    @field_validator('destination_cidr')
    @classmethod
    def destination_scope(cls,value): return private_cidr(value)
    @field_validator('ports')
    @classmethod
    def port_scope(cls,value): return ports(value)

class PolicySettings(BaseModel):
    enabled:bool=True; mode:Literal['monitor','enforce']='monitor'; egress_enabled:bool=False; egress_cidrs:list[str]=Field(default_factory=list,max_length=32)
    @field_validator('egress_cidrs')
    @classmethod
    def scope(cls,values): return [private_cidr(v) for v in values]
    @model_validator(mode='after')
    def enabled_egress_has_scope(self):
        if self.egress_enabled and not self.egress_cidrs: raise ValueError('Add at least one managed source scope before enabling egress guard')
        return self

class Toggle(BaseModel): enabled:bool

class EventReview(BaseModel):
    label:Literal['benign','malicious','unsure']
    note:str=Field(default='',max_length=500)
    @field_validator('note')
    @classmethod
    def clean_note(cls,value): return value.strip()

class Approval(BaseModel):
    label:str=Field(min_length=2,max_length=80)
    @field_validator('label')
    @classmethod
    def clean(cls,value):
        value=' '.join(value.split())
        if len(value)<2: raise ValueError('Enter a pattern label')
        if '_'.join(value.split()).lower()=='normal': raise ValueError('Reject benign patterns instead of labeling them Normal')
        return value
