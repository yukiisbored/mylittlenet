from dataclasses import dataclass
from enum import Enum
import struct

from .ethernet import MacAddress
from .ip import IPAddress


@dataclass
class ARP:
    Struct = struct.Struct("!HHBBH6s4s6s4s")

    class Operation(Enum):
        REQUEST = 1
        REPLY = 2

    class HardwareType(Enum):
        ETHERNET = 1

    class ProtocolType(Enum):
        IPv4 = 0x0800

    hwtype: HardwareType
    ptype: ProtocolType
    hwlen: int
    plen: int
    op: Operation
    smac: MacAddress
    sip: IPAddress
    dmac: MacAddress
    dip: IPAddress

    @classmethod
    def from_bytes(cls, bytes):
        hwtype, ptype, hwlen, plen, op, smac, sip, dmac, dip = cls.Struct.unpack(bytes)
        return cls(
            cls.HardwareType(hwtype),
            cls.ProtocolType(ptype),
            hwlen,
            plen,
            cls.Operation(op),
            MacAddress(smac),
            IPAddress(sip),
            MacAddress(dmac),
            IPAddress(dip),
        )

    def __bytes__(self):
        return self.Struct.pack(
            self.hwtype.value,
            self.ptype.value,
            self.hwlen,
            self.plen,
            self.op.value,
            bytes(self.smac),
            bytes(self.sip),
            bytes(self.dmac),
            bytes(self.dip),
        )
