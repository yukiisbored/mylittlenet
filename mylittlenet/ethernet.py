from dataclasses import dataclass
from enum import Enum
import struct

@dataclass
class MacAddress:
    b: bytes

    @classmethod
    def from_str(cls, mac: str) -> "MacAddress":
        return cls(bytes.fromhex(mac.replace(":", "")))

    def __str__(self) -> str:
        return ":".join(f"{b:02x}" for b in self.b)

    def __bytes__(self) -> bytes:
        return self.b

    def __repr__(self) -> str:
        return str(self)


@dataclass
class Frame:
    Struct = struct.Struct("!6s6sH")

    class Type(Enum):
        IPv4 = 0x0800
        ARP = 0x0806
        IPv6 = 0x86DD

    dst: MacAddress
    src: MacAddress
    type: Type
    payload: bytes

    @classmethod
    def from_bytes(cls, bytes) -> "Frame":
        dst, src, type = cls.Struct.unpack(bytes[:14])
        payload = bytes[14:]
        return cls(
            MacAddress(dst),
            MacAddress(src),
            cls.Type(type),
            payload
        )

    def __bytes__(self) -> bytes:
        return (
            self.Struct.pack(
                bytes(self.dst),
                bytes(self.src),
                self.type.value
            )
            + self.payload
        )
