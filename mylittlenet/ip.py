from dataclasses import dataclass
from enum import Enum
import struct


def checksum(bytes) -> int:
    checksum = 0
    for i in range(0, len(bytes), 2):
        checksum += (bytes[i] << 8) | bytes[i + 1]
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF


@dataclass
class IPAddress:
    b: bytes

    @classmethod
    def from_str(cls, ip: str) -> "IPAddress":
        return cls(bytes(map(int, ip.split("."))))

    def __str__(self) -> str:
        return ".".join(map(str, self.b))

    def __bytes__(self) -> bytes:
        return self.b

    def __repr__(self) -> str:
        return str(self)


@dataclass
class Packet:
    @dataclass
    class Header:
        Struct = struct.Struct("!BBHHHBBH4s4s")

        class Protocol(Enum):
            ICMP = 1
            TCP = 6
            UDP = 17

        version: int
        ihl: int
        tos: int
        len: int
        id: int
        flags: int
        ttl: int
        protocol: Protocol
        checksum: int
        src: IPAddress
        dst: IPAddress

        @classmethod
        def from_bytes(cls, bytes):
            (
                version_ihl,
                tos,
                len,
                id,
                flags,
                ttl,
                protocol,
                checksum,
                src,
                dst,
            ) = cls.Struct.unpack(bytes[:20])
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            return cls(
                version,
                ihl,
                tos,
                len,
                id,
                flags,
                ttl,
                cls.Protocol(protocol),
                checksum,
                IPAddress(src),
                IPAddress(dst),
            )

        def __bytes__(self):
            version_ihl = (self.version << 4) | self.ihl
            return self.Struct.pack(
                version_ihl,
                self.tos,
                self.len,
                self.id,
                self.flags,
                self.ttl,
                self.protocol.value,
                self.checksum,
                bytes(self.src),
                bytes(self.dst),
            )

        def calculate_checksum(self) -> int:
            old = self.checksum
            self.checksum = 0
            res = checksum(bytes(self))
            self.checksum = old
            return res

    header: Header
    payload: bytes

    @classmethod
    def from_bytes(cls, bytes):
        header = cls.Header.from_bytes(bytes)
        payload = bytes[header.ihl * 4 :]
        return cls(header, payload)

    def __bytes__(self):
        return bytes(self.header) + self.payload


@dataclass
class ICMP:
    Struct = struct.Struct("!BBHHH")

    class Type(Enum):
        ECHO_REQUEST = 8
        ECHO_REPLY = 0

    type: Type
    code: int
    checksum: int
    id: int
    seq: int
    payload: bytes

    @classmethod
    def from_bytes(cls, bytes):
        type, code, checksum, id, seq = cls.Struct.unpack(bytes[:8])
        payload = bytes[8:]
        return cls(cls.Type(type), code, checksum, id, seq, payload)

    def __bytes__(self):
        return (
            self.Struct.pack(
                self.type.value, self.code, self.checksum, self.id, self.seq
            )
            + self.payload
        )

    def calculate_checksum(self) -> int:
        old = self.checksum
        self.checksum = 0
        res = checksum(bytes(self))
        self.checksum = old
        return res
