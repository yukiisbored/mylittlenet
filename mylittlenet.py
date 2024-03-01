#!/usr/bin/env python3

import struct
from fcntl import ioctl
from dataclasses import dataclass
from enum import Enum
from contextlib import contextmanager
from typing import Callable


def mac_to_bytes(mac: str):
    return bytes.fromhex(mac.replace(":", ""))


def bytes_to_mac(bytes: bytes):
    return ":".join(f"{b:02x}" for b in bytes)


def ipv4_to_bytes(ip: str):
    return bytes(map(int, ip.split(".")))


def bytes_to_ipv4(bytes: bytes):
    return ".".join(map(str, bytes))


@dataclass
class Interface:
    name: str
    mac: bytes
    ip: bytes
    netmask: bytes
    read: Callable[[int], bytes]
    write: Callable[[bytes], int]

    def __repr__(self):
        mac = bytes_to_mac(self.mac)
        ip = bytes_to_ipv4(self.ip)
        netmask = bytes_to_ipv4(self.netmask)
        return f"Interface(name={self.name}, mac={mac}, ip={ip}, netmask={netmask})"


@dataclass
class EthernetFrame:
    class Type(Enum):
        IPv4 = 0x0800
        ARP = 0x0806
        IPv6 = 0x86DD

    dst: bytes
    src: bytes
    type: Type
    payload: bytes

    @classmethod
    def from_bytes(cls, bytes):
        dst, src, type = struct.unpack("!6s6sH", bytes[:14])
        payload = bytes[14:]
        return cls(dst, src, cls.Type(type), payload)

    def __bytes__(self):
        return struct.pack("!6s6sH", self.dst, self.src, self.type.value) + self.payload

    def __repr__(self):
        src = bytes_to_mac(self.src)
        dst = bytes_to_mac(self.dst)
        return f"EthernetFrame(dst={src}, src={dst}, type={self.type}, payload={self.payload})"


@dataclass
class ARP:
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
    smac: bytes
    sip: bytes
    dmac: bytes
    dip: bytes

    @classmethod
    def from_bytes(cls, bytes):
        hwtype, ptype, hwlen, plen, op, smac, sip, dmac, dip = struct.unpack(
            "!HHBBH6s4s6s4s", bytes
        )
        return cls(cls.HardwareType(hwtype), cls.ProtocolType(ptype), hwlen, plen, cls.Operation(op), smac, sip, dmac, dip)

    def __bytes__(self):
        return struct.pack(
            "!HHBBH6s4s6s4s",
            self.hwtype.value,
            self.ptype.value,
            self.hwlen,
            self.plen,
            self.op.value,
            self.smac,
            self.sip,
            self.dmac,
            self.dip,
        )

    def __repr__(self):
        smac = bytes_to_mac(self.smac)
        sip = bytes_to_ipv4(self.sip)
        dmac = bytes_to_mac(self.dmac)
        dip = bytes_to_ipv4(self.dip)

        return f"ARP(hwtype={self.hwtype}, ptype={self.ptype}, hwlen={self.hwlen}, plen={self.plen}, op={self.op}, smac={smac}, sip={sip}, dmac={dmac}, dip={dip})"


@dataclass
class IPv4:
    @dataclass
    class Header:
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
        src: bytes
        dst: bytes

        @classmethod
        def from_bytes(cls, bytes):
            version_ihl, tos, len, id, flags, ttl, protocol, checksum, src, dst = struct.unpack(
                "!BBHHHBBH4s4s", bytes[:20]
            )
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            return cls(version, ihl, tos, len, id, flags, ttl, cls.Protocol(protocol), checksum, src, dst)

        def __bytes__(self):
            version_ihl = (self.version << 4) | self.ihl
            return struct.pack(
                "!BBHHHBBH4s4s",
                version_ihl,
                self.tos,
                self.len,
                self.id,
                self.flags,
                self.ttl,
                self.protocol.value,
                self.checksum,
                self.src,
                self.dst,
            )

        def __repr__(self):
            src = bytes_to_ipv4(self.src)
            dst = bytes_to_ipv4(self.dst)
            return f"Header(version={self.version}, ihl={self.ihl}, tos={self.tos}, len={self.len}, id={self.id}, flags={self.flags}, ttl={self.ttl}, protocol={self.protocol}, checksum={self.checksum}, src={src}, dst={dst})"

    header: Header
    payload: bytes

    @classmethod
    def from_bytes(cls, bytes):
        header = cls.Header.from_bytes(bytes)
        payload = bytes[header.ihl * 4 :]
        return cls(header, payload)

    def __bytes__(self):
        return bytes(self.header) + self.payload

    def __repr__(self):
        return f"IPv4(header={self.header}, payload={self.payload})"


def ipv4_checksum(bytes):
    checksum = 0
    for i in range(0, len(bytes), 2):
        checksum += (bytes[i] << 8) | bytes[i + 1]
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF


@dataclass
class ICMPv4:
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
        type, code, checksum, id, seq = struct.unpack("!BBHHH", bytes[:8])
        payload = bytes[8:]
        return cls(cls.Type(type), code, checksum, id, seq, payload)

    def __bytes__(self):
        return struct.pack("!BBHHH", self.type.value, self.code, self.checksum, self.id, self.seq) + self.payload

    def __repr__(self):
        return f"ICMPv4(type={self.type}, code={self.code}, id={self.id}, seq={self.seq}, payload={self.payload})"


@contextmanager
def open_tap(name: str):
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000
    TUNSETIFF = 0x400454ca

    tap = open("/dev/net/tun", "r+b", buffering=0)
    ifr = struct.pack("16sH", name.encode("utf-8"), IFF_TAP | IFF_NO_PI)
    ioctl(tap, TUNSETIFF, ifr)

    try:
        yield tap
    finally:
        tap.close()


def handle_arp(interface: Interface, frame: EthernetFrame, arp: ARP):
    if arp.op == ARP.Operation.REQUEST and arp.dip == interface.ip:
        print(f"ARP request for {bytes_to_ipv4(arp.dip)}")
        reply = EthernetFrame(
            dst=frame.src,
            src=interface.mac,
            type=EthernetFrame.Type.ARP,
            payload=bytes(ARP(
                hwtype=ARP.HardwareType.ETHERNET,
                ptype=ARP.ProtocolType.IPv4,
                hwlen=6,
                plen=4,
                op=ARP.Operation.REPLY,
                smac=interface.mac,
                sip=interface.ip,
                dmac=arp.smac,
                dip=arp.sip,
            )),
        )
        interface.write(bytes(reply))
        print(f"ARP reply to {bytes_to_mac(arp.smac)}")


def handle_icmpv4(interface: Interface, frame: EthernetFrame, ipv4: IPv4, icmp: ICMPv4):
    if icmp.type == ICMPv4.Type.ECHO_REQUEST:
        print(f"ICMP echo request from {bytes_to_ipv4(ipv4.header.src)}")
        icmpv4 = ICMPv4(
            type=ICMPv4.Type.ECHO_REPLY,
            code=0,
            checksum=0,
            id=icmp.id,
            seq=icmp.seq,
            payload=icmp.payload,
        )
        icmpv4.checksum = ipv4_checksum(bytes(icmpv4))
        ipv4_payload = bytes(icmpv4)

        ipv4_header = IPv4.Header(
            version=4,
            ihl=5,
            tos=0,
            len=0,
            id=0,
            flags=0,
            ttl=64,
            protocol=IPv4.Header.Protocol.ICMP,
            checksum=0,
            src=interface.ip,
            dst=ipv4.header.src,
        )
        ipv4_header.len = len(bytes(ipv4_header)) + len(ipv4_payload)
        ipv4_header.checksum = ipv4_checksum(bytes(ipv4_header))
        ipv4 = IPv4(header=ipv4_header, payload=ipv4_payload)

        reply = EthernetFrame(
            dst=frame.src,
            src=interface.mac,
            type=EthernetFrame.Type.IPv4,
            payload=bytes(ipv4),
        )

        interface.write(bytes(reply))
        print(f"ICMP echo reply to {bytes_to_ipv4(ipv4.header.src)}")


def handle_ipv4(interface: Interface, frame: EthernetFrame, ipv4: IPv4):
    if ipv4.header.dst != interface.ip:
        return

    match ipv4.header.protocol:
        case IPv4.Header.Protocol.ICMP:
            icmp = ICMPv4.from_bytes(ipv4.payload)
            handle_icmpv4(interface, frame, ipv4, icmp)
        case _:
            print(ipv4)


def main():
    with open_tap("tap0") as tap:
        interface = Interface(
                name="tap0",
                mac=mac_to_bytes("00:11:22:33:44:55"),
                ip=ipv4_to_bytes("10.0.0.1"),
                netmask=ipv4_to_bytes("255.255.255.0"),
                read=tap.read,
                write=tap.write,
        )
        print(f"Interface: {interface}")

        while True:
            data = interface.read(1600)
            frame = EthernetFrame.from_bytes(data)

            match frame.type:
                case EthernetFrame.Type.ARP:
                    arp = ARP.from_bytes(frame.payload)
                    handle_arp(interface, frame, arp)
                case EthernetFrame.Type.IPv4:
                    ipv4 = IPv4.from_bytes(frame.payload)
                    handle_ipv4(interface, frame, ipv4)
                case EthernetFrame.Type.IPv6:
                    pass
                case _:
                    print(frame)


if __name__ == "__main__":
    main()
