from dataclasses import dataclass
from typing import Callable
import logging

from .ethernet import MacAddress, Frame
from .ip import IPAddress, Packet, ICMP
from .arp import ARP

logger = logging.getLogger(__name__)


@dataclass
class Interface:
    name: str
    mac: MacAddress
    ip: IPAddress
    netmask: IPAddress

    read: Callable[[int], bytes]
    write: Callable[[bytes], int]

    mtu: int = 1500

    def run(self):
        while True:
            data = self.read(self.mtu)
            frame = Frame.from_bytes(data)

            match frame.type:
                case Frame.Type.ARP:
                    self.handle_arp(frame)
                case Frame.Type.IPv4:
                    self.handle_ip(frame)
                case Frame.Type.IPv6:
                    pass

    def handle_arp(self, frame: Frame):
        payload = ARP.from_bytes(frame.payload)

        if payload.op != ARP.Operation.REQUEST:
            return

        if payload.dip != self.ip:
            return

        logger.debug(
            f"Received ARP request for {payload.dip} from {payload.sip} ({payload.smac})"
        )

        reply = Frame(
            dst=frame.src,
            src=self.mac,
            type=Frame.Type.ARP,
            payload=bytes(
                ARP(
                    hwtype=ARP.HardwareType.ETHERNET,
                    ptype=ARP.ProtocolType.IPv4,
                    hwlen=6,
                    plen=4,
                    op=ARP.Operation.REPLY,
                    smac=self.mac,
                    sip=self.ip,
                    dmac=payload.smac,
                    dip=payload.sip,
                )
            ),
        )

        self.write(bytes(reply))

        logger.debug(
            f"Sent ARP reply to {payload.sip} ({payload.smac}) that we're {self.ip} ({self.mac})"
        )

    def handle_ip(self, frame: Frame):
        payload = Packet.from_bytes(frame.payload)

        if payload.header.dst != self.ip:
            logger.debug(
                f"IP packet not for us: {payload.header.dst} from {payload.header.src}. "
                f"We're {self.ip}."
            )
            return

        if payload.header.checksum != payload.header.calculate_checksum():
            logger.debug("IP packet has invalid checksum")
            return

        match payload.header.protocol:
            case Packet.Header.Protocol.ICMP:
                self.handle_icmp(frame, payload)
            case _:
                logger.warning(f"Unhandled IP protocol: {payload.header.protocol}")

    def handle_icmp(self, frame: Frame, packet: Packet):
        payload = ICMP.from_bytes(packet.payload)

        match payload.type:
            case ICMP.Type.ECHO_REQUEST:
                self.handle_icmp_echo_request(frame, packet, payload)
            case _:
                logger.warning(f"Unhandled ICMP type: {payload.type}")

    def handle_icmp_echo_request(self, frame: Frame, packet: Packet, icmp: ICMP):
        logger.debug(f"Received ICMP echo request from {packet.header.src}")
        icmp_reply = ICMP(
            type=ICMP.Type.ECHO_REPLY,
            code=0,
            checksum=0,
            id=icmp.id,
            seq=icmp.seq,
            payload=icmp.payload,
        )
        icmp_reply.checksum = icmp_reply.calculate_checksum()
        packet_payload = bytes(icmp_reply)

        packet_header = Packet.Header(
            version=4,
            ihl=5,
            tos=0,
            len=0,
            id=0,
            flags=0,
            ttl=64,
            protocol=Packet.Header.Protocol.ICMP,
            checksum=0,
            src=self.ip,
            dst=packet.header.src,
        )
        packet_header.len = len(bytes(packet_header)) + len(packet_payload)
        packet_header.checksum = packet_header.calculate_checksum()
        packet = Packet(header=packet_header, payload=packet_payload)

        reply = Frame(
            dst=frame.src,
            src=self.mac,
            type=Frame.Type.IPv4,
            payload=bytes(packet),
        )

        self.write(bytes(reply))

        logger.debug(f"Sent ICMP echo reply to {packet.header.dst}")
