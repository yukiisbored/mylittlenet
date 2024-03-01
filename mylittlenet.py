#!/usr/bin/env python3

import logging

from mylittlenet.ethernet import MacAddress
from mylittlenet.ip import IPAddress
from mylittlenet.interface import Interface
from mylittlenet.tap import open_tap

logger = logging.getLogger(__name__)


def main():
    logging.basicConfig(
        level=logging.DEBUG,
        format="[%(asctime)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    with open_tap("tap0") as tap:
        interface = Interface(
            name="tap0",
            mac=MacAddress.from_str("00:11:22:33:44:55"),
            ip=IPAddress.from_str("10.0.0.1"),
            netmask=IPAddress.from_str("255.255.255.0"),
            read=tap.read,
            write=tap.write,
        )

        logger.info(f"Interface {interface.name}:")
        logger.info(f"  - MAC     : {interface.mac}")
        logger.info(f"  - IP      : {interface.ip}")
        logger.info(f"  - Netmask : {interface.netmask}")

        interface.run()


if __name__ == "__main__":
    main()
