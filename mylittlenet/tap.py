from io import FileIO
from contextlib import contextmanager
import platform
from fcntl import ioctl
import struct


def open_tap(name: str):
    match platform.system():
        case "Linux":
            return __open_tap_linux(name)
        case _:  # pragma: no cover
            raise NotImplementedError("Unsupported platform")


@contextmanager
def __open_tap_linux(name: str):
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000
    TUNSETIFF = 0x400454CA

    tap = open("/dev/net/tun", "r+b", buffering=0)
    ifr = struct.pack("16sH", name.encode("utf-8"), IFF_TAP | IFF_NO_PI)
    ioctl(tap, TUNSETIFF, ifr)

    try:
        yield tap
    finally:
        tap.close()
