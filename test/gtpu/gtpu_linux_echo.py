#!/usr/bin/env python3

import socket
import struct
import sys


GTPU_PORT = 2152
REQ_TEID = 0x2001
RSP_TEID = 0x2002
GTPU_FLAGS = 0x30
GTPU_GPDU = 0xFF


def build_gtpu(teid: int, payload: bytes) -> bytes:
    return struct.pack("!BBHI", GTPU_FLAGS, GTPU_GPDU, len(payload), teid) + payload


def parse_gtpu(packet: bytes):
    if len(packet) < 8:
        raise ValueError("packet too short")
    flags, msg_type, length, teid = struct.unpack("!BBHI", packet[:8])
    if flags != GTPU_FLAGS or msg_type != GTPU_GPDU:
        raise ValueError("unsupported gtpu header")
    payload = packet[8:8 + length]
    return teid, payload


def main():
    bind_ip = sys.argv[1] if len(sys.argv) > 1 else "192.168.66.1"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_ip, GTPU_PORT))
    print(f"linux gtpu echo listening on {bind_ip}:{GTPU_PORT}")
    while True:
        packet, addr = sock.recvfrom(4096)
        teid, payload = parse_gtpu(packet)
        if teid != REQ_TEID:
            print(f"ignore unexpected TEID {teid:#x} from {addr}")
            continue
        sock.sendto(build_gtpu(RSP_TEID, payload), addr)
        print(f"echo {payload!r} to {addr}")


if __name__ == "__main__":
    main()