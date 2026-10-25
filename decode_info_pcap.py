#!/usr/bin/env python3
"""Extract and decode the final payload in info.pcap (standard library only)."""
import socket
import struct
import sys
import zlib
from pathlib import Path

FRAME_NO = 7679
XOR_KEY = bytes.fromhex("13374299ABCD")
COLUMN_ORDER = [1, 0, 5, 3, 2, 6, 4]
# Zero-based row order; the all-NUL row (row 5) is padding and omitted.
ROW_ORDER = [0, 3, 4, 2, 6, 1]


def extract_frame_payload(pcap_path: Path, wanted_frame: int) -> tuple[bytes, tuple[str, int, str, int]]:
    data = pcap_path.read_bytes()
    magic = data[:4]
    if magic in (bytes.fromhex("d4c3b2a1"), bytes.fromhex("4d3cb2a1")):
        endian = "<"
    elif magic in (bytes.fromhex("a1b2c3d4"), bytes.fromhex("a1b23c4d")):
        endian = ">"
    else:
        raise ValueError(f"Unsupported PCAP magic: {magic.hex()}")

    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    if linktype != 1:
        raise ValueError(f"Expected Ethernet PCAP (linktype 1), got {linktype}")

    offset = 24  # classic PCAP global header
    frame_no = 0
    while offset + 16 <= len(data):
        _ts_sec, _ts_frac, captured_len, _original_len = struct.unpack_from(
            endian + "IIII", data, offset
        )
        offset += 16
        frame = data[offset : offset + captured_len]
        offset += captured_len
        frame_no += 1
        if frame_no != wanted_frame:
            continue

        if len(frame) < 14:
            raise ValueError("Target Ethernet frame is too short")

        ether_type = struct.unpack_from("!H", frame, 12)[0]
        ip_offset = 14
        # Skip VLAN tags, if present.
        while ether_type in (0x8100, 0x88A8, 0x9100):
            ether_type = struct.unpack_from("!H", frame, ip_offset + 2)[0]
            ip_offset += 4

        if ether_type != 0x0800:
            raise ValueError(f"Frame {wanted_frame} is not IPv4")
        if len(frame) < ip_offset + 20:
            raise ValueError("Truncated IPv4 header")

        ihl = (frame[ip_offset] & 0x0F) * 4
        ip_total_len = struct.unpack_from("!H", frame, ip_offset + 2)[0]
        if frame[ip_offset + 9] != 6:
            raise ValueError(f"Frame {wanted_frame} is not TCP")

        tcp_offset = ip_offset + ihl
        src_port, dst_port = struct.unpack_from("!HH", frame, tcp_offset)
        tcp_header_len = (frame[tcp_offset + 12] >> 4) * 4
        payload_start = tcp_offset + tcp_header_len
        payload_end = min(ip_offset + ip_total_len, len(frame))
        payload = frame[payload_start:payload_end]

        src_ip = socket.inet_ntoa(frame[ip_offset + 12 : ip_offset + 16])
        dst_ip = socket.inet_ntoa(frame[ip_offset + 16 : ip_offset + 20])
        return payload, (src_ip, src_port, dst_ip, dst_port)

    raise ValueError(f"Frame {wanted_frame} not found")


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("info.pcap")
    payload, endpoints = extract_frame_payload(path, FRAME_NO)
    print(f"Frame {FRAME_NO}: {endpoints[0]}:{endpoints[1]} -> {endpoints[2]}:{endpoints[3]}")
    print(f"Payload length: {len(payload)} bytes")

    xored = bytes(value ^ XOR_KEY[i % len(XOR_KEY)] for i, value in enumerate(payload))
    record = zlib.decompress(xored)
    if record[:4] != bytes.fromhex("DEADBEEF"):
        raise ValueError("Unexpected record marker")
    body_len = int.from_bytes(record[4:8], "little")
    body = record[8:]
    if body_len != 49 or len(body) != body_len:
        raise ValueError(f"Unexpected record length: declared={body_len}, actual={len(body)}")

    # Decode to Latin-1 so every byte survives, including NULs as '\x00'.
    grid = [body[i : i + 7].decode("latin1") for i in range(0, len(body), 7)]
    column_reordered = ["".join(row[col] for col in COLUMN_ORDER) for row in grid]

    print("Rows after column reordering (NULs retained):")
    for i, row in enumerate(column_reordered):
        print(f"  {i}: {row!r}")

    # This row/column reconstruction is inferred from the fragments. It is not
    # part of the XOR+zlib recipe itself; the CTF validator should be used for
    # authoritative acceptance.
    candidate = "".join(column_reordered[row] for row in ROW_ORDER).replace("\x00", "")
    leet_map = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s"})
    print("Reconstructed candidate:", candidate)
    print("Leetspeak reading:", candidate.translate(leet_map))


if __name__ == "__main__":
    main()
