#!/usr/bin/env python3
"""
Usage: 
  python tx.py <filepath | filename> <receiver_ip> <port>
"""

import socket
import struct
import hashlib
import os
import sys
import time
import random

# configuration
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5005
CHUNK_SIZE   = 1400   # bytes per data packet (safe UDP payload size)
HEADER_FORMAT   = "!HI"    # TransmissionID + SequenceNumber
HEADER_SIZE     = struct.calcsize(HEADER_FORMAT)   # = 6 bytes


def build_first_packet(trans_id: int, max_seq: int, filename: str) -> bytes:
    """SeqNr=0: Header + MaxSeqNr + FileName"""
    header  = struct.pack("!HII", trans_id, 0, max_seq)
    return header + filename.encode("utf-8")


def build_data_packet(trans_id: int, seq_nr: int, chunk: bytes) -> bytes:
    """SeqNr=1..max: Header + Data"""
    header = struct.pack(HEADER_FORMAT, trans_id, seq_nr)
    return header + chunk


def build_last_packet(trans_id: int, seq_nr: int, md5_digest: bytes) -> bytes:
    """Last packet: Header + MD5 (16 bytes)"""
    return struct.pack("!HI16s", trans_id, seq_nr, md5_digest)


def send_file(filepath: str, host: str, port: int):
    # file validation
    if not os.path.isfile(filepath):
        print(f"[TX-PY] ERROR: File not found: {filepath}")
        sys.exit(1)

    filename = os.path.basename(filepath)

    # reads file & prepares chunks
    with open(filepath, "rb") as f:
        file_data = f.read()

    chunks  = [file_data[i:i+CHUNK_SIZE] for i in range(0, len(file_data), CHUNK_SIZE)]
    max_seq = len(chunks)

    # compute MD5
    md5_digest = hashlib.md5(file_data).digest()   # always 16 bytes

    # random TransmissionID (16 bit - 0..65535)
    trans_id = random.randint(1, 65535)

    # setup UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"[TX-PY] Sending '{filename}' ({len(file_data)} bytes) to {host}:{port}")
    print(f"[TX-PY] TransmissionID={trans_id}, Chunks={max_seq}, MD5={md5_digest.hex()}")
    print("-" * 60)

    # FIRST PACKET (SeqNr = 0)
    pkt = build_first_packet(trans_id, max_seq, filename)
    sock.sendto(pkt, (host, port))
    print(f"[TX-PY] FIRST packet sent  | SeqNr=0 | MaxSeq={max_seq} | File='{filename}'")

    # DATA PACKETS (SeqNr = 1 .. max_seq)
    for i, chunk in enumerate(chunks):
        seq_nr = i + 1
        pkt = build_data_packet(trans_id, seq_nr, chunk)
        sock.sendto(pkt, (host, port))
        print(f"[TX-PY] DATA  packet sent  | SeqNr={seq_nr}/{max_seq} | {len(chunk)} bytes")
        time.sleep(0.001)   # tiny delay – avoids overwhelming the receiver

    # LAST PACKET
    last_seq = max_seq + 1
    pkt = build_last_packet(trans_id, last_seq, md5_digest)
    sock.sendto(pkt, (host, port))
    print(f"[TX-PY] LAST  packet sent  | SeqNr={last_seq} | MD5={md5_digest.hex()}")
    print("-" * 60)
    print("[TX-PY] Transmission complete.")

    sock.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tx.py <filepath> [receiver_ip] [port]")
        print("Example: python tx.py myfile.txt 127.0.0.1 5005")
        sys.exit(1)

    filepath = sys.argv[1]
    host     = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_HOST
    port     = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_PORT

    send_file(filepath, host, port)