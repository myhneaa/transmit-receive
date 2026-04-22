#!/usr/bin/env python3
"""
Usage:
  python rx.py [port]
"""

import socket
import struct
import hashlib
import sys

# configuration
DEFAULT_PORT = 5005


def start_rx(port):
    # setup UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))

    print(f"[RX-PY] Listening on UDP port {port}...")
    print("-" * 60)

    # state variables
    packets = {}
    filename = ""
    max_seq = 0
    received_md5 = b""
    got_first = False
    got_last = False

    # receive loop
    while not got_last:
        data, addr = sock.recvfrom(65535)

        if len(data) < 6:
            continue  # packet too small, ignore

        # parsing common header
        trans_id, seq_nr = struct.unpack("!HI", data[:6])
        payload = data[6:]

        # FIRST PACKET (SeqNr = 0)
        if seq_nr == 0:
            max_seq = struct.unpack("!I", payload[:4])[0]
            filename = payload[4:].decode('utf-8')
            got_first = True
            print(f"[RX-PY] INIT Packet | TransID={trans_id} | MaxSeq={max_seq} | File='{filename}'")
            continue

        # LAST PACKET: SeqNr = max_seq + 1
        if got_first and seq_nr == max_seq + 1 and len(payload) == 16:
            received_md5 = payload
            got_last = True
            print(f"[RX-PY] FINAL Packet | MD5={received_md5.hex()}")
            continue

        # DATA PACKET
        if seq_nr >= 1:
            packets[seq_nr] = payload
            print(f"[RX-PY] DATA received | SeqNr={seq_nr}/{max_seq} | Length={len(payload)} bytes")

    sock.close()

    # reassemble file
    if not got_first or not got_last:
        print("[RX-PY] ERROR: Incomplete transmission. Missing first or last packet.")
        sys.exit(1)

    print("-" * 60)
    print(f"[RX-PY] Reassembling {len(packets)} chunks...")

    file_data = bytearray()
    for i in range(1, max_seq + 1):
        if i in packets:
            file_data.extend(packets[i])
        else:
            print(f"[RX-PY] WARNING: Missing chunk {i}")

    # verify MD5
    computed_md5 = hashlib.md5(file_data).digest()

    print(f"[RX-PY] Computed MD5 : {computed_md5.hex()}")
    print(f"[RX-PY] Received MD5 : {received_md5.hex()}")

    if computed_md5 == received_md5:
        out_name = f"received_{filename}"
        with open(out_name, "wb") as f:
            f.write(file_data)
        print(f"[RX-PY] SUCCESS: MD5 matches. File saved as '{out_name}'.")
    else:
        print("[RX-PY] ERROR: MD5 mismatch. The file may be corrupted.")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    start_rx(port)