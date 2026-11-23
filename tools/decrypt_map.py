#!/usr/bin/env python3
"""Decrypt an M73EdCard calibration map (*.map).

Format: 10-byte ASCII signature "M73EdCard\\0", then the body XOR-ed with a fixed
10-byte key. The key index restarts at the beginning of every written chunk
(record/field), and chunk boundaries are not stored, so the phase is recovered
with a Viterbi pass that prefers plaintext made of zeros / text / small numbers.

usage: decrypt_map.py ST10.map out.bin
"""
import sys

SIG = b"M73EdCard\x00"
KEY = bytes.fromhex("de58a299fa8497e055aa")
SWITCH_PENALTY = 6.0


def byte_score(b):
    if b == 0:
        return 3.0
    if 0x20 <= b < 0x7F or b >= 0xC0:
        return 1.0
    if b < 0x20:
        return 0.5
    return 0.0


def decrypt(raw):
    if not raw.startswith(SIG):
        raise SystemExit("not an M73EdCard file")
    body = raw[len(SIG):]
    n = len(body)
    # state p: byte i is decrypted with KEY[(i - p) % 10], i.e. the current
    # chunk started at an offset congruent to p.  A new chunk may start at any
    # byte i, which moves the state to p = i % 10.
    score = [0.0] + [-1e9] * 9
    back = bytearray(n)  # 1 = a new chunk starts at this byte
    for i, c in enumerate(body):
        q = i % 10
        best_prev = max(range(10), key=lambda p: score[p])
        restart = score[best_prev] - SWITCH_PENALTY
        if restart > score[q]:
            score[q] = restart
            back[i] = 1 + best_prev
        for p in range(10):
            score[p] += byte_score(c ^ KEY[(i - p) % 10])
    p = max(range(10), key=lambda q: score[q])
    phase = bytearray(n)
    for i in range(n - 1, -1, -1):
        phase[i] = p
        if back[i] and p == i % 10:
            p = back[i] - 1
    return bytes(c ^ KEY[(i - phase[i]) % 10] for i, c in enumerate(body))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    data = decrypt(open(sys.argv[1], "rb").read())
    open(sys.argv[2], "wb").write(data)
