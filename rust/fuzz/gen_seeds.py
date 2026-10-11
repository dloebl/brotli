#!/usr/bin/env python3
"""Generates seed corpora for the differential fuzzers from tests/testdata."""
import os, random, struct, subprocess, sys

here = os.path.dirname(os.path.abspath(__file__))
testdata = os.path.join(here, "..", "..", "tests", "testdata")
dec_dir = os.path.join(here, "corpus", "decode")
enc_dir = os.path.join(here, "corpus", "encode")
os.makedirs(dec_dir, exist_ok=True)
os.makedirs(enc_dir, exist_ok=True)
rnd = random.Random(1)
n = 0
for name in sorted(os.listdir(testdata)):
    path = os.path.join(testdata, name)
    data = open(path, "rb").read()
    if ".compressed" in name:
        for flags in (0, 8 | 32, 64, 1 | 16):
            hdr = bytes([flags, rnd.randrange(256), rnd.randrange(256), rnd.randrange(256)])
            open(os.path.join(dec_dir, "%s.%d" % (name, flags)), "wb").write(hdr + data[: 1 << 20])
            n += 1
    else:
        chunk = data[: 1 << 16]
        for q in (0, 1, 2, 4, 5, 6, 7, 9, 10, 11):
            hdr = bytearray(rnd.randrange(256) for _ in range(24))
            hdr[0] = q
            hdr[1] = rnd.choice([0, 6, 8, 12, 14])  # lgwin 10, 16, 18, 22, 24
            hdr[2] = rnd.choice([0, 0, 128, 64, 8, 16, 4])
            hdr[13] &= 0xFE
            hdr[15] &= 0x3F
            hdr[16] = 0
            hdr[20] &= 0x7F
            open(os.path.join(enc_dir, "%s.q%d" % (name, q)), "wb").write(bytes(hdr) + chunk)
            n += 1
print("wrote %d seeds" % n)
