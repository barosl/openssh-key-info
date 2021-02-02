#!/usr/bin/env python3

# An analysis of the OpenSSH private key format: https://coolaj86.com/articles/the-openssh-private-key-format/

import base64
import struct
import argparse
from pathlib import Path
import re

def read_text(buf, pos):
    text_len = struct.unpack('>i', buf[pos:pos+4])[0]
    new_idx = pos+4+text_len
    text = buf[pos+4:new_idx]
    assert len(text) == text_len
    return text, new_idx

def parse_key(fpath):
    print(f'File: {fpath}')

    text = Path(fpath).read_text()
    mat = re.search('(?s)-----BEGIN OPENSSH PRIVATE KEY-----(.*?)-----END OPENSSH PRIVATE KEY-----', text)
    if mat is None:
        print('Not an OpenSSH private key')
        return
    text = mat.group(1)
    buf = base64.b64decode(text)

    pos = 15
    assert buf[:pos] == b'openssh-key-v1\0'
    cipher, pos = read_text(buf, pos)
    kdf, pos = read_text(buf, pos)
    kdf_buf, pos = read_text(buf, pos)
    key_cnt = struct.unpack('>i', buf[pos:pos+4])[0]
    assert key_cnt == 1

    pos = 0
    kdf_salt, pos = read_text(kdf_buf, pos)
    kdf_rounds = struct.unpack('>i', kdf_buf[pos:pos+4])[0]

    print(f"Cipher: {cipher.decode('utf-8')}")
    print(f"KDF: {kdf.decode('utf-8')} ({kdf_rounds} rounds)")

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('key_file', nargs='+')
    args = ap.parse_args()

    for fpath in args.key_file:
        parse_key(fpath)
        print('---')
