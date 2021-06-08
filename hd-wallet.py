#!/usr/bin/env python3

import hashlib
import hmac
from typing import Optional

from base58 import b58decode_check
from ecdsa.curves import SECP256k1
from binascii import (
    hexlify, unhexlify
)
from ecdsa.ecdsa import (
    int_to_string, string_to_int
)

import ecdsa
import struct


class HDWallet:

    def __init__(self):
        self._chain_code = None
        self._depth: int = 0
        self._index: int = 0
        self._parent_fingerprint: bytes = b"\0\0\0\0"
        self._verified_key = None
        self._public_key = None

    def Normal_Child__extended_public_key(self, index):
        i_str = struct.pack(">L", index)
        data = unhexlify(self._public_key) + i_str

        key = bytes.fromhex(self._public_key)
        hmac_hash = hmac.new(key=key, msg=data, digestmod=hashlib.sha512).hexdigest()
        print("hmac_hash:", hmac_hash)
        left_32bit = hmac_hash[:64]  # 64 hex >> 32 bit
        child_chain_code = hmac_hash[64:]

        int_child_public_key = int(self._public_key, 16) + int(left_32bit, 16)
        child_public_key = (b"\0" * 32 + int_to_string(int_child_public_key))[-32:]

        print("child_chain_code: ", child_chain_code)
        print("child_public_key: ", child_public_key)

    def from_xpublic_key(self, xpublic_key: str) -> "HDWallet":
        """
        Master from XPublic Key.

        :param xpublic_key: XPublic key.
        :type xpublic_key: str

        :returns: HDWallet -- Hierarchical Deterministic Wallet instance.
        """

        deserialize_xpublic_key = self.deserialize_xpublic_key(xpublic_key=xpublic_key)
        self._depth, self._parent_fingerprint, self._index = (
            int.from_bytes(deserialize_xpublic_key[1], "big"),
            deserialize_xpublic_key[2],
            struct.unpack(">L", deserialize_xpublic_key[3])[0]
        )
        self._chain_code = deserialize_xpublic_key[4]
        self._verified_key = ecdsa.VerifyingKey.from_string(
            deserialize_xpublic_key[5], curve=SECP256k1
        )
        self._public_key = self.compressed()
        return self

    @staticmethod
    def deserialize_xpublic_key(xpublic_key: str, encoded: bool = True) -> tuple:
        decoded_xpublic_key = b58decode_check(xpublic_key) if encoded else xpublic_key
        if len(decoded_xpublic_key) != 78:
            raise ValueError("Invalid xpublic key.")
        return (
            decoded_xpublic_key[:4], decoded_xpublic_key[4:5],
            decoded_xpublic_key[5:9], decoded_xpublic_key[9:13],
            decoded_xpublic_key[13:45], decoded_xpublic_key[45:]
        )

    def compressed(self, uncompressed: Optional[str] = None) -> str:
        """
        Get Compresed Public Key.

        :param uncompressed: Uncompressed public key, default to ``None``.
        :type uncompressed: str

        :returns: str -- Commpresed public key.
        """

        _verified_key = ecdsa.VerifyingKey.from_string(
            unhexlify(uncompressed), curve=SECP256k1
        ) if uncompressed else self._verified_key
        padx = (b"\0" * 32 + int_to_string(
            _verified_key.pubkey.point.x()))[-32:]
        if _verified_key.pubkey.point.y() & 1:
            ck = b"\3" + padx
        else:
            ck = b"\2" + padx
        return hexlify(ck).decode()


xpub = 'dgub8kXBZ7ymNWy2RKqyrtun4BKWC5w12ChzSjiYYYjegnpE6PcYvSAuL1YnWEQVKQXgmiBbFLj2GWir1MmXvZ5Kv7Q7boRf3xMRqSvYfnFyyoT'
hd = HDWallet()
hd.from_xpublic_key(xpublic_key=xpub)
print(hd.deserialize_xpublic_key(xpublic_key=xpub))
print(hd.Normal_Child__extended_public_key(index=1))

i_str = b'\x00\x00\x00\x01'
_hamc  = b"\x9d\xf1O\xeaj\xe8g\xa7\xa3\x03\x9b\xa5?\xdd\xce\x9f\xed\x04'v\x8a\x0f\x98?-co\x866\xc1PZ\xb4&\x8c\xcb\xb9\xd6[g\xb0\xa6\xf3>LYR\xe6\x87\xbb\xa5\x04\x90\xca\x89\xf8\xc0\x9aD\xef\xed\xa8h\x80"
secret= b'\x8a\x1d3O\xb1Uq{\xed\xf7\x16\xde\r\xd3rp\xde\xb37\xb7\xb5(\x17|\x07\xc6\x92k\x82\x05\x8b\xb1'