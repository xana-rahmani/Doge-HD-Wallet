#!/usr/bin/env python3

from typing import Optional
from base58 import b58decode_check
from ecdsa.curves import SECP256k1
from binascii import (hexlify, unhexlify)
from ecdsa.ecdsa import int_to_string
from elliptic_curve_cryptography_ecc import ecc
from hashlib import sha256
import ecdsa
import struct
import hashlib
import hmac

class HDWallet:

    def __init__(self):
        self._chain_code = None
        self._depth: int = 0
        self._index: int = 0
        self._path: str = "m"
        self._parent_fingerprint: bytes = b"\0\0\0\0"
        self._verified_key = None
        self._public_key = None

    def from_path(self, path: str) -> "HDWallet":
        """ Normal Child: extended public key """

        if str(path)[0:2] != "m/":
            raise ValueError("Bad path, please insert like this type of path \"m/0/0\"! ")

        for index in path.lstrip("m/").split("/"):
            if "'" in index:
                "Bad path, \' in path need to private"
            else:
                self._derive_key_by_index(int(index))
                self._path += str("/" + index)
        return self

    def _derive_key_by_index(self, index) -> "HDWallet":
        i_str = struct.pack(">L", index)
        data = unhexlify(self._public_key) + i_str
        hmac_hash = hmac.new(key=self._chain_code, msg=data, digestmod=hashlib.sha512).digest()

        left_32bit = hmac_hash[:32]
        self._chain_code = hmac_hash[32:].hex()

        pubkey = ecc.ECPrivkey(left_32bit[0:32]) + ecc.ECPubkey(bytes.fromhex(self._public_key))
        self._verified_key = ecdsa.VerifyingKey.from_string(
            pubkey.get_public_key_bytes(compressed=False), curve=SECP256k1
        )

        self._depth += 1
        self._index = index
        self._parent_fingerprint = unhexlify(self.finger_print())
        self._public_key = pubkey.get_public_key_bytes(compressed=True)

        return self

    def public_key(self, compressed: bool = True) -> str:
        """
        Get Public Key.

        :param compressed: Compressed public key, default to ``True``.
        :type compressed: bool

        :returns: str -- Public key.
        """
        return self.compressed() if compressed else self.uncompressed()

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

    def uncompressed(self, compressed: Optional[str] = None) -> str:
        """
        Get Uncommpresed Public Key.

        :param compressed: Compressed public key, default to ``None``.
        :type compressed: str

        :returns: str -- Uncommpresed public key.
        """

        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        public_key = unhexlify(compressed) if compressed else unhexlify(self.compressed())
        x = int.from_bytes(public_key[1:33], byteorder='big')
        y_sq = (pow(x, 3, p) + 7) % p
        y = pow(y_sq, (p + 1) // 4, p)
        if y % 2 != public_key[0] % 2:
            y = p - y
        y = y.to_bytes(32, byteorder='big')
        return (public_key[1:33] + y).hex()

    def finger_print(self) -> str:
        return self.hash(self._public_key)[:8]

    def hash(self, public_key: str = None):
        return hashlib.new("ripemd160", sha256(unhexlify(public_key)).digest()).hexdigest()


xpub = 'dgub8kXBZ7ymNWy2RKqyrtun4BKWC5w12ChzSjiYYYjegnpE6PcYvSAuL1YnWEQVKQXgmiBbFLj2GWir1MmXvZ5Kv7Q7boRf3xMRqSvYfnFyyoT'
hd = HDWallet()
hd.from_xpublic_key(xpublic_key=xpub)
hd.from_path(path='m/0')
print(hd.public_key())

