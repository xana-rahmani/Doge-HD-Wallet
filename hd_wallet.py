#!/usr/bin/env python3

from typing import Union, Any, NamedTuple

import base58
from base58 import b58decode_check
from elliptic_curve_cryptography_ecc import ecc
from elliptic_curve_cryptography_ecc.crypto import hash_160
from elliptic_curve_cryptography_ecc.cryptocurrencies import get_cryptocurrency
import hashlib
import hmac

class HDWallet(NamedTuple):

    eckey: Union[ecc.ECPubkey, ecc.ECPrivkey]
    cryptocurrency: Any
    chaincode: bytes
    depth: int = 0
    parent_fingerprint: bytes = b'\x00' * 4  # as in serialized format, this is the *parent's* fingerprint
    child_number: bytes = b'\x00' * 4

    @classmethod
    def from_xpublic_key(cls, xpublic_key: str, symbol: str = "DOGE") -> "HDWallet":
        """
        Master from XPublic Key.

        :param symbol:
        :param xpublic_key: XPublic key.
        :type xpublic_key: str

        :returns: HDWallet -- Hierarchical Deterministic Wallet instance.
        """

        deserialize_xpublic_key = cls.deserialize_xpublic_key(xpublic_key=xpublic_key)
        depth = int.from_bytes(deserialize_xpublic_key[1], "big")
        parent_fingerprint = deserialize_xpublic_key[2]
        child_number = deserialize_xpublic_key[3]
        chaincode = deserialize_xpublic_key[4]
        eckey = ecc.ECPubkey(deserialize_xpublic_key[5])
        cryptocurrency = get_cryptocurrency(symbol=symbol)

        return HDWallet(eckey=eckey, chaincode=chaincode, depth=depth, parent_fingerprint=parent_fingerprint,
                        child_number=child_number, cryptocurrency=cryptocurrency)

    def subkey_at_public_derivation(self, path: str) -> "HDWallet":
        """ Normal Child: extended public key """

        if path is None:
            raise Exception("derivation path must not be None")
        if str(path)[0:2] != "m/":
            raise ValueError("Bad path, please insert like this type of path \"m/0/0\"! ")

        depth = self.depth
        chaincode = self.chaincode
        pubkey = self.eckey.get_public_key_bytes(compressed=True)

        for child_index in path.lstrip("m/").split("/"):
            if "'" in child_index:
                raise Exception("Bad path, \' in path need to private")
            else:
                parent_pubkey = pubkey
                child_index = int(child_index)
                _child_index = bytes.fromhex(ecc.rev_hex(ecc.int_to_hex(child_index, 4)))
                I = hmac.new(key=chaincode, msg=pubkey + _child_index, digestmod=hashlib.sha512).digest()
                _pubkey = ecc.ECPrivkey(I[0:32]) + ecc.ECPubkey(pubkey)
                if _pubkey.is_at_infinity():
                    raise ecc.InvalidECPointException()
                pubkey = _pubkey.get_public_key_bytes(compressed=True)
                chaincode = I[32:]
                depth += 1

        parent_fingerprint = hash_160(parent_pubkey)[0:4]
        child_number = child_index.to_bytes(length=4, byteorder="big")
        eckey = ecc.ECPubkey(pubkey)

        return HDWallet(eckey=eckey, chaincode=chaincode, depth=depth, parent_fingerprint=parent_fingerprint,
                        child_number=child_number, cryptocurrency=self.cryptocurrency)

    def public_key(self, compressed: bool = True) -> str:
        """
        Get Public Key.

        :param compressed: Compressed public key, default to ``True``.
        :type compressed: bool

        :returns: str -- Public key.
        """
        return self.eckey.get_public_key_hex(compressed=compressed)

    def p2pkh_address(self) -> str:
        """
        Get Pay to Public Key Hash (P2PKH) address.

        :returns: str -- P2PKH address.
        """
        compressed_public_key = self.eckey.get_public_key_bytes(compressed=True)
        public_key_hash = hash_160(compressed_public_key)
        network_hash160_bytes = bytes.fromhex(hex(self.cryptocurrency.PUBLIC_KEY_ADDRESS)[2:]) + public_key_hash
        return base58.b58encode_check(network_hash160_bytes).decode("utf-8")

    @staticmethod
    def deserialize_xpublic_key(xpublic_key: str, encoded: bool = True) -> tuple:
        decoded_xpublic_key = b58decode_check(xpublic_key) if encoded else xpublic_key
        if len(decoded_xpublic_key) != 78:
            raise Exception('Invalid length for extended key: {}'.format(len(xpublic_key)))
        return (
            decoded_xpublic_key[:4],
            decoded_xpublic_key[4:5],  # depth
            decoded_xpublic_key[5:9],  # parent_fingerprint
            decoded_xpublic_key[9:13],  # child_number
            decoded_xpublic_key[13:45],  # chaincode
            decoded_xpublic_key[45:]  # eckey
        )
