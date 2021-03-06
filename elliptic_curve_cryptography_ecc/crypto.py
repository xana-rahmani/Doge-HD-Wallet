# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 The Electrum developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import sys
import hashlib
import hmac
from typing import Union

from .util import assert_bytes, to_bytes, versiontuple


HAS_PYAES = False
try:
    import pyaes
except:
    pass
else:
    HAS_PYAES = True

HAS_CRYPTODOME = False
MIN_CRYPTODOME_VERSION = "3.7"
try:
    import Cryptodome
    if versiontuple(Cryptodome.__version__) < versiontuple(MIN_CRYPTODOME_VERSION):
        print(f"found module 'Cryptodome' but it is too old: {Cryptodome.__version__}<{MIN_CRYPTODOME_VERSION}")
        raise Exception()
    from Cryptodome.Cipher import ChaCha20_Poly1305 as CD_ChaCha20_Poly1305
    from Cryptodome.Cipher import ChaCha20 as CD_ChaCha20
    from Cryptodome.Cipher import AES as CD_AES
except:
    pass
else:
    HAS_CRYPTODOME = True

HAS_CRYPTOGRAPHY = False
MIN_CRYPTOGRAPHY_VERSION = "2.1"
try:
    import cryptography
    if versiontuple(cryptography.__version__) < versiontuple(MIN_CRYPTOGRAPHY_VERSION):
        print(f"found module 'cryptography' but it is too old: {cryptography.__version__}<{MIN_CRYPTOGRAPHY_VERSION}")
        raise Exception()
    from cryptography import exceptions
    from cryptography.hazmat.primitives.ciphers import Cipher as CG_Cipher
    from cryptography.hazmat.primitives.ciphers import algorithms as CG_algorithms
    from cryptography.hazmat.primitives.ciphers import modes as CG_modes
    from cryptography.hazmat.backends import default_backend as CG_default_backend
    import cryptography.hazmat.primitives.ciphers.aead as CG_aead
except:
    pass
else:
    HAS_CRYPTOGRAPHY = True


if not (HAS_CRYPTODOME or HAS_CRYPTOGRAPHY):
    sys.exit(f"Error: at least one of ('pycryptodomex', 'cryptography') needs to be installed.")


class InvalidPadding(Exception):
    pass


def append_PKCS7_padding(data: bytes) -> bytes:
    assert_bytes(data)
    padlen = 16 - (len(data) % 16)
    return data + bytes([padlen]) * padlen


def strip_PKCS7_padding(data: bytes) -> bytes:
    assert_bytes(data)
    if len(data) % 16 != 0 or len(data) == 0:
        raise InvalidPadding("invalid length")
    padlen = data[-1]
    if not (0 < padlen <= 16):
        raise InvalidPadding("invalid padding byte (out of range)")
    for i in data[-padlen:]:
        if i != padlen:
            raise InvalidPadding("invalid padding byte (inconsistent)")
    return data[0:-padlen]


def aes_encrypt_with_iv(key: bytes, iv: bytes, data: bytes) -> bytes:
    assert_bytes(key, iv, data)
    data = append_PKCS7_padding(data)
    if HAS_CRYPTODOME:
        e = CD_AES.new(key, CD_AES.MODE_CBC, iv).encrypt(data)
    elif HAS_CRYPTOGRAPHY:
        cipher = CG_Cipher(CG_algorithms.AES(key), CG_modes.CBC(iv), backend=CG_default_backend())
        encryptor = cipher.encryptor()
        e = encryptor.update(data) + encryptor.finalize()
    elif HAS_PYAES:
        aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
        aes = pyaes.Encrypter(aes_cbc, padding=pyaes.PADDING_NONE)
        e = aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer
    else:
        raise Exception("no AES backend found")
    return e


def aes_decrypt_with_iv(key: bytes, iv: bytes, data: bytes) -> bytes:
    assert_bytes(key, iv, data)
    if HAS_CRYPTODOME:
        cipher = CD_AES.new(key, CD_AES.MODE_CBC, iv)
        data = cipher.decrypt(data)
    elif HAS_CRYPTOGRAPHY:
        cipher = CG_Cipher(CG_algorithms.AES(key), CG_modes.CBC(iv), backend=CG_default_backend())
        decryptor = cipher.decryptor()
        data = decryptor.update(data) + decryptor.finalize()
    elif HAS_PYAES:
        aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
        aes = pyaes.Decrypter(aes_cbc, padding=pyaes.PADDING_NONE)
        data = aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer
    else:
        raise Exception("no AES backend found")
    try:
        return strip_PKCS7_padding(data)
    except InvalidPadding:
        raise Exception("Incorrect password")


def hash_160(x: bytes) -> bytes:
    return ripemd(sha256(x))


def ripemd(x):
    try:
        md = hashlib.new('ripemd160')
        md.update(x)
        return md.digest()
    except BaseException:
        from . import ripemd
        md = ripemd.new(x)
        return md.digest()


def sha256(x: Union[bytes, str]) -> bytes:
    x = to_bytes(x, 'utf8')
    return bytes(hashlib.sha256(x).digest())


def sha256d(x: Union[bytes, str]) -> bytes:
    x = to_bytes(x, 'utf8')
    out = bytes(sha256(sha256(x)))
    return out


def hmac_oneshot(key: bytes, msg: bytes, digest) -> bytes:
    if hasattr(hmac, 'digest'):
        # requires python 3.7+; faster
        return hmac.digest(key, msg, digest)
    else:
        return hmac.new(key, msg, digest).digest()

