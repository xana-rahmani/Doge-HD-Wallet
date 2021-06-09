#!/usr/bin/env python3

from types import SimpleNamespace
from typing import Any, Optional

import inspect
import sys


class NestedNamespace(SimpleNamespace):
    def __init__(self, dictionary, **kwargs):
        super().__init__(**kwargs)
        for key, value in dictionary.items():
            if isinstance(value, dict):
                self.__setattr__(key, NestedNamespace(value))
            else:
                self.__setattr__(key, value)


class SegwitAddress(NestedNamespace):

    HRP: Optional[str] = None
    VERSION: int = 0x00


class CoinType(NestedNamespace):
    INDEX: int
    HARDENED: bool

    def __str__(self):
        return f"{self.INDEX}'" if self.HARDENED else f"{self.INDEX}"


class ExtendedKey(NestedNamespace):
    P2PKH: int
    P2SH: int

    P2WPKH: Optional[int] = None
    P2WPKH_IN_P2SH: Optional[int] = None

    P2WSH: Optional[int] = None
    P2WSH_IN_P2SH: Optional[int] = None


class ExtendedPrivateKey(ExtendedKey):
    pass


class ExtendedPublicKey(ExtendedKey):
    pass


class Cryptocurrency(NestedNamespace):

    NAME: str
    SYMBOL: str
    NETWORK: str
    SOURCE_CODE: Optional[str]
    COIN_TYPE: CoinType

    SCRIPT_ADDRESS: int
    PUBLIC_KEY_ADDRESS: int
    SEGWIT_ADDRESS: SegwitAddress

    EXTENDED_PRIVATE_KEY: ExtendedPrivateKey
    EXTENDED_PUBLIC_KEY: ExtendedPublicKey

    MESSAGE_PREFIX: Optional[str]
    DEFAULT_PATH: str
    WIF_SECRET_KEY: int


class DogecoinMainnet(Cryptocurrency):

    NAME = "Dogecoin"
    SYMBOL = "DOGE"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/dogecoin/dogecoin"
    COIN_TYPE = CoinType({
        "INDEX": 3,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x16
    PUBLIC_KEY_ADDRESS = 0x1e
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x02fac398,
        "P2SH": 0x02fac398,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x02facafd,
        "P2SH": 0x02facafd,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x19Dogecoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xf1


class DogecoinTestnet(Cryptocurrency):

    NAME = "Dogecoin"
    SYMBOL = "DOGETEST"
    NETWORK = "testnet"
    SOURCE_CODE = "https://github.com/dogecoin/dogecoin"
    COIN_TYPE = CoinType({
        "INDEX": 3,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xc4
    PUBLIC_KEY_ADDRESS = 0x71
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "dogecointestnet",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x04358394,
        "P2SH": 0x04358394,
        "P2WPKH": 0x04358394,
        "P2WPKH_IN_P2SH": 0x04358394,
        "P2WSH": 0x04358394,
        "P2WSH_IN_P2SH": 0x04358394
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x043587cf,
        "P2SH": 0x043587cf,
        "P2WPKH": 0x043587cf,
        "P2WPKH_IN_P2SH": 0x043587cf,
        "P2WSH": 0x043587cf,
        "P2WSH_IN_P2SH": 0x043587cf
    })

    MESSAGE_PREFIX = "\x19Dogecoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xf1

def get_cryptocurrency(symbol: str) -> Any:

    for _, cryptocurrency in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(cryptocurrency):
            if issubclass(cryptocurrency, Cryptocurrency) and cryptocurrency != Cryptocurrency:
                if symbol == cryptocurrency.SYMBOL:
                    return cryptocurrency

    raise ValueError(f"Invalid Cryptocurrency '{symbol}' symbol.")

