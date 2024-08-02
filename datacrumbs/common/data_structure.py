import ctypes
from typing import *


class DFEvent:
    pid: int
    tid: int
    name: str
    cat: str
    ts: int
    args: Dict


class Filename(ctypes.Structure):
    _fields_ = [
        ("fname", ctypes.c_char * 256),
    ]
