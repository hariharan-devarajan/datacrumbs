import ctypes


class DFEvent:
    pid: int
    tid: int
    name: str
    cat: str
    ts: int
    freq: int
    time: int
    size_sum: int
    fname: str


class Filename(ctypes.Structure):
    _fields_ = [
        ("fname", ctypes.c_char * 256),
    ]
