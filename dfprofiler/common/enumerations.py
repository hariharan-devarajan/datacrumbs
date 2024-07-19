from enum import Enum


class ProbeType(Enum):
    SYSTEM = 0
    KERNEL = 1
    USER = 2

    def __str__(self):
        return self.value
