from enum import Enum


class ProbeType(Enum):
    SYSTEM = 0
    KERNEL = 1
    USER = 2

    def __str__(self):
        return self.value

class Mode(Enum):
    PROFILE = 'profile'
    TRACE = 'trace'

    def __str__(self):
        return self.value

    @staticmethod
    def get_enum(value):
        if Mode.PROFILE.value == value:
            return Mode.PROFILE
        elif Mode.TRACE.value == value:
            return Mode.TRACE
        return None