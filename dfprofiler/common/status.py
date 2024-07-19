from enum import Enum

class ProfilerStatus(Enum):
    """
    Different status codes for the profiler.
    """
    SUCCESS = 0
    SYSTEM_FAIL = -1

    def __str__(self):
        return self.value