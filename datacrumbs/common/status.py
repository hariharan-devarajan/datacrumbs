from enum import Enum


class ProfilerStatus(Enum):
    """
    Different status codes for the profiler.
    """

    SUCCESS = 0
    SYSTEM_FAIL = -1
    CONVERT_ERROR = 1000

    def __str__(self):
        return self.value

    def success(self):
        return self.value == ProfilerStatus.SUCCESS.value

    def failed(self):
        return self.value != ProfilerStatus.SUCCESS.value
