from dfprofiler.common.enumerations import ProbeType

from typing import *


class BCCFunctions:
    name: str
    regex: str
    entry_cmd: str
    exit_cmd: str

    def __init__(
        self, name: str, regex: str = None, entry_cmd: str = "", exit_cmd: str = ""
    ) -> None:
        self.name = name
        self.regex = regex
        self.entry_cmd = entry_cmd
        self.exit_cmd = exit_cmd


class BCCProbes:
    type: ProbeType
    category: str
    functions: List[BCCFunctions]

    def __init__(
        self, type: ProbeType, category: str, functions: List[BCCFunctions]
    ) -> None:
        self.type = type
        self.category = category
        self.functions = functions
