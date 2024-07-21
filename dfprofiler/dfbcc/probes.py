from dfprofiler.common.enumerations import ProbeType

from typing import *


class BCCFunctions:
    name: str
    regex: str
    entry_cmd: str
    exit_cmd_stats: str
    exit_cmd_key: str
    entry_args: str

    def __init__(
        self,
        name: str,
        regex: str = None,
        entry_args: str = "",
        entry_cmd: str = "",
        exit_cmd_stats: str = "",
        exit_cmd_key: str = "",
    ) -> None:
        self.name = name
        self.regex = regex
        self.entry_cmd = entry_cmd
        self.exit_cmd_stats = exit_cmd_stats
        self.exit_cmd_key = exit_cmd_key
        self.entry_args = entry_args


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
