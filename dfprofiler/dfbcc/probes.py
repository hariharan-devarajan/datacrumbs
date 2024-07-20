from dfprofiler.common.enumerations import ProbeType

from typing import *


class BCCFunctions:
    name: str
    regex: str

    def __init__(self, name: str, regex: str = None) -> None:
        self.name = name
        self.regex = regex


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
