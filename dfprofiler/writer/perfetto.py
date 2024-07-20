import logging
import json
import os
from dfprofiler.common.data_structure import DFEvent
from dfprofiler.configs.configuration_manager import ConfigurationManager


class PerfettoWriter:
    config: ConfigurationManager

    def __init__(self) -> None:
        self.config = ConfigurationManager.get_instance()
        try:
            os.remove(self.config.profile_file)
        except OSError:
            pass
        self.trace_log = logging.getLogger("dfprofiler.trace")
        self.trace_log.setLevel(logging.INFO)
        trace_file_handler = logging.FileHandler(self.config.profile_file)
        trace_file_handler.setLevel(logging.INFO)
        trace_file_handler.setFormatter(logging.Formatter("%(message)s"))
        self.trace_log.addHandler(trace_file_handler)
        self.trace_log.info("[")

    def write(self, event: DFEvent):
        obj = {
            "pid": event.pid,
            "tid": event.tid,
            "name": event.name,
            "cat": event.cat,
            "ph": "C",
            "ts": int(event.ts * self.config.interval_sec * 1e6),  # Convert to us
            "args": {
                "count": event.count,
                "time": event.time / 1e9,  # Convert to sec
            },
        }
        self.trace_log.info(json.dumps(obj))
