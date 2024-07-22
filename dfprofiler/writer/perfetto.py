import logging
import json
import os
import gzip
import shutil
import socket
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
        try:
            os.remove(f"{self.config.profile_file}.gz")
        except OSError:
            pass
        self.trace_log = logging.getLogger("dfprofiler.trace")
        self.trace_log.setLevel(logging.INFO)
        trace_file_handler = logging.FileHandler(self.config.profile_file)
        trace_file_handler.setLevel(logging.INFO)
        trace_file_handler.setFormatter(logging.Formatter("%(message)s"))
        self.trace_log.addHandler(trace_file_handler)
        self.trace_log.info("[")

    def finalize(self):
        logging.info(f"Finalizing Writer")
        with open(self.config.profile_file, "rb") as f_in:
            with gzip.open(f"{self.config.profile_file}.gz", "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        # try:
        #     os.remove(self.config.profile_file)
        # except OSError:
        #     pass

    def write(self, event: DFEvent):
        obj = {
            "pid": event.pid,
            "tid": event.tid,
            "name": event.name,
            "cat": event.cat,
            "ph": "C",
            "ts": int(event.ts * self.config.interval_sec * 1e6),  # Convert to us
            "args": {"hostname": socket.gethostname()},
        }
        for key, value in event.args.items():
            obj["args"][key] = value
        self.trace_log.info(json.dumps(obj))
