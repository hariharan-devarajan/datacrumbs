import logging
from time import sleep
import ctypes
from typing import *

# External Imports
from bcc import BPF
from bcc.utils import printb

# Internal Imports
from dfprofiler.dfbcc.app_connector import BCCApplicationConnector
from dfprofiler.dfbcc.collector import BCCCollector
from dfprofiler.dfbcc.header import BCCHeader
from dfprofiler.dfbcc.io_probes import IOProbes
from dfprofiler.dfbcc.user_probes import UserProbes
from dfprofiler.configs.configuration_manager import ConfigurationManager
from dfprofiler.common.data_structure import DFEvent
from dfprofiler.writer.perfetto import PerfettoWriter


class BCCMain:
    config: ConfigurationManager

    def __init__(self) -> None:
        self.config = ConfigurationManager.get_instance()
        self.category_fn_map = {}
        pass

    def load(self) -> any:
        app_connector = BCCApplicationConnector()
        collector = BCCCollector()
        bpf_text = ""
        bpf_text += str(BCCHeader())
        bpf_text += str(app_connector)
        io_probes = IOProbes()
        count = 0
        probe_text, self.category_fn_map, count = io_probes.collector_fn(
            collector, self.category_fn_map, count
        )
        bpf_text += probe_text
        user_probes = UserProbes()
        probe_text, self.category_fn_map, count = user_probes.collector_fn(
            collector, self.category_fn_map, count
        )
        bpf_text += probe_text
        # bpf_text += str(collector)
        bpf_text = bpf_text.replace(
            "INTERVAL_RANGE", str(int(self.config.interval_sec * 1e9))
        )
        logging.debug(f"Compiled Program is \n{bpf_text}")
        f = open("profile.c", "w")
        f.write(bpf_text)
        f.close()
        self.bpf = BPF(text=bpf_text)
        app_connector.attach_probe(self.bpf)

        io_probes.attach_probes(self.bpf, collector)

        user_probes.attach_probes(self.bpf, collector)
        matched = self.bpf.num_open_kprobes()
        logging.info(f"{matched} functions matched")
        return self

    def run(self) -> None:
        writer = PerfettoWriter()
        count = 0
        exiting = False
        print("Ready to run code")
        while True:
            has_events = False
            try:
                sleep(self.config.interval_sec)
            except KeyboardInterrupt:
                exiting = True
            counts = self.bpf.get_table("fn_map")

            for k, v in reversed(
                sorted(
                    counts.items_lookup_and_delete_batch(),
                    key=lambda counts: counts[1].time,
                )
            ):
                event = DFEvent()
                event.pid = ctypes.c_uint32(k.id).value
                event.tid = ctypes.c_uint32(k.id >> 32).value
                if event.pid == 0 and k.trange == 0 and v.count == 1000:
                    exiting = True
                    continue
                event_tuple = self.category_fn_map[k.event_id]
                event.cat = event_tuple[0]
                function_probe = event_tuple[1]
                if function_probe.regex:
                    event.name = self.bpf.sym(k.ip, event.pid).decode()
                    if "unknown" in event.name:
                        event.name = self.bpf.ksym(k.ip).decode()
                else:
                    event.name = function_probe.name
                event.ts = k.trange
                event.count = v.count
                event.time = v.time
                writer.write(event)
            count += 1
            if exiting:
                break
