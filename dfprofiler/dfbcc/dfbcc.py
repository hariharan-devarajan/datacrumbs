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
from dfprofiler.common.data_structure import DFEvent, Filename
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
        no_event_count = 0
        has_events = False
        last_processed_ts = -1
        logging.info("Ready to run code")
        sleep_sec = self.config.interval_sec * 5
        wait_for = 60 / (sleep_sec)
        filename_map = {0: None}
        try:
            while True:
                counts = self.bpf.get_table("fn_map")
                filenames = self.bpf.get_table("file_hash")
                try:
                    logging.debug(
                        f"sleeping for {sleep_sec} secs with last ts {last_processed_ts}"
                    )
                    sleep(sleep_sec)
                    if has_events and no_event_count > wait_for:
                        logging.info(
                            f"No events for {no_event_count * sleep_sec} seconds. Quiting Profiler Now."
                        )
                        filenames.clear()
                        writer.finalize()
                        break
                except KeyboardInterrupt:
                    break
                for k, v in filenames.items():

                    if k.value not in filename_map:
                        filename_map[k.value] = v.fname.decode()
                map_values = sorted(
                    counts.items(),
                    key=lambda counts: counts[0].trange,
                )
                num_entries = len(map_values)
                big_ts = -1
                if num_entries > 0:
                    big_ts = map_values[num_entries - 1][0].trange
                processed = 0
                for k, v in map_values:
                    has_events = True
                    processed += 1
                    event = DFEvent()
                    event.pid = ctypes.c_uint32(k.id).value
                    if big_ts == k.trange and big_ts > last_processed_ts + 1:
                        logging.debug(
                            f"Previous loop had {last_processed_ts} ts and now is {big_ts} ts"
                        )
                        continue
                    event.tid = ctypes.c_uint32(k.id >> 32).value
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
                    event.fname = filename_map[k.file_hash]
                    event.freq = v.freq
                    event.time = v.time
                    event.size_sum = v.size_sum if v.size_sum > 0 else None
                    last_processed_ts = k.trange
                    logging.info(f"{last_processed_ts} timestamp processed")
                    writer.write(event)
                    keys = (counts.Key * 1)()
                    keys[0] = k
                    counts.items_delete_batch(keys)
                    no_event_count = 0
                if has_events:
                    no_event_count += 1
        except KeyboardInterrupt:
            pass
