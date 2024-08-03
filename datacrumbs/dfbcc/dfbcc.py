import logging
from time import sleep
import ctypes
from typing import *
import threading
import psutil

# External Imports
from bcc import BPF
from bcc.utils import printb

# Internal Imports
from datacrumbs.dfbcc.app_connector import BCCApplicationConnector
from datacrumbs.dfbcc.collector import BCCCollector
from datacrumbs.dfbcc.header import BCCHeader
from datacrumbs.dfbcc.io_probes import IOProbes
from datacrumbs.dfbcc.user_probes import UserProbes
from datacrumbs.configs.configuration_manager import ConfigurationManager
from datacrumbs.common.data_structure import DFEvent, Filename
from datacrumbs.writer.perfetto import PerfettoWriter


class BCCMain:
    config: ConfigurationManager

    def __init__(self) -> None:
        self.config = ConfigurationManager.get_instance()
        self.category_fn_map = {}
        self.writer = PerfettoWriter()
        self.run_thread_counter = True
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

    def run_network_usage(self):
        start_counter = 0
        logging.info("Running Network thread")
        while self.run_thread_counter:
            network_counts = psutil.net_io_counters(pernic=True)
            # logging.debug(f"network_counts {network_counts}")
            event = DFEvent()
            event.pid = 0
            event.tid = 0
            event.cat = "Network"
            event.name = "snetio"
            event.ts = start_counter * self.config.interval_sec
            # logging.debug(f"Logging event {event}")
            for interface, counter in network_counts.items():
                event.args = {
                    "nic": interface,
                    "bytes_sent": counter.bytes_sent,
                    "bytes_recv": counter.bytes_recv,
                    "packets_sent": counter.packets_sent,
                    "packets_recv": counter.packets_recv,
                    "errin": counter.errin,
                    "errout": counter.errout,
                    "dropin": counter.dropin,
                    "dropout": counter.dropout,
                }
                self.writer.write(event)
            sleep(self.config.interval_sec)
            start_counter += 1
        logging.debug("Exiting Network thread")

    def run_disk_usage(self):
        logging.info("Running Disk thread")
        start_counter = 0
        while self.run_thread_counter:
            disk_counters = psutil.disk_io_counters(perdisk=True)
            event = DFEvent()
            event.pid = 0
            event.tid = 0
            event.cat = "Disk"
            event.name = "io_stat"
            event.ts = start_counter * self.config.interval_sec

            for mount, counter in disk_counters.items():
                event.args = {
                    "mount": mount,
                    "read_count": counter.read_count,
                    "write_count": counter.write_count,
                    "read_bytes": counter.read_bytes,
                    "write_bytes": counter.write_bytes,
                    "read_time": counter.read_time,
                    "write_time": counter.write_time,
                }
                self.writer.write(event)
            sleep(self.config.interval_sec)
            start_counter += 1
        logging.debug("Exiting Disk thread")

    def run_cpu_loop(self):
        logging.info("Running CPU thread")
        start_counter = 0
        while self.run_thread_counter:
            cpu_utilization = psutil.cpu_percent(interval=1, percpu=True)
            event = DFEvent()
            event.pid = 0
            event.tid = 0
            event.cat = "CPU"
            event.name = "utilization"
            event.ts = start_counter * self.config.interval_sec
            event.args = {}
            for i, util in enumerate(cpu_utilization):
                event.args[f"CPU_{i}"] = util
            self.writer.write(event)
            sleep(self.config.interval_sec)
            start_counter += 1
        logging.debug("Exiting CPU thread")

    def run_memory_loop(self):
        logging.info("Running Memory thread")
        start_counter = 0
        while self.run_thread_counter:
            memory = psutil.virtual_memory()
            event = DFEvent()
            event.pid = 0
            event.tid = 0
            event.cat = "Memory"
            event.name = "virtual_memory"
            event.ts = start_counter * self.config.interval_sec
            event.args = {
                "total": memory.total,
                "available": memory.available,
                "percent": memory.percent,
                "used": memory.used,
                "free": memory.free,
                "active": memory.active,
                "inactive": memory.inactive,
                "buffers": memory.buffers,
                "cached": memory.cached,
                "shared": memory.shared,
                "slab": memory.slab,
            }
            self.writer.write(event)
            sleep(self.config.interval_sec)
            start_counter += 1
        logging.debug("Exiting memory thread")

    def stop(self):
        self.run_thread_counter = False
        logging.info("Stopping all threads")
        self.memory_loop.join()
        self.cpu_loop.join()
        self.disk_loop.join()
        self.network_loop.join()
        self.writer.finalize()

    def run(self) -> None:
        logging.info("Ready to run code")
        self.memory_loop = threading.Thread(target=self.run_memory_loop)
        self.memory_loop.start()
        self.cpu_loop = threading.Thread(target=self.run_cpu_loop)
        self.cpu_loop.start()
        self.disk_loop = threading.Thread(target=self.run_disk_usage)
        self.disk_loop.start()
        self.network_loop = threading.Thread(target=self.run_network_usage)
        self.network_loop.start()
        no_event_count = 0
        has_events = False
        last_processed_ts = -1
        sleep_sec = self.config.interval_sec * 5
        wait_for = 30 / (sleep_sec)
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
                        self.stop()
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
                        event.name = self.bpf.sym(k.ip, event.pid, module=True).decode()
                        if "unknown" in event.name:
                            event.name = self.bpf.ksym(k.ip, module=True).decode()
                    else:
                        event.name = function_probe.name
                    event.ts = k.trange
                    event.args = {}
                    event.args["fname"] = (
                        filename_map[k.file_hash]
                        if k.file_hash in filename_map
                        else None
                    )
                    event.args["freq"] = v.freq
                    event.args["time"] = v.time / 1e9
                    event.args["size_sum"] = v.size_sum if v.size_sum > 0 else None
                    last_processed_ts = k.trange
                    logging.info(f"{last_processed_ts} timestamp processed")
                    self.writer.write(event)
                    keys = (counts.Key * 1)()
                    keys[0] = k
                    counts.items_delete_batch(keys)
                    no_event_count = 0
                if has_events:
                    no_event_count += 1
        except KeyboardInterrupt:
            pass
