import logging
from time import sleep
import ctypes

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
        pass

    def load(self) -> any:
        app_connector = BCCApplicationConnector()
        collector = BCCCollector()
        bpf_text = ""
        bpf_text += str(BCCHeader())
        bpf_text += str(app_connector)
        bpf_text += str(collector)
        bpf_text = bpf_text.replace(
            "INTERVAL_RANGE", str(int(self.config.interval_sec * 1e9))
        )
        logging.debug(f"Compiled Program is \n{bpf_text}")
        self.bpf = BPF(text=bpf_text)
        app_connector.attach_probe(self.bpf)
        io_probes = IOProbes()
        io_probes.attach_probes(self.bpf, collector)
        user_probes = UserProbes()
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
                    counts.items(),
                    key=lambda counts: counts[1].time,
                )
            ):
                pid = ctypes.c_uint32(k.id).value
                tid = ctypes.c_uint32(k.id >> 32).value
                if pid == 0 and k.trange == 0 and k.ip == 0 and v.count == 1000:
                    exiting = True
                    continue
                fname = self.bpf.sym(k.ip, pid, show_module=True).decode()
                if "unknown" in fname:
                    fname = self.bpf.ksym(k.ip, show_module=True).decode()
                if "unknown" in fname:
                    cat = "unknown"
                else:
                    cat = fname.split(" ")[1]
                event = DFEvent()
                event.pid = pid
                event.tid = tid
                event.name = fname
                event.cat = cat
                event.ts = k.trange
                event.count = v.count
                event.time = v.time
                writer.write(event)
            count += 1
            counts.clear()
            if exiting:
                break
