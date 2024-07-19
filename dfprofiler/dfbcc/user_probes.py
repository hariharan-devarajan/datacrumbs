from typing import *
import os
import logging
from bcc import BPF
from dfprofiler.dfbcc.collector import BCCCollector
from dfprofiler.dfbcc.probes import BCCFunctions, BCCProbes
from dfprofiler.common.enumerations import ProbeType
from dfprofiler.configs.configuration_manager import ConfigurationManager


class UserProbes:
    config: ConfigurationManager
    probes: List[BCCProbes]

    def __init__(self) -> None:
        self.config = ConfigurationManager.get_instance()
        self.probes = []
        for key, value in self.config.user_libraries.items():
            probe = BCCProbes(ProbeType.USER, key, [])
            symbols = (
                os.popen(f"nm {value} | grep \" T \" | awk {{'print $3'}}")
                .read()
                .strip()
                .split("\n")
            )
            for symbol in symbols:
                probe.functions.append(BCCFunctions(symbol))
            self.probes.append(probe)

    def attach_probes(self, bpf: BPF, collector: BCCCollector) -> None:
        for probe in self.probes:
            for fn in probe.functions:
                try:
                    if ProbeType.SYSTEM == probe.type:
                        fnname = bpf.get_syscall_prefix().decode() + fn.name
                        bpf.attach_kprobe(event_re=fnname, fn_name=collector.entry_fn)
                        bpf.attach_kretprobe(event_re=fnname, fn_name=collector.exit_fn)
                    elif ProbeType.KERNEL == probe.type:
                        bpf.attach_kprobe(event_re=fn.name, fn_name=collector.entry_fn)
                        bpf.attach_kretprobe(event_re=fn.name, fn_name=collector.exit_fn)
                    elif ProbeType.USER == probe.type:
                        library = probe.category
                        if probe.category in self.config.user_libraries:
                            library = self.config.user_libraries[probe.category]
                        bpf.attach_uprobe(name=library, sym=fn.name, fn_name=collector.entry_fn)
                        bpf.attach_uretprobe(
                            name=library, sym=fn.name, fn_name=collector.exit_fn
                        )
                except Exception as e:
                    logging.warn(f"Unable attach probe {probe.category} to user function {fn.name} due to {e}")
