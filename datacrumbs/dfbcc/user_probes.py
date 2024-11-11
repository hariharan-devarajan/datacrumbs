from typing import *
import os
import re
from bcc import BPF
from tqdm import tqdm
from datacrumbs.dfbcc.collector import BCCCollector
from datacrumbs.dfbcc.probes import BCCFunctions, BCCProbes
from datacrumbs.common.enumerations import ProbeType
from datacrumbs.configs.configuration_manager import ConfigurationManager


class UserProbes:
    config: ConfigurationManager
    probes: List[BCCProbes]

    def __init__(self) -> None:
        self.config = ConfigurationManager.get_instance()
        self.probes = []
        num_symbols = 0
        for key, obj in self.config.user_libraries.items():
            probe = BCCProbes(ProbeType.USER, key, [])
            if "regex" not in obj:
                pattern = re.compile(".*")
            else:
                pattern = re.compile(obj["regex"])
            link = obj["link"]
            symbols = (
                os.popen(f"nm {link} | grep \" T \" | awk {{'print $3'}}")
                .read()
                .strip()
                .split("\n")
            )
            for symbol in tqdm(symbols, desc=f"User symbols for {key}"):
                if (symbol or symbol != "") and pattern.match(symbol):
                    probe.functions.append(BCCFunctions(symbol))
                    num_symbols += 1
                    self.config.tool_logger.debug(f"Adding Probe function {symbol} from {key}")
            self.probes.append(probe)
        self.config.tool_logger.info(f"Added {num_symbols} User probes")

    def collector_fn(self, collector: BCCCollector, category_fn_map, count: int):
        bpf_text = ""
        for probe in self.probes:
            for fn in probe.functions:
                if fn.is_custom:
                    count = count + 1
                    if ProbeType.USER == probe.type:
                        text = collector.custom_functions
                        text = text.replace("DFCAT", probe.category)
                        text = text.replace("DFFUNCTION", fn.name)
                        text = text.replace("DFEVENTID", str(count))
                        text = text.replace("DFENTRYCMD", fn.entry_cmd)
                        text = text.replace("DFEXITCMDSTATS", fn.exit_cmd_stats)
                        text = text.replace("DFEXITCMDKEY", fn.exit_cmd_key)
                        text = text.replace("DFENTRYARGS", fn.entry_args)
                        text = text.replace("DFENTRY_STRUCT", fn.entry_struct_str)
                        text = text.replace("DFEXIT_STRUCT", fn.exit_struct_str)
                        bpf_text += text
                        category_fn_map[count] = (probe.category, fn)

        return (bpf_text, category_fn_map, count)

    def attach_probes(self, bpf: BPF, collector: BCCCollector) -> None:
        self.config.tool_logger.info("Attaching probe for User Probes")
        added_libraries = set()
        for probe in tqdm(self.probes, "attach User probes"):
            for fn in tqdm(probe.functions, f"attach {probe.category} functions"):
                try:
                    if ProbeType.USER == probe.type:
                        self.config.tool_logger.debug(
                            f"Adding Probe function {fn.name} from {probe.category}"
                        )
                        library = probe.category
                        fname = fn.name
                        if probe.category in self.config.user_libraries:
                            library = self.config.user_libraries[probe.category]["link"]
                            if probe.category not in added_libraries:
                                bpf.add_module(library)
                                added_libraries.add(probe.category)
                                self.config.tool_logger.debug(
                                    f"Adding Probe library {library} from {probe.category}"
                                )
                        bpf.attach_uprobe(
                            name=library,
                            sym=fname,
                            fn_name=f"user_generic_entry",
                        )
                        bpf.attach_uretprobe(
                            name=library,
                            sym=fname,
                            fn_name=f"user_generic_exit",
                        )
                except Exception as e:
                    self.config.tool_logger.warn(
                        f"Unable attach probe {probe.category} to user function {fn.name} due to {e}"
                    )
