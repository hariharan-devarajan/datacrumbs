from bcc import BPF

from dfprofiler.configs.configuration_manager import ConfigurationManager


class BCCApplicationConnector:
    config: ConfigurationManager

    def __init__(self) -> None:
        self.config = ConfigurationManager.get_instance()
        self.functions = """
        int trace_dfprofiler_start(struct pt_regs *ctx) {
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64 tsp = bpf_ktime_get_ns();
            bpf_trace_printk(\"Tracing PID \%d\",pid);
            pid_map.update(&pid, &tsp);
            return 0;
        }
        int trace_dfprofiler_stop(struct pt_regs *ctx) {
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            bpf_trace_printk(\"Stop tracing PID \%d\",pid);
            pid_map.delete(&pid);
            struct stats_key_t key = {};
            key.id = 0;
            key.trange = 0;
            key.ip = 0;
            struct stats_t zero_stats = {};
            zero_stats.count = 1000;
            fn_map.lookup_or_init(&key, &zero_stats);
            return 0;
        }
        """

    def __str__(self) -> str:
        return self.functions

    def attach_probe(self, bpf: BPF) -> None:

        bpf.add_module(f"{self.config.install_dir}/libdfprofiler.so")
        bpf.attach_uprobe(
            name=f"{self.config.install_dir}/libdfprofiler.so",
            sym="dfprofiler_start",
            fn_name="trace_dfprofiler_start",
        )
        bpf.attach_uprobe(
            name=f"{self.config.install_dir}/libdfprofiler.so",
            sym="dfprofiler_stop",
            fn_name="trace_dfprofiler_stop",
        )
