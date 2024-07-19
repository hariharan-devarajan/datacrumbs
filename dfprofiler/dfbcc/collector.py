class BCCCollector:
    entry_fn: str
    exit_fn: str

    def __init__(self) -> None:
        self.entry_fn = "do_count_entry"
        self.exit_fn = "do_count_exit"
        self.functions = """
        int DF_ENTRY(struct pt_regs *ctx) {
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0)                                      
                return 0;
            
            struct fn_key_t key = {};
            key.pid = pid;
            struct fn_t fn = {};
            fn.ip = PT_REGS_IP(ctx);
            fn.ts = bpf_ktime_get_ns();
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int DF_EXIT(struct pt_regs *ctx) {
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0)                                      
                return 0;
            struct fn_key_t key = {};
            key.pid = pid;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
            struct stats_key_t stats_key = {};
            stats_key.trange = (fn->ts  - *start_ts) / INTERVAL_RANGE;
            stats_key.ip = fn->ip;
            stats_key.id = id;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        """
        self.functions = self.functions.replace("DF_ENTRY", self.entry_fn)
        self.functions = self.functions.replace("DF_EXIT", self.exit_fn)

    def __str__(self) -> str:
        return self.functions
