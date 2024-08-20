class BCCCollector:
    entry_fn: str
    exit_fn: str

    def __init__(self) -> None:
        self.sys_functions = """
        int syscall__trace_entry_DFFUNCTION(struct pt_regs *ctx DFENTRYARGS) {
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
            struct fn_key_t key = {};
            key.pid = pid;
            struct fn_t fn = {};
            fn.ip = PT_REGS_IP(ctx);
            fn.ts = bpf_ktime_get_ns();
            DFENTRYCMD
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_DFFUNCTION(struct pt_regs *ctx) {
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
            struct fn_key_t key = {};
            key.pid = pid;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
            struct stats_key_t stats_key = {};
            stats_key.trange = (fn->ts  - *start_ts) / INTERVAL_RANGE;
            stats_key.event_id = DFEVENTID;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            DFEXITCMDKEY
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            DFEXITCMDSTATS
            return 0;
        }
        """
        self.functions = """
        int trace_DFCAT_DFFUNCTION_entry(struct pt_regs *ctx DFENTRYARGS) {
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
            struct fn_key_t key = {};
            key.pid = pid;
            struct fn_t fn = {};
            fn.ip = PT_REGS_IP(ctx);
            fn.ts = bpf_ktime_get_ns();
            DFENTRYCMD
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_DFCAT_DFFUNCTION_exit(struct pt_regs *ctx) {
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
            struct fn_key_t key = {};
            key.pid = pid;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
            struct stats_key_t stats_key = {};
            stats_key.trange = (fn->ts  - *start_ts) / INTERVAL_RANGE;
            stats_key.event_id = DFEVENTID;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            DFEXITCMDKEY
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            DFEXITCMDSTATS
            return 0;
        }
        """
