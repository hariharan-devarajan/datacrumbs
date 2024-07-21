
        #include <linux/sched.h>
        #include <uapi/linux/limits.h>
        #include <uapi/linux/ptrace.h>
        
        struct stats_key_t {
            u64 trange;
            u64 id;
            u64 event_id;
            u64 ip;
        };
        struct stats_t {
            u64 time;
            s64 count;
        };
        struct fn_key_t {
            s64 pid;
        };
        struct fn_t {
            u64 ts;
            u64 ip;
        };
        
        BPF_HASH(pid_map, u32, u64); // map for apps to collect data
        BPF_HASH(fn_pid_map, struct fn_key_t, struct fn_t); // collect start time and ip for apps
        BPF_HASH(fn_map, struct stats_key_t, struct stats_t, 2 << 16); // emit events to python
        
        int trace_dfprofiler_start(struct pt_regs *ctx) {
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64 tsp = bpf_ktime_get_ns();
            bpf_trace_printk("Tracing PID \%d",pid);
            pid_map.update(&pid, &tsp);
            return 0;
        }
        int trace_dfprofiler_stop(struct pt_regs *ctx) {
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            bpf_trace_printk("Stop tracing PID \%d",pid);
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
        
        int trace_sys_openat_entry(struct pt_regs *ctx) {
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

        int trace_sys_openat_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 1;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_read_entry(struct pt_regs *ctx) {
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

        int trace_sys_read_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 2;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_write_entry(struct pt_regs *ctx) {
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

        int trace_sys_write_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 3;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_close_entry(struct pt_regs *ctx) {
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

        int trace_sys_close_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 4;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_copy_file_range_entry(struct pt_regs *ctx) {
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

        int trace_sys_copy_file_range_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 5;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_execve_entry(struct pt_regs *ctx) {
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

        int trace_sys_execve_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 6;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_execveat_entry(struct pt_regs *ctx) {
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

        int trace_sys_execveat_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 7;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_exit_entry(struct pt_regs *ctx) {
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

        int trace_sys_exit_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 8;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_faccessat_entry(struct pt_regs *ctx) {
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

        int trace_sys_faccessat_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 9;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_fcntl_entry(struct pt_regs *ctx) {
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

        int trace_sys_fcntl_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 10;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_fallocate_entry(struct pt_regs *ctx) {
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

        int trace_sys_fallocate_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 11;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_fdatasync_entry(struct pt_regs *ctx) {
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

        int trace_sys_fdatasync_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 12;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_flock_entry(struct pt_regs *ctx) {
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

        int trace_sys_flock_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 13;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_fsopen_entry(struct pt_regs *ctx) {
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

        int trace_sys_fsopen_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 14;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_fstatfs_entry(struct pt_regs *ctx) {
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

        int trace_sys_fstatfs_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 15;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_fsync_entry(struct pt_regs *ctx) {
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

        int trace_sys_fsync_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 16;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_ftruncate_entry(struct pt_regs *ctx) {
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

        int trace_sys_ftruncate_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 17;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_io_pgetevents_entry(struct pt_regs *ctx) {
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

        int trace_sys_io_pgetevents_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 18;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_lseek_entry(struct pt_regs *ctx) {
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

        int trace_sys_lseek_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 19;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_memfd_create_entry(struct pt_regs *ctx) {
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

        int trace_sys_memfd_create_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 20;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_migrate_pages_entry(struct pt_regs *ctx) {
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

        int trace_sys_migrate_pages_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 21;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_mlock_entry(struct pt_regs *ctx) {
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

        int trace_sys_mlock_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 22;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_mmap_entry(struct pt_regs *ctx) {
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

        int trace_sys_mmap_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 23;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_msync_entry(struct pt_regs *ctx) {
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

        int trace_sys_msync_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 24;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_pread64_entry(struct pt_regs *ctx) {
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

        int trace_sys_pread64_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 25;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_preadv_entry(struct pt_regs *ctx) {
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

        int trace_sys_preadv_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 26;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_preadv2_entry(struct pt_regs *ctx) {
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

        int trace_sys_preadv2_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 27;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_pwrite64_entry(struct pt_regs *ctx) {
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

        int trace_sys_pwrite64_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 28;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_pwritev_entry(struct pt_regs *ctx) {
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

        int trace_sys_pwritev_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 29;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_pwritev2_entry(struct pt_regs *ctx) {
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

        int trace_sys_pwritev2_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 30;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_readahead_entry(struct pt_regs *ctx) {
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

        int trace_sys_readahead_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 31;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_readlinkat_entry(struct pt_regs *ctx) {
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

        int trace_sys_readlinkat_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 32;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_readv_entry(struct pt_regs *ctx) {
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

        int trace_sys_readv_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 33;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_renameat_entry(struct pt_regs *ctx) {
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

        int trace_sys_renameat_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 34;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_renameat2_entry(struct pt_regs *ctx) {
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

        int trace_sys_renameat2_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 35;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_statfs_entry(struct pt_regs *ctx) {
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

        int trace_sys_statfs_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 36;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_statx_entry(struct pt_regs *ctx) {
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

        int trace_sys_statx_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 37;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_sync_entry(struct pt_regs *ctx) {
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

        int trace_sys_sync_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 38;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_sync_file_range_entry(struct pt_regs *ctx) {
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

        int trace_sys_sync_file_range_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 39;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_syncfs_entry(struct pt_regs *ctx) {
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

        int trace_sys_syncfs_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 40;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_sys_writev_entry(struct pt_regs *ctx) {
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

        int trace_sys_writev_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 41;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_os_cache_add_to_page_cache_lru_entry(struct pt_regs *ctx) {
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

        int trace_os_cache_add_to_page_cache_lru_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 42;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_os_cache_mark_page_accessed_entry(struct pt_regs *ctx) {
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

        int trace_os_cache_mark_page_accessed_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 43;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_os_cache_account_page_dirtied_entry(struct pt_regs *ctx) {
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

        int trace_os_cache_account_page_dirtied_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 44;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_os_cache_mark_buffer_dirty_entry(struct pt_regs *ctx) {
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

        int trace_os_cache_mark_buffer_dirty_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 45;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_os_cache_do_page_cache_ra_entry(struct pt_regs *ctx) {
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

        int trace_os_cache_do_page_cache_ra_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 46;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_os_cache___page_cache_alloc_entry(struct pt_regs *ctx) {
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

        int trace_os_cache___page_cache_alloc_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 47;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_ext4_ext4_file_write_iter_entry(struct pt_regs *ctx) {
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

        int trace_ext4_ext4_file_write_iter_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 48;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_ext4_ext4_file_open_entry(struct pt_regs *ctx) {
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

        int trace_ext4_ext4_file_open_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 49;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_ext4_ext4_sync_file_entry(struct pt_regs *ctx) {
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

        int trace_ext4_ext4_sync_file_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 50;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_ext4_ext4_alloc_da_blocks_entry(struct pt_regs *ctx) {
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

        int trace_ext4_ext4_alloc_da_blocks_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 51;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_ext4_ext4_da_release_space_entry(struct pt_regs *ctx) {
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

        int trace_ext4_ext4_da_release_space_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 52;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_ext4_ext4_da_reserve_space_entry(struct pt_regs *ctx) {
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

        int trace_ext4_ext4_da_reserve_space_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 53;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_ext4_ext4_da_write_begin_entry(struct pt_regs *ctx) {
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

        int trace_ext4_ext4_da_write_begin_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 54;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_ext4_ext4_da_write_end_entry(struct pt_regs *ctx) {
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

        int trace_ext4_ext4_da_write_end_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 55;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_ext4_ext4_discard_preallocations_entry(struct pt_regs *ctx) {
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

        int trace_ext4_ext4_discard_preallocations_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 56;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_ext4_ext4_fallocate_entry(struct pt_regs *ctx) {
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

        int trace_ext4_ext4_fallocate_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 57;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_ext4_ext4_free_blocks_entry(struct pt_regs *ctx) {
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

        int trace_ext4_ext4_free_blocks_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 58;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_ext4_ext4_readpage_entry(struct pt_regs *ctx) {
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

        int trace_ext4_ext4_readpage_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 59;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_ext4_ext4_remove_blocks_entry(struct pt_regs *ctx) {
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

        int trace_ext4_ext4_remove_blocks_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 60;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_ext4_ext4_sync_fs_entry(struct pt_regs *ctx) {
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

        int trace_ext4_ext4_sync_fs_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 61;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_ext4_ext4_truncate_entry(struct pt_regs *ctx) {
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

        int trace_ext4_ext4_truncate_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 62;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_ext4_ext4_write_begin_entry(struct pt_regs *ctx) {
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

        int trace_ext4_ext4_write_begin_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 63;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_ext4_ext4_write_end_entry(struct pt_regs *ctx) {
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

        int trace_ext4_ext4_write_end_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 64;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_ext4_ext4_writepage_entry(struct pt_regs *ctx) {
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

        int trace_ext4_ext4_writepage_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 65;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_ext4_ext4_writepages_entry(struct pt_regs *ctx) {
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

        int trace_ext4_ext4_writepages_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 66;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_ext4_ext4_zero_range_entry(struct pt_regs *ctx) {
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

        int trace_ext4_ext4_zero_range_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 67;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_vfs_vfs_entry(struct pt_regs *ctx) {
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

        int trace_vfs_vfs_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 68;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_vfs_rw_verify_area_entry(struct pt_regs *ctx) {
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

        int trace_vfs_rw_verify_area_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 69;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_open_entry(struct pt_regs *ctx) {
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

        int trace_c_open_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 70;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_open64_entry(struct pt_regs *ctx) {
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

        int trace_c_open64_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 71;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_creat_entry(struct pt_regs *ctx) {
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

        int trace_c_creat_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 72;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_creat64_entry(struct pt_regs *ctx) {
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

        int trace_c_creat64_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 73;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_close_range_entry(struct pt_regs *ctx) {
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

        int trace_c_close_range_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 74;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_closefrom_entry(struct pt_regs *ctx) {
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

        int trace_c_closefrom_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 75;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_close_entry(struct pt_regs *ctx) {
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

        int trace_c_close_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 76;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_read_entry(struct pt_regs *ctx) {
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

        int trace_c_read_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 77;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_pread_entry(struct pt_regs *ctx) {
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

        int trace_c_pread_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 78;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_pread64_entry(struct pt_regs *ctx) {
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

        int trace_c_pread64_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 79;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_write_entry(struct pt_regs *ctx) {
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

        int trace_c_write_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 80;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_pwrite_entry(struct pt_regs *ctx) {
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

        int trace_c_pwrite_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 81;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_pwrite64_entry(struct pt_regs *ctx) {
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

        int trace_c_pwrite64_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 82;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_lseek_entry(struct pt_regs *ctx) {
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

        int trace_c_lseek_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 83;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_lseek64_entry(struct pt_regs *ctx) {
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

        int trace_c_lseek64_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 84;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_fdopen_entry(struct pt_regs *ctx) {
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

        int trace_c_fdopen_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 85;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_fileno_entry(struct pt_regs *ctx) {
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

        int trace_c_fileno_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 86;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_fileno_unlocked_entry(struct pt_regs *ctx) {
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

        int trace_c_fileno_unlocked_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 87;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_mmap_entry(struct pt_regs *ctx) {
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

        int trace_c_mmap_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 88;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_mmap64_entry(struct pt_regs *ctx) {
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

        int trace_c_mmap64_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 89;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_munmap_entry(struct pt_regs *ctx) {
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

        int trace_c_munmap_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 90;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_msync_entry(struct pt_regs *ctx) {
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

        int trace_c_msync_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 91;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_mremap_entry(struct pt_regs *ctx) {
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

        int trace_c_mremap_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 92;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_madvise_entry(struct pt_regs *ctx) {
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

        int trace_c_madvise_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 93;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_shm_open_entry(struct pt_regs *ctx) {
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

        int trace_c_shm_open_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 94;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_shm_unlink_entry(struct pt_regs *ctx) {
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

        int trace_c_shm_unlink_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 95;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_memfd_create_entry(struct pt_regs *ctx) {
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

        int trace_c_memfd_create_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 96;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_fsync_entry(struct pt_regs *ctx) {
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

        int trace_c_fsync_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 97;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_fdatasync_entry(struct pt_regs *ctx) {
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

        int trace_c_fdatasync_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 98;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_fcntl_entry(struct pt_regs *ctx) {
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

        int trace_c_fcntl_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 99;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_malloc_entry(struct pt_regs *ctx) {
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

        int trace_c_malloc_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 100;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_calloc_entry(struct pt_regs *ctx) {
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

        int trace_c_calloc_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 101;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_realloc_entry(struct pt_regs *ctx) {
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

        int trace_c_realloc_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 102;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_posix_memalign_entry(struct pt_regs *ctx) {
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

        int trace_c_posix_memalign_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 103;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_valloc_entry(struct pt_regs *ctx) {
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

        int trace_c_valloc_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 104;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_memalign_entry(struct pt_regs *ctx) {
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

        int trace_c_memalign_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 105;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_pvalloc_entry(struct pt_regs *ctx) {
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

        int trace_c_pvalloc_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 106;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_aligned_alloc_entry(struct pt_regs *ctx) {
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

        int trace_c_aligned_alloc_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 107;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_c_free_entry(struct pt_regs *ctx) {
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

        int trace_c_free_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 108;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_block_block_entry(struct pt_regs *ctx) {
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

        int trace_block_block_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 109;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_io_uring_io_uring_entry(struct pt_regs *ctx) {
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

        int trace_io_uring_io_uring_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 110;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_app_app_entry(struct pt_regs *ctx) {
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

        int trace_app_app_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 111;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        
        int trace_mpi_mpi_entry(struct pt_regs *ctx) {
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

        int trace_mpi_mpi_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000;
            stats_key.event_id = 112;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->count++;
            return 0;
        }
        