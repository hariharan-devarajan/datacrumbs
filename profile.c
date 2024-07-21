
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
            s64 freq;
            
        
            
            u64 size_sum;
        
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 1;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 2;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 3;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 4;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 5;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 6;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 7;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 8;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 9;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 10;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 11;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 12;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 13;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 14;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 15;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 16;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 17;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 18;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 19;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 20;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 21;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 22;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 23;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 24;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 25;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 26;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 27;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 28;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 29;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 30;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 31;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 32;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 33;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 34;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 35;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 36;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 37;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 38;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 39;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 40;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 41;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 42;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 43;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 44;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 45;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 46;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 47;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 48;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 49;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 50;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 51;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 52;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 53;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 54;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 55;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 56;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 57;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 58;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 59;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 60;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 61;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 62;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 63;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 64;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 65;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 66;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 67;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 68;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 69;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 70;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 71;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 72;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 73;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 74;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 75;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 76;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 77;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 78;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 79;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 80;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 81;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 82;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 83;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 84;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 85;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 86;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 87;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 88;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 89;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 90;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 91;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 92;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 93;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 94;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 95;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 96;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 97;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 98;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 99;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 100;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 101;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 102;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 103;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 104;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 105;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 106;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 107;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 108;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 109;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 110;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_app__Z10gen_randomB5cxx11i_entry(struct pt_regs *ctx) {
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

        int trace_app__Z10gen_randomB5cxx11i_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 111;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_app__fini_entry(struct pt_regs *ctx) {
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

        int trace_app__fini_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 112;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_app__init_entry(struct pt_regs *ctx) {
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

        int trace_app__init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 113;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_app__start_entry(struct pt_regs *ctx) {
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

        int trace_app__start_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 114;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_app_main_entry(struct pt_regs *ctx) {
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

        int trace_app_main_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 115;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPIX_Comm_ack_failed_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPIX_Comm_ack_failed_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 116;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPIX_Comm_agree_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPIX_Comm_agree_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 117;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPIX_Comm_failure_ack_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPIX_Comm_failure_ack_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 118;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPIX_Comm_failure_get_acked_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPIX_Comm_failure_get_acked_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 119;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPIX_Comm_get_failed_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPIX_Comm_get_failed_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 120;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPIX_Comm_iagree_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPIX_Comm_iagree_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 121;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPIX_Comm_is_revoked_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPIX_Comm_is_revoked_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 122;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPIX_Comm_revoke_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPIX_Comm_revoke_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 123;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPIX_Comm_shrink_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPIX_Comm_shrink_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 124;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Abort_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Abort_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 125;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Accumulate_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Accumulate_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 126;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Add_error_class_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Add_error_class_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 127;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Add_error_code_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Add_error_code_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 128;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Add_error_string_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Add_error_string_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 129;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Address_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Address_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 130;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Allgather_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Allgather_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 131;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Allgather_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Allgather_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 132;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Allgatherv_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Allgatherv_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 133;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Allgatherv_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Allgatherv_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 134;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Alloc_mem_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Alloc_mem_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 135;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Allreduce_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Allreduce_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 136;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Allreduce_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Allreduce_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 137;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Alltoall_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Alltoall_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 138;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Alltoall_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Alltoall_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 139;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Alltoallv_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Alltoallv_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 140;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Alltoallv_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Alltoallv_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 141;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Alltoallw_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Alltoallw_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 142;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Alltoallw_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Alltoallw_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 143;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Attr_delete_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Attr_delete_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 144;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Attr_get_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Attr_get_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 145;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Attr_put_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Attr_put_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 146;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Barrier_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Barrier_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 147;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Barrier_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Barrier_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 148;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Bcast_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Bcast_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 149;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Bcast_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Bcast_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 150;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Bsend_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Bsend_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 151;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Bsend_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Bsend_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 152;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Buffer_attach_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Buffer_attach_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 153;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Buffer_detach_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Buffer_detach_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 154;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Cancel_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Cancel_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 155;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Cart_coords_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Cart_coords_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 156;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Cart_create_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Cart_create_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 157;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Cart_get_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Cart_get_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 158;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Cart_map_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Cart_map_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 159;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Cart_rank_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Cart_rank_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 160;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Cart_shift_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Cart_shift_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 161;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Cart_sub_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Cart_sub_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 162;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Cartdim_get_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Cartdim_get_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 163;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Close_port_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Close_port_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 164;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_accept_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_accept_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 165;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_c2f_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_c2f_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 166;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_call_errhandler_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_call_errhandler_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 167;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_compare_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_compare_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 168;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_connect_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_connect_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 169;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_create_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_create_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 170;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_create_errhandler_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_create_errhandler_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 171;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_create_from_group_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_create_from_group_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 172;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_create_group_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_create_group_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 173;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_create_keyval_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_create_keyval_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 174;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_delete_attr_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_delete_attr_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 175;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_disconnect_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_disconnect_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 176;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_dup_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_dup_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 177;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_dup_with_info_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_dup_with_info_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 178;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_f2c_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_f2c_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 179;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_free_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_free_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 180;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_free_keyval_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_free_keyval_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 181;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_get_attr_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_get_attr_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 182;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_get_errhandler_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_get_errhandler_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 183;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_get_info_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_get_info_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 184;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_get_name_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_get_name_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 185;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_get_parent_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_get_parent_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 186;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_group_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_group_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 187;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_idup_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_idup_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 188;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_idup_with_info_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_idup_with_info_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 189;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_join_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_join_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 190;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_rank_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_rank_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 191;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_remote_group_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_remote_group_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 192;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_remote_size_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_remote_size_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 193;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_set_attr_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_set_attr_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 194;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_set_errhandler_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_set_errhandler_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 195;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_set_info_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_set_info_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 196;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_set_name_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_set_name_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 197;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_size_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_size_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 198;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_spawn_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_spawn_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 199;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_spawn_multiple_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_spawn_multiple_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 200;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_split_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_split_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 201;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_split_type_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_split_type_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 202;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Comm_test_inter_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Comm_test_inter_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 203;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Compare_and_swap_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Compare_and_swap_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 204;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Dims_create_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Dims_create_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 205;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Dist_graph_create_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Dist_graph_create_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 206;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Dist_graph_create_adjacent_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Dist_graph_create_adjacent_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 207;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Dist_graph_neighbors_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Dist_graph_neighbors_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 208;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Dist_graph_neighbors_count_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Dist_graph_neighbors_count_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 209;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Errhandler_c2f_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Errhandler_c2f_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 210;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Errhandler_create_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Errhandler_create_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 211;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Errhandler_f2c_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Errhandler_f2c_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 212;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Errhandler_free_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Errhandler_free_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 213;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Errhandler_get_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Errhandler_get_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 214;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Errhandler_set_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Errhandler_set_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 215;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Error_class_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Error_class_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 216;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Error_string_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Error_string_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 217;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Exscan_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Exscan_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 218;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Exscan_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Exscan_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 219;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Fetch_and_op_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Fetch_and_op_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 220;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_c2f_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_c2f_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 221;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_call_errhandler_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_call_errhandler_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 222;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_close_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_close_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 223;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_create_errhandler_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_create_errhandler_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 224;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_delete_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_delete_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 225;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_f2c_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_f2c_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 226;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_get_amode_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_get_amode_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 227;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_get_atomicity_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_get_atomicity_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 228;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_get_byte_offset_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_get_byte_offset_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 229;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_get_errhandler_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_get_errhandler_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 230;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_get_group_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_get_group_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 231;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_get_info_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_get_info_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 232;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_get_position_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_get_position_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 233;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_get_position_shared_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_get_position_shared_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 234;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_get_size_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_get_size_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 235;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_get_type_extent_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_get_type_extent_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 236;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_get_view_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_get_view_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 237;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_iread_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_iread_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 238;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_iread_all_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_iread_all_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 239;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_iread_at_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_iread_at_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 240;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_iread_at_all_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_iread_at_all_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 241;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_iread_shared_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_iread_shared_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 242;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_iwrite_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_iwrite_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 243;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_iwrite_all_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_iwrite_all_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 244;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_iwrite_at_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_iwrite_at_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 245;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_iwrite_at_all_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_iwrite_at_all_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 246;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_iwrite_shared_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_iwrite_shared_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 247;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_open_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_open_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 248;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_preallocate_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_preallocate_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 249;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_read_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_read_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 250;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_read_all_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_read_all_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 251;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_read_all_begin_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_read_all_begin_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 252;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_read_all_end_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_read_all_end_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 253;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_read_at_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_read_at_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 254;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_read_at_all_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_read_at_all_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 255;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_read_at_all_begin_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_read_at_all_begin_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 256;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_read_at_all_end_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_read_at_all_end_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 257;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_read_ordered_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_read_ordered_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 258;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_read_ordered_begin_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_read_ordered_begin_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 259;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_read_ordered_end_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_read_ordered_end_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 260;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_read_shared_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_read_shared_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 261;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_seek_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_seek_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 262;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_seek_shared_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_seek_shared_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 263;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_set_atomicity_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_set_atomicity_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 264;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_set_errhandler_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_set_errhandler_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 265;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_set_info_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_set_info_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 266;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_set_size_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_set_size_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 267;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_set_view_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_set_view_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 268;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_sync_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_sync_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 269;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_write_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_write_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 270;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_write_all_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_write_all_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 271;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_write_all_begin_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_write_all_begin_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 272;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_write_all_end_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_write_all_end_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 273;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_write_at_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_write_at_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 274;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_write_at_all_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_write_at_all_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 275;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_write_at_all_begin_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_write_at_all_begin_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 276;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_write_at_all_end_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_write_at_all_end_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 277;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_write_ordered_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_write_ordered_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 278;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_write_ordered_begin_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_write_ordered_begin_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 279;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_write_ordered_end_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_write_ordered_end_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 280;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_File_write_shared_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_File_write_shared_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 281;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Finalize_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Finalize_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 282;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Finalized_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Finalized_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 283;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Free_mem_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Free_mem_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 284;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Gather_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Gather_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 285;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Gather_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Gather_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 286;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Gatherv_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Gatherv_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 287;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Gatherv_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Gatherv_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 288;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Get_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Get_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 289;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Get_accumulate_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Get_accumulate_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 290;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Get_address_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Get_address_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 291;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Get_count_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Get_count_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 292;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Get_elements_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Get_elements_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 293;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Get_elements_x_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Get_elements_x_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 294;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Get_library_version_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Get_library_version_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 295;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Get_processor_name_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Get_processor_name_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 296;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Get_version_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Get_version_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 297;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Graph_create_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Graph_create_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 298;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Graph_get_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Graph_get_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 299;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Graph_map_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Graph_map_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 300;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Graph_neighbors_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Graph_neighbors_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 301;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Graph_neighbors_count_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Graph_neighbors_count_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 302;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Graphdims_get_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Graphdims_get_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 303;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Grequest_complete_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Grequest_complete_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 304;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Grequest_start_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Grequest_start_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 305;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Group_c2f_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Group_c2f_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 306;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Group_compare_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Group_compare_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 307;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Group_difference_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Group_difference_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 308;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Group_excl_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Group_excl_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 309;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Group_f2c_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Group_f2c_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 310;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Group_free_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Group_free_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 311;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Group_from_session_pset_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Group_from_session_pset_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 312;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Group_incl_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Group_incl_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 313;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Group_intersection_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Group_intersection_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 314;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Group_range_excl_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Group_range_excl_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 315;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Group_range_incl_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Group_range_incl_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 316;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Group_rank_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Group_rank_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 317;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Group_size_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Group_size_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 318;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Group_translate_ranks_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Group_translate_ranks_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 319;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Group_union_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Group_union_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 320;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Iallgather_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Iallgather_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 321;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Iallgatherv_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Iallgatherv_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 322;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Iallreduce_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Iallreduce_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 323;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Ialltoall_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Ialltoall_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 324;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Ialltoallv_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Ialltoallv_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 325;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Ialltoallw_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Ialltoallw_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 326;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Ibarrier_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Ibarrier_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 327;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Ibcast_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Ibcast_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 328;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Ibsend_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Ibsend_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 329;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Iexscan_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Iexscan_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 330;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Igather_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Igather_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 331;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Igatherv_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Igatherv_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 332;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Improbe_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Improbe_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 333;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Imrecv_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Imrecv_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 334;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Ineighbor_allgather_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Ineighbor_allgather_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 335;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Ineighbor_allgatherv_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Ineighbor_allgatherv_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 336;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Ineighbor_alltoall_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Ineighbor_alltoall_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 337;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Ineighbor_alltoallv_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Ineighbor_alltoallv_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 338;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Ineighbor_alltoallw_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Ineighbor_alltoallw_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 339;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Info_c2f_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Info_c2f_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 340;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Info_create_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Info_create_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 341;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Info_create_env_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Info_create_env_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 342;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Info_delete_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Info_delete_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 343;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Info_dup_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Info_dup_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 344;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Info_f2c_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Info_f2c_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 345;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Info_free_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Info_free_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 346;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Info_get_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Info_get_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 347;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Info_get_nkeys_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Info_get_nkeys_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 348;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Info_get_nthkey_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Info_get_nthkey_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 349;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Info_get_string_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Info_get_string_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 350;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Info_get_valuelen_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Info_get_valuelen_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 351;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Info_set_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Info_set_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 352;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 353;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Init_thread_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Init_thread_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 354;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Initialized_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Initialized_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 355;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Intercomm_create_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Intercomm_create_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 356;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Intercomm_create_from_groups_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Intercomm_create_from_groups_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 357;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Intercomm_merge_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Intercomm_merge_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 358;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Iprobe_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Iprobe_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 359;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Irecv_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Irecv_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 360;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Ireduce_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Ireduce_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 361;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Ireduce_scatter_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Ireduce_scatter_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 362;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Ireduce_scatter_block_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Ireduce_scatter_block_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 363;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Irsend_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Irsend_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 364;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Is_thread_main_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Is_thread_main_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 365;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Iscan_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Iscan_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 366;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Iscatter_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Iscatter_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 367;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Iscatterv_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Iscatterv_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 368;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Isend_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Isend_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 369;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Isendrecv_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Isendrecv_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 370;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Isendrecv_replace_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Isendrecv_replace_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 371;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Issend_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Issend_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 372;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Keyval_create_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Keyval_create_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 373;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Keyval_free_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Keyval_free_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 374;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Lookup_name_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Lookup_name_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 375;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Message_c2f_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Message_c2f_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 376;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Message_f2c_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Message_f2c_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 377;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Mprobe_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Mprobe_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 378;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Mrecv_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Mrecv_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 379;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Neighbor_allgather_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Neighbor_allgather_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 380;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Neighbor_allgather_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Neighbor_allgather_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 381;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Neighbor_allgatherv_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Neighbor_allgatherv_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 382;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Neighbor_allgatherv_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Neighbor_allgatherv_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 383;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Neighbor_alltoall_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Neighbor_alltoall_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 384;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Neighbor_alltoall_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Neighbor_alltoall_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 385;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Neighbor_alltoallv_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Neighbor_alltoallv_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 386;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Neighbor_alltoallv_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Neighbor_alltoallv_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 387;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Neighbor_alltoallw_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Neighbor_alltoallw_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 388;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Neighbor_alltoallw_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Neighbor_alltoallw_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 389;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Op_c2f_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Op_c2f_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 390;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Op_commutative_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Op_commutative_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 391;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Op_create_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Op_create_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 392;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Op_f2c_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Op_f2c_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 393;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Op_free_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Op_free_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 394;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Open_port_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Open_port_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 395;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Pack_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Pack_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 396;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Pack_external_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Pack_external_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 397;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Pack_external_size_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Pack_external_size_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 398;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Pack_size_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Pack_size_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 399;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Parrived_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Parrived_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 400;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Pcontrol_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Pcontrol_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 401;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Pready_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Pready_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 402;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Pready_list_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Pready_list_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 403;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Pready_range_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Pready_range_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 404;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Precv_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Precv_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 405;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Probe_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Probe_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 406;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Psend_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Psend_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 407;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Publish_name_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Publish_name_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 408;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Put_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Put_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 409;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Query_thread_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Query_thread_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 410;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Raccumulate_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Raccumulate_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 411;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Recv_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Recv_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 412;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Recv_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Recv_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 413;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Reduce_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Reduce_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 414;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Reduce_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Reduce_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 415;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Reduce_local_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Reduce_local_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 416;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Reduce_scatter_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Reduce_scatter_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 417;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Reduce_scatter_block_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Reduce_scatter_block_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 418;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Reduce_scatter_block_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Reduce_scatter_block_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 419;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Reduce_scatter_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Reduce_scatter_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 420;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Register_datarep_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Register_datarep_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 421;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Request_c2f_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Request_c2f_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 422;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Request_f2c_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Request_f2c_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 423;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Request_free_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Request_free_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 424;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Request_get_status_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Request_get_status_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 425;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Rget_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Rget_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 426;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Rget_accumulate_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Rget_accumulate_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 427;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Rput_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Rput_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 428;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Rsend_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Rsend_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 429;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Rsend_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Rsend_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 430;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Scan_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Scan_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 431;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Scan_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Scan_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 432;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Scatter_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Scatter_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 433;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Scatter_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Scatter_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 434;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Scatterv_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Scatterv_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 435;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Scatterv_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Scatterv_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 436;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Send_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Send_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 437;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Send_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Send_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 438;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Sendrecv_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Sendrecv_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 439;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Sendrecv_replace_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Sendrecv_replace_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 440;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Session_c2f_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Session_c2f_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 441;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Session_call_errhandler_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Session_call_errhandler_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 442;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Session_create_errhandler_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Session_create_errhandler_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 443;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Session_f2c_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Session_f2c_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 444;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Session_finalize_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Session_finalize_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 445;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Session_get_errhandler_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Session_get_errhandler_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 446;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Session_get_info_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Session_get_info_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 447;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Session_get_nth_pset_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Session_get_nth_pset_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 448;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Session_get_num_psets_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Session_get_num_psets_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 449;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Session_get_pset_info_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Session_get_pset_info_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 450;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Session_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Session_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 451;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Session_set_errhandler_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Session_set_errhandler_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 452;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Session_set_info_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Session_set_info_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 453;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Ssend_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Ssend_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 454;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Ssend_init_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Ssend_init_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 455;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Start_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Start_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 456;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Startall_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Startall_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 457;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Status_c2f_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Status_c2f_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 458;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Status_c2f08_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Status_c2f08_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 459;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Status_f082c_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Status_f082c_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 460;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Status_f082f_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Status_f082f_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 461;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Status_f2c_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Status_f2c_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 462;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Status_f2f08_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Status_f2f08_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 463;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Status_set_cancelled_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Status_set_cancelled_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 464;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Status_set_elements_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Status_set_elements_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 465;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Status_set_elements_x_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Status_set_elements_x_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 466;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_category_changed_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_category_changed_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 467;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_category_get_categories_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_category_get_categories_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 468;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_category_get_cvars_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_category_get_cvars_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 469;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_category_get_index_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_category_get_index_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 470;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_category_get_info_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_category_get_info_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 471;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_category_get_num_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_category_get_num_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 472;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_category_get_pvars_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_category_get_pvars_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 473;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_cvar_get_index_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_cvar_get_index_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 474;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_cvar_get_info_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_cvar_get_info_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 475;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_cvar_get_num_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_cvar_get_num_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 476;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_cvar_handle_alloc_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_cvar_handle_alloc_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 477;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_cvar_handle_free_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_cvar_handle_free_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 478;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_cvar_read_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_cvar_read_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 479;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_cvar_write_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_cvar_write_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 480;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_enum_get_info_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_enum_get_info_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 481;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_enum_get_item_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_enum_get_item_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 482;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_finalize_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_finalize_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 483;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_init_thread_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_init_thread_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 484;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_pvar_get_index_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_pvar_get_index_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 485;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_pvar_get_info_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_pvar_get_info_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 486;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_pvar_get_num_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_pvar_get_num_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 487;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_pvar_handle_alloc_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_pvar_handle_alloc_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 488;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_pvar_handle_free_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_pvar_handle_free_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 489;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_pvar_read_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_pvar_read_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 490;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_pvar_readreset_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_pvar_readreset_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 491;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_pvar_reset_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_pvar_reset_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 492;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_pvar_session_create_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_pvar_session_create_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 493;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_pvar_session_free_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_pvar_session_free_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 494;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_pvar_start_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_pvar_start_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 495;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_pvar_stop_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_pvar_stop_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 496;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_T_pvar_write_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_T_pvar_write_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 497;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Test_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Test_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 498;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Test_cancelled_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Test_cancelled_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 499;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Testall_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Testall_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 500;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Testany_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Testany_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 501;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Testsome_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Testsome_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 502;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Topo_test_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Topo_test_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 503;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_c2f_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_c2f_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 504;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_commit_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_commit_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 505;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_contiguous_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_contiguous_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 506;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_create_darray_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_create_darray_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 507;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_create_f90_complex_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_create_f90_complex_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 508;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_create_f90_integer_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_create_f90_integer_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 509;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_create_f90_real_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_create_f90_real_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 510;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_create_hindexed_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_create_hindexed_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 511;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_create_hindexed_block_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_create_hindexed_block_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 512;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_create_hvector_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_create_hvector_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 513;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_create_indexed_block_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_create_indexed_block_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 514;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_create_keyval_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_create_keyval_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 515;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_create_resized_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_create_resized_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 516;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_create_struct_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_create_struct_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 517;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_create_subarray_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_create_subarray_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 518;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_delete_attr_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_delete_attr_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 519;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_dup_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_dup_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 520;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_extent_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_extent_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 521;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_f2c_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_f2c_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 522;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_free_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_free_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 523;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_free_keyval_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_free_keyval_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 524;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_get_attr_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_get_attr_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 525;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_get_contents_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_get_contents_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 526;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_get_envelope_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_get_envelope_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 527;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_get_extent_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_get_extent_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 528;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_get_extent_x_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_get_extent_x_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 529;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_get_name_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_get_name_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 530;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_get_true_extent_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_get_true_extent_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 531;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_get_true_extent_x_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_get_true_extent_x_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 532;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_hindexed_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_hindexed_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 533;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_hvector_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_hvector_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 534;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_indexed_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_indexed_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 535;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_lb_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_lb_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 536;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_match_size_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_match_size_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 537;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_set_attr_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_set_attr_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 538;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_set_name_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_set_name_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 539;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_size_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_size_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 540;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_size_x_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_size_x_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 541;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_struct_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_struct_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 542;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_ub_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_ub_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 543;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Type_vector_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Type_vector_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 544;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Unpack_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Unpack_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 545;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Unpack_external_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Unpack_external_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 546;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Unpublish_name_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Unpublish_name_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 547;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Wait_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Wait_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 548;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Waitall_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Waitall_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 549;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Waitany_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Waitany_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 550;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Waitsome_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Waitsome_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 551;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_allocate_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_allocate_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 552;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_allocate_shared_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_allocate_shared_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 553;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_attach_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_attach_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 554;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_c2f_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_c2f_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 555;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_call_errhandler_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_call_errhandler_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 556;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_complete_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_complete_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 557;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_create_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_create_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 558;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_create_dynamic_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_create_dynamic_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 559;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_create_errhandler_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_create_errhandler_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 560;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_create_keyval_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_create_keyval_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 561;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_delete_attr_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_delete_attr_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 562;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_detach_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_detach_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 563;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_f2c_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_f2c_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 564;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_fence_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_fence_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 565;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_flush_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_flush_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 566;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_flush_all_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_flush_all_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 567;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_flush_local_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_flush_local_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 568;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_flush_local_all_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_flush_local_all_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 569;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_free_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_free_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 570;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_free_keyval_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_free_keyval_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 571;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_get_attr_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_get_attr_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 572;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_get_errhandler_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_get_errhandler_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 573;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_get_group_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_get_group_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 574;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_get_info_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_get_info_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 575;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_get_name_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_get_name_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 576;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_lock_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_lock_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 577;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_lock_all_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_lock_all_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 578;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_post_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_post_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 579;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_set_attr_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_set_attr_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 580;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_set_errhandler_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_set_errhandler_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 581;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_set_info_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_set_info_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 582;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_set_name_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_set_name_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 583;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_shared_query_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_shared_query_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 584;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_start_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_start_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 585;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_sync_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_sync_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 586;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_test_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_test_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 587;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_unlock_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_unlock_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 588;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_unlock_all_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_unlock_all_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 589;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Win_wait_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Win_wait_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 590;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Wtick_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Wtick_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 591;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_mpi_PMPI_Wtime_entry(struct pt_regs *ctx) {
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

        int trace_mpi_PMPI_Wtime_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 592;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        