
        #include <linux/sched.h>
        #include <uapi/linux/limits.h>
        #include <uapi/linux/ptrace.h>
        
        struct stats_key_t {
            u64 trange;
            u64 id;
            u64 event_id;
            u64 ip;
            u64 file_hash;
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
        struct file_t {
          u64 id;
          int fd;  
        };
        struct filename_t {
            char fname[256];
        };
        
        BPF_HASH(pid_map, u32, u64); // map for apps to collect data
        BPF_HASH(fn_pid_map, struct fn_key_t, struct fn_t); // collect start time and ip for apps
        BPF_HASH(fn_map, struct stats_key_t, struct stats_t, 2 << 16); // emit events to python
        BPF_HASH(file_hash, u32, struct filename_t);
        BPF_HASH(latest_hash, u64, u32);
        BPF_HASH(latest_fd, u64, int);
        BPF_HASH(fd_hash, struct file_t, u32);
        BPF_HASH(pid_hash, u64, u64);
        
        static u64 get_hash(u64 id) {
            u64 first_hash = 1;
            u64* hash_value = pid_hash.lookup_or_init(&id, &first_hash);
            (*hash_value)++;
            return *hash_value;
        }
        
        int trace_datacrumbs_start(struct pt_regs *ctx) {
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = 10;
            u64* start_ts = pid_map.lookup(&pid);
            u64 tsp = bpf_ktime_get_ns();
            if (start_ts != 0)                                      
                tsp = *start_ts;
            else
                pid_map.update(&pid, &tsp);
            pid = id;
            bpf_trace_printk("Tracing PID \%d",pid);
            pid_map.update(&pid, &tsp);
            return 0;
        }
        int trace_datacrumbs_stop(struct pt_regs *ctx) {
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            bpf_trace_printk("Stop tracing PID \%d",pid);
            pid_map.delete(&pid);
            return 0;
        }
        
        int syscall__trace_entry_openat(struct pt_regs *ctx , int dfd, const char *filename, int flags) {
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
            
                        struct filename_t fname_i;
                        int len = bpf_probe_read_user_str(&fname_i.fname, sizeof(fname_i.fname), filename);
                        //fname_i.fname[len-1] = '\0';
                        u32 filehash = get_hash(id);
                        bpf_trace_printk("Hash value is %d for filename \%s",filename,filehash);
                        file_hash.update(&filehash, &fname_i);
                        latest_hash.update(&id, &filehash);
                        
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_openat(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 1;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            
                        u32* hash_ptr = latest_hash.lookup(&id);
                        if (hash_ptr != 0) {
                            stats_key.file_hash = *hash_ptr; 
                        }
                        
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
                        if (hash_ptr != 0) {
                            int fd = PT_REGS_RC(ctx);
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = fd;
                            fd_hash.update(&file_key, hash_ptr);
                        }
                        
            return 0;
        }
        
        int syscall__trace_entry_read(struct pt_regs *ctx 
                        , int fd, void *data, u64 count
                        ) {
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
            
                        latest_fd.update(&id,&fd);
                        
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_read(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 2;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u32* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key.file_hash = *hash_ptr; 
                            }
                        }
                        
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 
            return 0;
        }
        
        int syscall__trace_entry_write(struct pt_regs *ctx 
                        , int fd, const void *data, u64 count
                        ) {
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
            
                        latest_fd.update(&id,&fd);
                        
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_write(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 3;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u32* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key.file_hash = *hash_ptr; 
                            }
                        }
                        
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 
            return 0;
        }
        
        int syscall__trace_entry_close(struct pt_regs *ctx 
                        , int fd
                        ) {
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
            
                        latest_fd.update(&id,&fd);
                        
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_close(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 4;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u32* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key.file_hash = *hash_ptr; 
                            }
                        }
                        
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int syscall__trace_entry_copy_file_range(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_copy_file_range(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_execve(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_execve(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_execveat(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_execveat(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_exit(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_exit(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_faccessat(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_faccessat(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_fcntl(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_fcntl(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_fallocate(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_fallocate(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_fdatasync(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_fdatasync(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_flock(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_flock(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_fsopen(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_fsopen(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_fstatfs(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_fstatfs(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_fsync(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_fsync(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_ftruncate(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_ftruncate(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_io_pgetevents(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_io_pgetevents(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_lseek(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_lseek(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_memfd_create(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_memfd_create(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_migrate_pages(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_migrate_pages(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_mlock(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_mlock(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_mmap(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_mmap(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_msync(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_msync(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_pread64(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_pread64(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_preadv(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_preadv(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_preadv2(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_preadv2(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_pwrite64(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_pwrite64(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_pwritev(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_pwritev(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_pwritev2(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_pwritev2(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_readahead(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_readahead(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_readlinkat(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_readlinkat(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_readv(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_readv(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_renameat(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_renameat(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_renameat2(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_renameat2(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_statfs(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_statfs(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_statx(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_statx(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_sync(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_sync(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_sync_file_range(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_sync_file_range(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_syncfs(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_syncfs(struct pt_regs *ctx) {
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
        
        int syscall__trace_entry_writev(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int sys__trace_exit_writev(struct pt_regs *ctx) {
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
        
        int trace_os_cache_add_to_page_cache_lru_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_os_cache_add_to_page_cache_lru_exit(struct pt_regs *ctx) {
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
        
        int trace_os_cache_mark_page_accessed_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_os_cache_mark_page_accessed_exit(struct pt_regs *ctx) {
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
        
        int trace_os_cache_account_page_dirtied_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_os_cache_account_page_dirtied_exit(struct pt_regs *ctx) {
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
        
        int trace_os_cache_mark_buffer_dirty_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_os_cache_mark_buffer_dirty_exit(struct pt_regs *ctx) {
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
        
        int trace_os_cache_do_page_cache_ra_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_os_cache_do_page_cache_ra_exit(struct pt_regs *ctx) {
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
        
        int trace_os_cache___page_cache_alloc_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_os_cache___page_cache_alloc_exit(struct pt_regs *ctx) {
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
        
        int trace_os_cache_page_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_os_cache_page_exit(struct pt_regs *ctx) {
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
        
        int trace_os_cache_lru_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_os_cache_lru_exit(struct pt_regs *ctx) {
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
        
        int trace_os_cache_swap_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_os_cache_swap_exit(struct pt_regs *ctx) {
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
        
        int trace_os_cache_buffer_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_os_cache_buffer_exit(struct pt_regs *ctx) {
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
        
        int trace_os_cache_nr_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_os_cache_nr_exit(struct pt_regs *ctx) {
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
        
        int trace_map_map_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_map_map_exit(struct pt_regs *ctx) {
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
        
        int trace_bio_bio_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_bio_bio_exit(struct pt_regs *ctx) {
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
        
        int trace_ext4_ext4_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_ext4_ext4_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_vfs_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_vfs_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_generic_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_generic_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_remote_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_remote_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_llseek_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_llseek_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_do_sync_read_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_do_sync_read_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_vfs_read_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_vfs_read_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_do_sync_write_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_do_sync_write_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_vfs_write_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_vfs_write_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_file_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_file_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_do_readv_writev_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_do_readv_writev_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_vfs_readv_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_vfs_readv_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_vfs_writev_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_vfs_writev_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_do_sendfile_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_do_sendfile_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_rw_verify_area_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_rw_verify_area_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_wait_on_page_bit_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_wait_on_page_bit_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_find_or_create_page_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_find_or_create_page_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_find_get_pages_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_find_get_pages_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_find_get_pages_contig_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_find_get_pages_contig_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_grab_cache_page_nowait_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_grab_cache_page_nowait_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_wake_up_page_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_wake_up_page_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_do_readahead_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_do_readahead_exit(struct pt_regs *ctx) {
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
        
        int trace_vfs_read_cache_page_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_read_cache_page_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 77;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_vfs_fdatawrite_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_vfs_fdatawrite_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 78;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_c_fopen_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_fopen_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 79;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_c_fopen64_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_fopen64_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 80;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_c_fclose_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_fclose_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 81;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_c_fread_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_fread_exit(struct pt_regs *ctx) {
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
            stats_key.trange = (fn->ts  - *start_ts) / 1000000000;
            stats_key.event_id = 82;
            stats_key.id = id;
            stats_key.ip = fn->ip;
            
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(&stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
            
            return 0;
        }
        
        int trace_c_fwrite_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_fwrite_exit(struct pt_regs *ctx) {
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
        
        int trace_c_ftell_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_ftell_exit(struct pt_regs *ctx) {
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
        
        int trace_c_fseek_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_fseek_exit(struct pt_regs *ctx) {
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
        
        int trace_c_open_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_open_exit(struct pt_regs *ctx) {
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
        
        int trace_c_open64_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_open64_exit(struct pt_regs *ctx) {
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
        
        int trace_c_creat_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_creat_exit(struct pt_regs *ctx) {
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
        
        int trace_c_creat64_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_creat64_exit(struct pt_regs *ctx) {
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
        
        int trace_c_close_range_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_close_range_exit(struct pt_regs *ctx) {
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
        
        int trace_c_closefrom_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_closefrom_exit(struct pt_regs *ctx) {
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
        
        int trace_c_close_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_close_exit(struct pt_regs *ctx) {
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
        
        int trace_c_read_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_read_exit(struct pt_regs *ctx) {
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
        
        int trace_c_pread_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_pread_exit(struct pt_regs *ctx) {
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
        
        int trace_c_pread64_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_pread64_exit(struct pt_regs *ctx) {
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
        
        int trace_c_write_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_write_exit(struct pt_regs *ctx) {
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
        
        int trace_c_pwrite_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_pwrite_exit(struct pt_regs *ctx) {
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
        
        int trace_c_pwrite64_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_pwrite64_exit(struct pt_regs *ctx) {
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
        
        int trace_c_lseek_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_lseek_exit(struct pt_regs *ctx) {
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
        
        int trace_c_lseek64_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_lseek64_exit(struct pt_regs *ctx) {
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
        
        int trace_c_fdopen_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_fdopen_exit(struct pt_regs *ctx) {
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
        
        int trace_c_fileno_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_fileno_exit(struct pt_regs *ctx) {
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
        
        int trace_c_fileno_unlocked_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_fileno_unlocked_exit(struct pt_regs *ctx) {
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
        
        int trace_c_mmap_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_mmap_exit(struct pt_regs *ctx) {
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
        
        int trace_c_mmap64_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_mmap64_exit(struct pt_regs *ctx) {
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
        
        int trace_c_munmap_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_munmap_exit(struct pt_regs *ctx) {
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
        
        int trace_c_msync_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_msync_exit(struct pt_regs *ctx) {
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
        
        int trace_c_mremap_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_mremap_exit(struct pt_regs *ctx) {
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
        
        int trace_c_madvise_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_madvise_exit(struct pt_regs *ctx) {
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
        
        int trace_c_shm_open_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_shm_open_exit(struct pt_regs *ctx) {
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
        
        int trace_c_shm_unlink_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_shm_unlink_exit(struct pt_regs *ctx) {
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
        
        int trace_c_memfd_create_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_memfd_create_exit(struct pt_regs *ctx) {
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
        
        int trace_c_fsync_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_fsync_exit(struct pt_regs *ctx) {
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
        
        int trace_c_fdatasync_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_fdatasync_exit(struct pt_regs *ctx) {
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
        
        int trace_c_fcntl_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_fcntl_exit(struct pt_regs *ctx) {
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
        
        int trace_c_malloc_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_malloc_exit(struct pt_regs *ctx) {
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
        
        int trace_c_calloc_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_calloc_exit(struct pt_regs *ctx) {
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
        
        int trace_c_realloc_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_realloc_exit(struct pt_regs *ctx) {
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
        
        int trace_c_posix_memalign_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_posix_memalign_exit(struct pt_regs *ctx) {
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
        
        int trace_c_valloc_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_valloc_exit(struct pt_regs *ctx) {
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
        
        int trace_c_memalign_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_memalign_exit(struct pt_regs *ctx) {
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
        
        int trace_c_pvalloc_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_pvalloc_exit(struct pt_regs *ctx) {
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
        
        int trace_c_aligned_alloc_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_aligned_alloc_exit(struct pt_regs *ctx) {
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
        
        int trace_c_free_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_free_exit(struct pt_regs *ctx) {
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
        
        int trace_c_aio_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_c_aio_exit(struct pt_regs *ctx) {
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
        
        int trace_block_block_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_block_block_exit(struct pt_regs *ctx) {
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
        
        int trace_io_uring_io_uring_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_io_uring_io_uring_exit(struct pt_regs *ctx) {
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
        
        int trace_app__Z10gen_randomB5cxx11i_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_app__Z10gen_randomB5cxx11i_exit(struct pt_regs *ctx) {
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
        
        int trace_app__fini_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_app__fini_exit(struct pt_regs *ctx) {
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
        
        int trace_app__init_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_app__init_exit(struct pt_regs *ctx) {
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
        
        int trace_app__start_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_app__start_exit(struct pt_regs *ctx) {
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
        
        int trace_app_main_entry(struct pt_regs *ctx ) {
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
            
            fn_pid_map.update(&key, &fn);
            return 0;
        }

        int trace_app_main_exit(struct pt_regs *ctx) {
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
        