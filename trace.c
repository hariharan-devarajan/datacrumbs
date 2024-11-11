
        #include <linux/sched.h>
        #include <uapi/linux/limits.h>
        #include <uapi/linux/ptrace.h>
        
        struct fn_key_t {
            u64 id;
        };
        struct fn_t {
            u64 ip;
            u64 ts;
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
        BPF_HASH(file_hash, u64, struct filename_t, 10240);
        BPF_HASH(latest_hash, struct fn_key_t, u64);
        BPF_HASH(latest_fd, u64, int);
        BPF_HASH(fd_hash, struct file_t, u64);
        BPF_HASH(pid_hash, u64, u64);
        
        BPF_RINGBUF_OUTPUT(events, 1 << 16); // emit events to python
        
        static u64 get_hash(unsigned char *str, u64 len) {
            u64 hash = 5381;
            int c = *str;
            int count = 0;
            while (count < len && c) {
                hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
                c = *str++;
                count++;
            }
            return hash;
        }
        /*static u64 get_hash(u64 id) {
            u64 first_hash = 1;
            u64* hash_value = pid_hash.lookup_or_init(&id, &first_hash);
            (*hash_value)++;
            return *hash_value;
        }*/
        
        struct generic_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
        };         
        int trace_generic_entry(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
            return 0;
        }

        int trace_generic_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct generic_event_t stats_key_v = {};
            struct generic_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 10000;
            stats_key->ip = fn->ip;
                    
                        
            struct generic_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
              
            bpf_trace_printk("Submitting GEN TRACE IP \%d",fn->ip);      
            
            events.ringbuf_output(&stats_key_v, sizeof(struct generic_event_t), 0);
        
            return 0;
        }
        
        int syscall__trace_entry_generic(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
           
            return 0;
        }

        int sys__trace_exit_generic(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct generic_event_t stats_key_v = {};
            struct generic_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 10000;
            stats_key->ip = fn->ip;
        
                        
            struct generic_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            bpf_trace_printk("Submitting GEN SYS IP \%d",fn->ip);
            
            events.ringbuf_output(&stats_key_v, sizeof(struct generic_event_t), 0);
        
            
        
            return 0;
        }
        
        int trace_datacrumbs_start(struct pt_regs *ctx) {
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = 0;
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
        
        
            struct sys_openat_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            u64 file_hash;
            
        };
        
        int syscall__trace_entry_openat(struct pt_regs *ctx , int dfd, const char *filename, int flags) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
        
            
                        struct filename_t fname_i;
                        u64 filename_len = sizeof(fname_i.fname);
                        int len = bpf_probe_read_user_str(&fname_i.fname, filename_len, filename);
                        //fname_i.fname[len-1] = '\0';
                        u64 filehash = get_hash(fname_i.fname, filename_len);
                        bpf_trace_printk("Hash value is %d for filename \%s",filehash,filename);
                        file_hash.update(&filehash, &fname_i);
                        latest_hash.update(&key, &filehash);
                           
            return 0;
        }

        int sys__trace_exit_openat(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_openat_event_t stats_key_v = {};
            struct sys_openat_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 1;
            stats_key->ip = fn->ip;
        
            
                        u64* hash_ptr = latest_hash.lookup(&key);
                        if (hash_ptr != 0) {
                            stats_key->file_hash = *hash_ptr; 
                        }
                        
                        
            struct sys_openat_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
                        if (hash_ptr != 0) {
                            int fd = PT_REGS_RC(ctx);
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = fd;
                            fd_hash.update(&file_key, hash_ptr);
                        }
                        
            bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_openat_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_read_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            u64 file_hash;
            u64 size_sum;
        };
        
        int syscall__trace_entry_read(struct pt_regs *ctx 
                        , int fd, void *data, u64 count
                        ) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
        
            
                        latest_fd.update(&id,&fd);
                           
            return 0;
        }

        int sys__trace_exit_read(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_read_event_t stats_key_v = {};
            struct sys_read_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 2;
            stats_key->ip = fn->ip;
        
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        
                        
            struct sys_read_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 
            bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_read_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_write_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            u64 file_hash;
            u64 size_sum;
        };
        
        int syscall__trace_entry_write(struct pt_regs *ctx 
                        , int fd, const void *data, u64 count
                        ) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
        
            
                        latest_fd.update(&id,&fd);
                           
            return 0;
        }

        int sys__trace_exit_write(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_write_event_t stats_key_v = {};
            struct sys_write_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 3;
            stats_key->ip = fn->ip;
        
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        
                        
            struct sys_write_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 
            bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_write_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_close_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            u64 file_hash;
            
        };
        
        int syscall__trace_entry_close(struct pt_regs *ctx 
                        , int fd
                        ) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
        
            
                        latest_fd.update(&id,&fd);
                           
            return 0;
        }

        int sys__trace_exit_close(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_close_event_t stats_key_v = {};
            struct sys_close_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 4;
            stats_key->ip = fn->ip;
        
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        
                        
            struct sys_close_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_close_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_fallocate_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            u64 file_hash;
            
        };
        
        int syscall__trace_entry_fallocate(struct pt_regs *ctx 
                        , int fd, int mode, int offset, int len
                        ) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
        
            
                        latest_fd.update(&id,&fd);
                           
            return 0;
        }

        int sys__trace_exit_fallocate(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_fallocate_event_t stats_key_v = {};
            struct sys_fallocate_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 5;
            stats_key->ip = fn->ip;
        
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        
                        
            struct sys_fallocate_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_fallocate_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_fdatasync_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            u64 file_hash;
            
        };
        
        int syscall__trace_entry_fdatasync(struct pt_regs *ctx 
                        , int fd
                        ) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
        
            
                        latest_fd.update(&id,&fd);
                           
            return 0;
        }

        int sys__trace_exit_fdatasync(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_fdatasync_event_t stats_key_v = {};
            struct sys_fdatasync_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 6;
            stats_key->ip = fn->ip;
        
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        
                        
            struct sys_fdatasync_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_fdatasync_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_flock_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            u64 file_hash;
            
        };
        
        int syscall__trace_entry_flock(struct pt_regs *ctx 
                        , int fd, int cmd
                        ) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
        
            
                        latest_fd.update(&id,&fd);
                           
            return 0;
        }

        int sys__trace_exit_flock(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_flock_event_t stats_key_v = {};
            struct sys_flock_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 7;
            stats_key->ip = fn->ip;
        
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        
                        
            struct sys_flock_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_flock_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_fsync_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            u64 file_hash;
            
        };
        
        int syscall__trace_entry_fsync(struct pt_regs *ctx 
                        , int fd
                        ) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
        
            
                        latest_fd.update(&id,&fd);
                           
            return 0;
        }

        int sys__trace_exit_fsync(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_fsync_event_t stats_key_v = {};
            struct sys_fsync_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 8;
            stats_key->ip = fn->ip;
        
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        
                        
            struct sys_fsync_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_fsync_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_ftruncate_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            u64 file_hash;
            
        };
        
        int syscall__trace_entry_ftruncate(struct pt_regs *ctx 
                        , int fd, int length
                        ) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
        
            
                        latest_fd.update(&id,&fd);
                           
            return 0;
        }

        int sys__trace_exit_ftruncate(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_ftruncate_event_t stats_key_v = {};
            struct sys_ftruncate_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 9;
            stats_key->ip = fn->ip;
        
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        
                        
            struct sys_ftruncate_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_ftruncate_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_lseek_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            u64 file_hash;
            
        };
        
        int syscall__trace_entry_lseek(struct pt_regs *ctx 
                        , int fd, int offset, int whence
                        ) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
        
            
                        latest_fd.update(&id,&fd);
                           
            return 0;
        }

        int sys__trace_exit_lseek(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_lseek_event_t stats_key_v = {};
            struct sys_lseek_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 10;
            stats_key->ip = fn->ip;
        
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        
                        
            struct sys_lseek_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_lseek_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_pread64_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            u64 file_hash;
            u64 size_sum;
        };
        
        int syscall__trace_entry_pread64(struct pt_regs *ctx 
                        , int fd, void *buf, u64 count, u64 pos
                        ) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
        
            
                        latest_fd.update(&id,&fd);
                           
            return 0;
        }

        int sys__trace_exit_pread64(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_pread64_event_t stats_key_v = {};
            struct sys_pread64_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 11;
            stats_key->ip = fn->ip;
        
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        
                        
            struct sys_pread64_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 
            bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_pread64_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_preadv_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            u64 file_hash;
            u64 size_sum;
        };
        
        int syscall__trace_entry_preadv(struct pt_regs *ctx 
                        , int fd, u64 buf, u64 vlen, u64 pos_l, u64 pos_h
                        ) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
        
            
                        latest_fd.update(&id,&fd);
                           
            return 0;
        }

        int sys__trace_exit_preadv(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_preadv_event_t stats_key_v = {};
            struct sys_preadv_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 12;
            stats_key->ip = fn->ip;
        
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        
                        
            struct sys_preadv_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 
            bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_preadv_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_preadv2_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            u64 file_hash;
            u64 size_sum;
        };
        
        int syscall__trace_entry_preadv2(struct pt_regs *ctx 
                        , int fd, u64 buf, u64 vlen, u64 pos_l, u64 pos_h, u64 flags
                        ) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
        
            
                        latest_fd.update(&id,&fd);
                           
            return 0;
        }

        int sys__trace_exit_preadv2(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_preadv2_event_t stats_key_v = {};
            struct sys_preadv2_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 13;
            stats_key->ip = fn->ip;
        
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        
                        
            struct sys_preadv2_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 
            bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_preadv2_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_pwrite64_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            u64 file_hash;
            u64 size_sum;
        };
        
        int syscall__trace_entry_pwrite64(struct pt_regs *ctx 
                        , int fd, const void *data, u64 count, u64 pos
                        ) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
        
            
                        latest_fd.update(&id,&fd);
                           
            return 0;
        }

        int sys__trace_exit_pwrite64(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_pwrite64_event_t stats_key_v = {};
            struct sys_pwrite64_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 14;
            stats_key->ip = fn->ip;
        
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        
                        
            struct sys_pwrite64_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 
            bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_pwrite64_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_pwritev_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            u64 file_hash;
            u64 size_sum;
        };
        
        int syscall__trace_entry_pwritev(struct pt_regs *ctx 
                        , int fd, u64 buf, u64 vlen, u64 pos_l, u64 pos_h
                        ) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
        
            
                        latest_fd.update(&id,&fd);
                           
            return 0;
        }

        int sys__trace_exit_pwritev(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_pwritev_event_t stats_key_v = {};
            struct sys_pwritev_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 15;
            stats_key->ip = fn->ip;
        
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        
                        
            struct sys_pwritev_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 
            bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_pwritev_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_pwritev2_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            u64 file_hash;
            u64 size_sum;
        };
        
        int syscall__trace_entry_pwritev2(struct pt_regs *ctx 
                        , int fd, u64 buf, u64 vlen, u64 pos_l, u64 pos_h, u64 flags
                        ) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
        
            
                        latest_fd.update(&id,&fd);
                           
            return 0;
        }

        int sys__trace_exit_pwritev2(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_pwritev2_event_t stats_key_v = {};
            struct sys_pwritev2_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 16;
            stats_key->ip = fn->ip;
        
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        
                        
            struct sys_pwritev2_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 
            bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_pwritev2_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_readahead_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            u64 file_hash;
            u64 size_sum;
        };
        
        int syscall__trace_entry_readahead(struct pt_regs *ctx 
                        , int fd, u64 offset, u64 count
                        ) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
        
            
                        latest_fd.update(&id,&fd);
                           
            return 0;
        }

        int sys__trace_exit_readahead(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_readahead_event_t stats_key_v = {};
            struct sys_readahead_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 17;
            stats_key->ip = fn->ip;
        
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        
                        
            struct sys_readahead_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 
            bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_readahead_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_readv_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            u64 file_hash;
            u64 size_sum;
        };
        
        int syscall__trace_entry_readv(struct pt_regs *ctx 
                        , int fd, u64 vec, u64 vlen
                        ) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
        
            
                        latest_fd.update(&id,&fd);
                           
            return 0;
        }

        int sys__trace_exit_readv(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_readv_event_t stats_key_v = {};
            struct sys_readv_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 18;
            stats_key->ip = fn->ip;
        
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        
                        
            struct sys_readv_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 
            bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_readv_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_writev_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            u64 file_hash;
            u64 size_sum;
        };
        
        int syscall__trace_entry_writev(struct pt_regs *ctx 
                        , int fd, u64 vec, u64 vlen
                        ) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
        
            
                        latest_fd.update(&id,&fd);
                           
            return 0;
        }

        int sys__trace_exit_writev(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_writev_event_t stats_key_v = {};
            struct sys_writev_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 19;
            stats_key->ip = fn->ip;
        
            
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        
                        
            struct sys_writev_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 
            bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_writev_event_t), 0);
        
            
        
            return 0;
        }
        