
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
        // BPF_PERF_OUTPUT(events); // emit events to python
        
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            stats_key->event_id = 100001;
            stats_key->ip = fn->ip;
                    
                        
            struct generic_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
              
            // bpf_trace_printk("Submitting GEN TRACE IP \%d",fn->ip);      
            
            events.ringbuf_output(&stats_key_v, sizeof(struct generic_event_t), 0);
        
            return 0;
        }
                
        int user_generic_entry(struct pt_regs *ctx) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
            return 0;
        }

        int user_generic_exit(struct pt_regs *ctx) {
            
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
            stats_key->event_id = 100002;
            stats_key->ip = fn->ip;
                    
                        
            struct generic_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
              
            // bpf_trace_printk("Submitting GEN TRACE IP \%d",fn->ip);      
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            stats_key->event_id = 100000;
            stats_key->ip = fn->ip;
        
                        
            struct generic_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            // bpf_trace_printk("Submitting GEN SYS IP \%d",fn->ip);
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
                        
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
                                 
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
                                 
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_close_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_copy_file_range_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_copy_file_range(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_copy_file_range_event_t stats_key_v = {};
            struct sys_copy_file_range_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 5;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_copy_file_range_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_copy_file_range_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_execve_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_execve(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_execve_event_t stats_key_v = {};
            struct sys_execve_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 6;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_execve_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_execve_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_execveat_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_execveat(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_execveat_event_t stats_key_v = {};
            struct sys_execveat_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 7;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_execveat_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_execveat_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_exit_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_exit(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_exit_event_t stats_key_v = {};
            struct sys_exit_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 8;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_exit_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_exit_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_faccessat_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_faccessat(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_faccessat_event_t stats_key_v = {};
            struct sys_faccessat_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 9;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_faccessat_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_faccessat_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_fcntl_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_fcntl(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_fcntl_event_t stats_key_v = {};
            struct sys_fcntl_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 10;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_fcntl_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_fcntl_event_t), 0);
        
            
        
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
                        
                        
            struct sys_fallocate_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
                        
                        
            struct sys_fdatasync_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
                        
                        
            struct sys_flock_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_flock_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_fsopen_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_fsopen(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_fsopen_event_t stats_key_v = {};
            struct sys_fsopen_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 14;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_fsopen_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_fsopen_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_fstatfs_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_fstatfs(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_fstatfs_event_t stats_key_v = {};
            struct sys_fstatfs_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 15;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_fstatfs_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_fstatfs_event_t), 0);
        
            
        
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
                        
                        
            struct sys_fsync_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
                        
                        
            struct sys_ftruncate_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_ftruncate_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_io_pgetevents_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_io_pgetevents(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_io_pgetevents_event_t stats_key_v = {};
            struct sys_io_pgetevents_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 18;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_io_pgetevents_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_io_pgetevents_event_t), 0);
        
            
        
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
                        
                        
            struct sys_lseek_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_lseek_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_memfd_create_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_memfd_create(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_memfd_create_event_t stats_key_v = {};
            struct sys_memfd_create_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 20;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_memfd_create_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_memfd_create_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_migrate_pages_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_migrate_pages(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_migrate_pages_event_t stats_key_v = {};
            struct sys_migrate_pages_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 21;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_migrate_pages_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_migrate_pages_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_mlock_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_mlock(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_mlock_event_t stats_key_v = {};
            struct sys_mlock_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 22;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_mlock_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_mlock_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_mmap_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_mmap(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_mmap_event_t stats_key_v = {};
            struct sys_mmap_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 23;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_mmap_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_mmap_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_msync_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_msync(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_msync_event_t stats_key_v = {};
            struct sys_msync_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 24;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_msync_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_msync_event_t), 0);
        
            
        
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            stats_key->event_id = 25;
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
                                 
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            stats_key->event_id = 26;
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
                                 
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            stats_key->event_id = 27;
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
                                 
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            stats_key->event_id = 28;
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
                                 
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            stats_key->event_id = 29;
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
                                 
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            stats_key->event_id = 30;
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
                                 
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            stats_key->event_id = 31;
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
                                 
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_readahead_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_readlinkat_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_readlinkat(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_readlinkat_event_t stats_key_v = {};
            struct sys_readlinkat_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 32;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_readlinkat_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_readlinkat_event_t), 0);
        
            
        
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            stats_key->event_id = 33;
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
                                 
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_readv_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_renameat_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_renameat(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_renameat_event_t stats_key_v = {};
            struct sys_renameat_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 34;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_renameat_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_renameat_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_renameat2_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_renameat2(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_renameat2_event_t stats_key_v = {};
            struct sys_renameat2_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 35;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_renameat2_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_renameat2_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_statfs_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_statfs(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_statfs_event_t stats_key_v = {};
            struct sys_statfs_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 36;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_statfs_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_statfs_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_statx_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_statx(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_statx_event_t stats_key_v = {};
            struct sys_statx_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 37;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_statx_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_statx_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_sync_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_sync(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_sync_event_t stats_key_v = {};
            struct sys_sync_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 38;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_sync_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_sync_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_sync_file_range_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_sync_file_range(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_sync_file_range_event_t stats_key_v = {};
            struct sys_sync_file_range_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 39;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_sync_file_range_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_sync_file_range_event_t), 0);
        
            
        
            return 0;
        }
        
        
            struct sys_syncfs_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        int syscall__trace_entry_syncfs(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_syncfs_event_t stats_key_v = {};
            struct sys_syncfs_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 40;
            stats_key->ip = fn->ip;
        
            
                        
            struct sys_syncfs_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_syncfs_event_t), 0);
        
            
        
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            stats_key->event_id = 41;
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
                                 
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct sys_writev_event_t), 0);
        
            
        
            return 0;
        }
        
        
        
            struct os_cache_add_to_page_cache_lru_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_os_cache_add_to_page_cache_lru_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct os_cache_add_to_page_cache_lru_event_t stats_key_v = {};
            struct os_cache_add_to_page_cache_lru_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 42;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct os_cache_add_to_page_cache_lru_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct os_cache_add_to_page_cache_lru_event_t), 0);
        
            return 0;
        }
        
        
        
            struct os_cache_mark_page_accessed_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_os_cache_mark_page_accessed_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct os_cache_mark_page_accessed_event_t stats_key_v = {};
            struct os_cache_mark_page_accessed_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 43;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct os_cache_mark_page_accessed_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct os_cache_mark_page_accessed_event_t), 0);
        
            return 0;
        }
        
        
        
            struct os_cache_account_page_dirtied_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_os_cache_account_page_dirtied_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct os_cache_account_page_dirtied_event_t stats_key_v = {};
            struct os_cache_account_page_dirtied_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 44;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct os_cache_account_page_dirtied_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct os_cache_account_page_dirtied_event_t), 0);
        
            return 0;
        }
        
        
        
            struct os_cache_mark_buffer_dirty_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_os_cache_mark_buffer_dirty_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct os_cache_mark_buffer_dirty_event_t stats_key_v = {};
            struct os_cache_mark_buffer_dirty_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 45;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct os_cache_mark_buffer_dirty_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct os_cache_mark_buffer_dirty_event_t), 0);
        
            return 0;
        }
        
        
        
            struct os_cache_do_page_cache_ra_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_os_cache_do_page_cache_ra_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct os_cache_do_page_cache_ra_event_t stats_key_v = {};
            struct os_cache_do_page_cache_ra_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 46;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct os_cache_do_page_cache_ra_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct os_cache_do_page_cache_ra_event_t), 0);
        
            return 0;
        }
        
        
        
            struct os_cache_page_cache_pipe_buf_release_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_os_cache_page_cache_pipe_buf_release_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_os_cache_page_cache_pipe_buf_release_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct os_cache_page_cache_pipe_buf_release_event_t stats_key_v = {};
            struct os_cache_page_cache_pipe_buf_release_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 47;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct os_cache_page_cache_pipe_buf_release_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct os_cache_page_cache_pipe_buf_release_event_t), 0);
        
            return 0;
        }
        
        
        
            struct os_cache___page_cache_alloc_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_os_cache___page_cache_alloc_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct os_cache___page_cache_alloc_event_t stats_key_v = {};
            struct os_cache___page_cache_alloc_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 48;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct os_cache___page_cache_alloc_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct os_cache___page_cache_alloc_event_t), 0);
        
            return 0;
        }
        
        
        
            struct os_cache___do_page_cache_readahead_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_os_cache___do_page_cache_readahead_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_os_cache___do_page_cache_readahead_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct os_cache___do_page_cache_readahead_event_t stats_key_v = {};
            struct os_cache___do_page_cache_readahead_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 49;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct os_cache___do_page_cache_readahead_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct os_cache___do_page_cache_readahead_event_t), 0);
        
            return 0;
        }
        
        
        
            struct vfs_vfs_read_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_vfs_vfs_read_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct vfs_vfs_read_event_t stats_key_v = {};
            struct vfs_vfs_read_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 50;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct vfs_vfs_read_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct vfs_vfs_read_event_t), 0);
        
            return 0;
        }
        
        
        
            struct vfs_vfs_write_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_vfs_vfs_write_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct vfs_vfs_write_event_t stats_key_v = {};
            struct vfs_vfs_write_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 51;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct vfs_vfs_write_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct vfs_vfs_write_event_t), 0);
        
            return 0;
        }
        
        
        
            struct vfs_vfs_readv_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_vfs_vfs_readv_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct vfs_vfs_readv_event_t stats_key_v = {};
            struct vfs_vfs_readv_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 52;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct vfs_vfs_readv_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct vfs_vfs_readv_event_t), 0);
        
            return 0;
        }
        
        
        
            struct vfs_vfs_writev_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_vfs_vfs_writev_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct vfs_vfs_writev_event_t stats_key_v = {};
            struct vfs_vfs_writev_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 53;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct vfs_vfs_writev_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct vfs_vfs_writev_event_t), 0);
        
            return 0;
        }
        
        
        
            struct vfs_do_sendfile_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_vfs_do_sendfile_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct vfs_do_sendfile_event_t stats_key_v = {};
            struct vfs_do_sendfile_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 54;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct vfs_do_sendfile_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct vfs_do_sendfile_event_t), 0);
        
            return 0;
        }
        
        
        
            struct vfs_rw_verify_area_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_vfs_rw_verify_area_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct vfs_rw_verify_area_event_t stats_key_v = {};
            struct vfs_rw_verify_area_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 55;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct vfs_rw_verify_area_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct vfs_rw_verify_area_event_t), 0);
        
            return 0;
        }
        
        
        
            struct vfs_wait_on_page_bit_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_vfs_wait_on_page_bit_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct vfs_wait_on_page_bit_event_t stats_key_v = {};
            struct vfs_wait_on_page_bit_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 56;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct vfs_wait_on_page_bit_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct vfs_wait_on_page_bit_event_t), 0);
        
            return 0;
        }
        
        
        
            struct vfs_find_get_pages_contig_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_vfs_find_get_pages_contig_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct vfs_find_get_pages_contig_event_t stats_key_v = {};
            struct vfs_find_get_pages_contig_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 57;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct vfs_find_get_pages_contig_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct vfs_find_get_pages_contig_event_t), 0);
        
            return 0;
        }
        
        
        
            struct vfs_grab_cache_page_nowait_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_vfs_grab_cache_page_nowait_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct vfs_grab_cache_page_nowait_event_t stats_key_v = {};
            struct vfs_grab_cache_page_nowait_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 58;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct vfs_grab_cache_page_nowait_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct vfs_grab_cache_page_nowait_event_t), 0);
        
            return 0;
        }
        
        
        
            struct vfs_read_cache_page_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_vfs_read_cache_page_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct vfs_read_cache_page_event_t stats_key_v = {};
            struct vfs_read_cache_page_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 59;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct vfs_read_cache_page_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct vfs_read_cache_page_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_fopen_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_fopen_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_fopen_event_t stats_key_v = {};
            struct c_fopen_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 60;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_fopen_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_fopen_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_fopen64_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_fopen64_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_fopen64_event_t stats_key_v = {};
            struct c_fopen64_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 61;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_fopen64_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_fopen64_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_fclose_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_fclose_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_fclose_event_t stats_key_v = {};
            struct c_fclose_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 62;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_fclose_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_fclose_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_fread_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_fread_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_fread_event_t stats_key_v = {};
            struct c_fread_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 63;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_fread_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_fread_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_fwrite_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_fwrite_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_fwrite_event_t stats_key_v = {};
            struct c_fwrite_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 64;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_fwrite_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_fwrite_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_ftell_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_ftell_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_ftell_event_t stats_key_v = {};
            struct c_ftell_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 65;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_ftell_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_ftell_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_fseek_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_fseek_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_fseek_event_t stats_key_v = {};
            struct c_fseek_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 66;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_fseek_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_fseek_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_open_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_open_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_open_event_t stats_key_v = {};
            struct c_open_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 67;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_open_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_open_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_open64_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_open64_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_open64_event_t stats_key_v = {};
            struct c_open64_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 68;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_open64_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_open64_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_creat_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_creat_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_creat_event_t stats_key_v = {};
            struct c_creat_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 69;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_creat_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_creat_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_creat64_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_creat64_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_creat64_event_t stats_key_v = {};
            struct c_creat64_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 70;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_creat64_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_creat64_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_close_range_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_close_range_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_close_range_event_t stats_key_v = {};
            struct c_close_range_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 71;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_close_range_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_close_range_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_closefrom_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_closefrom_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_closefrom_event_t stats_key_v = {};
            struct c_closefrom_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 72;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_closefrom_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_closefrom_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_pread_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_pread_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_pread_event_t stats_key_v = {};
            struct c_pread_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 73;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_pread_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_pread_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_pwrite_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_pwrite_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_pwrite_event_t stats_key_v = {};
            struct c_pwrite_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 74;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_pwrite_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_pwrite_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_lseek64_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_lseek64_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_lseek64_event_t stats_key_v = {};
            struct c_lseek64_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 75;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_lseek64_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_lseek64_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_fdopen_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_fdopen_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_fdopen_event_t stats_key_v = {};
            struct c_fdopen_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 76;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_fdopen_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_fdopen_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_fileno_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_fileno_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_fileno_event_t stats_key_v = {};
            struct c_fileno_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 77;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_fileno_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_fileno_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_fileno_unlocked_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_fileno_unlocked_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_fileno_unlocked_event_t stats_key_v = {};
            struct c_fileno_unlocked_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 78;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_fileno_unlocked_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_fileno_unlocked_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_mmap64_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_mmap64_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_mmap64_event_t stats_key_v = {};
            struct c_mmap64_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 79;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_mmap64_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_mmap64_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_munmap_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_munmap_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_munmap_event_t stats_key_v = {};
            struct c_munmap_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 80;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_munmap_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_munmap_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_mremap_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_mremap_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_mremap_event_t stats_key_v = {};
            struct c_mremap_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 81;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_mremap_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_mremap_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_madvise_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_madvise_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_madvise_event_t stats_key_v = {};
            struct c_madvise_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 82;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_madvise_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_madvise_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_shm_open_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_shm_open_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_shm_open_event_t stats_key_v = {};
            struct c_shm_open_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 83;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_shm_open_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_shm_open_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_shm_unlink_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_shm_unlink_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_shm_unlink_event_t stats_key_v = {};
            struct c_shm_unlink_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 84;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_shm_unlink_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_shm_unlink_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_malloc_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_malloc_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_malloc_event_t stats_key_v = {};
            struct c_malloc_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 85;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_malloc_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_malloc_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_calloc_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_calloc_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_calloc_event_t stats_key_v = {};
            struct c_calloc_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 86;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_calloc_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_calloc_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_realloc_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_realloc_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_realloc_event_t stats_key_v = {};
            struct c_realloc_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 87;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_realloc_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_realloc_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_posix_memalign_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_posix_memalign_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_posix_memalign_event_t stats_key_v = {};
            struct c_posix_memalign_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 88;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_posix_memalign_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_posix_memalign_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_valloc_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_valloc_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_valloc_event_t stats_key_v = {};
            struct c_valloc_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 89;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_valloc_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_valloc_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_memalign_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_memalign_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_memalign_event_t stats_key_v = {};
            struct c_memalign_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 90;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_memalign_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_memalign_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_pvalloc_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_pvalloc_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_pvalloc_event_t stats_key_v = {};
            struct c_pvalloc_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 91;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_pvalloc_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_pvalloc_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_aligned_alloc_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_aligned_alloc_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_aligned_alloc_event_t stats_key_v = {};
            struct c_aligned_alloc_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 92;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_aligned_alloc_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_aligned_alloc_event_t), 0);
        
            return 0;
        }
        
        
        
            struct c_free_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_c_free_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
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
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct c_free_event_t stats_key_v = {};
            struct c_free_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 93;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct c_free_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct c_free_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app1__Z10gen_randomB5cxx11i_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app1__Z10gen_randomB5cxx11i_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app1__Z10gen_randomB5cxx11i_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app1__Z10gen_randomB5cxx11i_event_t stats_key_v = {};
            struct app1__Z10gen_randomB5cxx11i_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 94;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app1__Z10gen_randomB5cxx11i_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app1__Z10gen_randomB5cxx11i_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app1__fini_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app1__fini_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app1__fini_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app1__fini_event_t stats_key_v = {};
            struct app1__fini_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 95;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app1__fini_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app1__fini_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app1__init_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app1__init_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app1__init_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app1__init_event_t stats_key_v = {};
            struct app1__init_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 96;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app1__init_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app1__init_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app1__start_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app1__start_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app1__start_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app1__start_event_t stats_key_v = {};
            struct app1__start_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 97;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app1__start_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app1__start_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app1_main_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app1_main_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app1_main_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app1_main_event_t stats_key_v = {};
            struct app1_main_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 98;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app1_main_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app1_main_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app2__Z10gen_randomB5cxx11i_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app2__Z10gen_randomB5cxx11i_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app2__Z10gen_randomB5cxx11i_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app2__Z10gen_randomB5cxx11i_event_t stats_key_v = {};
            struct app2__Z10gen_randomB5cxx11i_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 99;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app2__Z10gen_randomB5cxx11i_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app2__Z10gen_randomB5cxx11i_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app2__fini_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app2__fini_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app2__fini_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app2__fini_event_t stats_key_v = {};
            struct app2__fini_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 100;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app2__fini_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app2__fini_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app2__init_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app2__init_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app2__init_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app2__init_event_t stats_key_v = {};
            struct app2__init_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 101;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app2__init_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app2__init_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app2__start_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app2__start_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app2__start_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app2__start_event_t stats_key_v = {};
            struct app2__start_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 102;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app2__start_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app2__start_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app2_main_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app2_main_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app2_main_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app2_main_event_t stats_key_v = {};
            struct app2_main_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 103;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app2_main_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app2_main_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_AllocResults_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_AllocResults_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_AllocResults_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_AllocResults_event_t stats_key_v = {};
            struct app3_AllocResults_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 104;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_AllocResults_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_AllocResults_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_CreateTest_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_CreateTest_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_CreateTest_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_CreateTest_event_t stats_key_v = {};
            struct app3_CreateTest_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 105;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_CreateTest_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_CreateTest_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_CurrentTimeString_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_CurrentTimeString_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_CurrentTimeString_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_CurrentTimeString_event_t stats_key_v = {};
            struct app3_CurrentTimeString_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 106;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_CurrentTimeString_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_CurrentTimeString_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_DecodeDirective_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_DecodeDirective_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_DecodeDirective_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_DecodeDirective_event_t stats_key_v = {};
            struct app3_DecodeDirective_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 107;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_DecodeDirective_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_DecodeDirective_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_DelaySecs_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_DelaySecs_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_DelaySecs_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_DelaySecs_event_t stats_key_v = {};
            struct app3_DelaySecs_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 108;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_DelaySecs_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_DelaySecs_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_DumpBuffer_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_DumpBuffer_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_DumpBuffer_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_DumpBuffer_event_t stats_key_v = {};
            struct app3_DumpBuffer_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 109;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_DumpBuffer_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_DumpBuffer_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_ExtractHint_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_ExtractHint_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_ExtractHint_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_ExtractHint_event_t stats_key_v = {};
            struct app3_ExtractHint_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 110;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_ExtractHint_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_ExtractHint_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_FailMessage_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_FailMessage_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_FailMessage_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_FailMessage_event_t stats_key_v = {};
            struct app3_FailMessage_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 111;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_FailMessage_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_FailMessage_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_FreeResults_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_FreeResults_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_FreeResults_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_FreeResults_event_t stats_key_v = {};
            struct app3_FreeResults_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 112;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_FreeResults_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_FreeResults_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_GetNumNodes_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_GetNumNodes_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_GetNumNodes_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_GetNumNodes_event_t stats_key_v = {};
            struct app3_GetNumNodes_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 113;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_GetNumNodes_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_GetNumNodes_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_GetNumTasks_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_GetNumTasks_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_GetNumTasks_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_GetNumTasks_event_t stats_key_v = {};
            struct app3_GetNumTasks_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 114;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_GetNumTasks_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_GetNumTasks_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_GetNumTasksOnNode0_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_GetNumTasksOnNode0_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_GetNumTasksOnNode0_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_GetNumTasksOnNode0_event_t stats_key_v = {};
            struct app3_GetNumTasksOnNode0_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 115;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_GetNumTasksOnNode0_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_GetNumTasksOnNode0_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_GetOffsetArrayRandom_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_GetOffsetArrayRandom_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_GetOffsetArrayRandom_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_GetOffsetArrayRandom_event_t stats_key_v = {};
            struct app3_GetOffsetArrayRandom_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 116;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_GetOffsetArrayRandom_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_GetOffsetArrayRandom_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_GetPlatformName_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_GetPlatformName_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_GetPlatformName_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_GetPlatformName_event_t stats_key_v = {};
            struct app3_GetPlatformName_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 117;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_GetPlatformName_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_GetPlatformName_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_GetProcessorAndCore_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_GetProcessorAndCore_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_GetProcessorAndCore_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_GetProcessorAndCore_event_t stats_key_v = {};
            struct app3_GetProcessorAndCore_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 118;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_GetProcessorAndCore_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_GetProcessorAndCore_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_GetTestFileName_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_GetTestFileName_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_GetTestFileName_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_GetTestFileName_event_t stats_key_v = {};
            struct app3_GetTestFileName_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 119;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_GetTestFileName_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_GetTestFileName_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_GetTimeStamp_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_GetTimeStamp_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_GetTimeStamp_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_GetTimeStamp_event_t stats_key_v = {};
            struct app3_GetTimeStamp_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 120;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_GetTimeStamp_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_GetTimeStamp_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_HumanReadable_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_HumanReadable_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_HumanReadable_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_HumanReadable_event_t stats_key_v = {};
            struct app3_HumanReadable_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 121;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_HumanReadable_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_HumanReadable_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_MPIIO_Access_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_MPIIO_Access_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_MPIIO_Access_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_MPIIO_Access_event_t stats_key_v = {};
            struct app3_MPIIO_Access_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 122;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_MPIIO_Access_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_MPIIO_Access_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_MPIIO_Delete_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_MPIIO_Delete_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_MPIIO_Delete_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_MPIIO_Delete_event_t stats_key_v = {};
            struct app3_MPIIO_Delete_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 123;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_MPIIO_Delete_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_MPIIO_Delete_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_MPIIO_GetFileSize_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_MPIIO_GetFileSize_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_MPIIO_GetFileSize_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_MPIIO_GetFileSize_event_t stats_key_v = {};
            struct app3_MPIIO_GetFileSize_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 124;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_MPIIO_GetFileSize_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_MPIIO_GetFileSize_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_MPIIO_xfer_hints_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_MPIIO_xfer_hints_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_MPIIO_xfer_hints_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_MPIIO_xfer_hints_event_t stats_key_v = {};
            struct app3_MPIIO_xfer_hints_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 125;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_MPIIO_xfer_hints_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_MPIIO_xfer_hints_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_NodeMemoryStringToBytes_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_NodeMemoryStringToBytes_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_NodeMemoryStringToBytes_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_NodeMemoryStringToBytes_event_t stats_key_v = {};
            struct app3_NodeMemoryStringToBytes_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 126;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_NodeMemoryStringToBytes_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_NodeMemoryStringToBytes_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_OpTimerFlush_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_OpTimerFlush_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_OpTimerFlush_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_OpTimerFlush_event_t stats_key_v = {};
            struct app3_OpTimerFlush_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 127;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_OpTimerFlush_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_OpTimerFlush_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_OpTimerFree_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_OpTimerFree_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_OpTimerFree_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_OpTimerFree_event_t stats_key_v = {};
            struct app3_OpTimerFree_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 128;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_OpTimerFree_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_OpTimerFree_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_OpTimerInit_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_OpTimerInit_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_OpTimerInit_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_OpTimerInit_event_t stats_key_v = {};
            struct app3_OpTimerInit_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 129;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_OpTimerInit_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_OpTimerInit_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_OpTimerValue_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_OpTimerValue_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_OpTimerValue_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_OpTimerValue_event_t stats_key_v = {};
            struct app3_OpTimerValue_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 130;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_OpTimerValue_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_OpTimerValue_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_POSIX_Close_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_POSIX_Close_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_POSIX_Close_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_POSIX_Close_event_t stats_key_v = {};
            struct app3_POSIX_Close_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 131;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_POSIX_Close_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_POSIX_Close_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_POSIX_Create_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_POSIX_Create_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_POSIX_Create_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_POSIX_Create_event_t stats_key_v = {};
            struct app3_POSIX_Create_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 132;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_POSIX_Create_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_POSIX_Create_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_POSIX_Delete_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_POSIX_Delete_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_POSIX_Delete_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_POSIX_Delete_event_t stats_key_v = {};
            struct app3_POSIX_Delete_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 133;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_POSIX_Delete_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_POSIX_Delete_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_POSIX_Fsync_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_POSIX_Fsync_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_POSIX_Fsync_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_POSIX_Fsync_event_t stats_key_v = {};
            struct app3_POSIX_Fsync_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 134;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_POSIX_Fsync_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_POSIX_Fsync_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_POSIX_GetFileSize_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_POSIX_GetFileSize_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_POSIX_GetFileSize_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_POSIX_GetFileSize_event_t stats_key_v = {};
            struct app3_POSIX_GetFileSize_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 135;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_POSIX_GetFileSize_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_POSIX_GetFileSize_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_POSIX_Mknod_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_POSIX_Mknod_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_POSIX_Mknod_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_POSIX_Mknod_event_t stats_key_v = {};
            struct app3_POSIX_Mknod_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 136;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_POSIX_Mknod_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_POSIX_Mknod_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_POSIX_Open_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_POSIX_Open_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_POSIX_Open_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_POSIX_Open_event_t stats_key_v = {};
            struct app3_POSIX_Open_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 137;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_POSIX_Open_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_POSIX_Open_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_POSIX_Rename_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_POSIX_Rename_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_POSIX_Rename_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_POSIX_Rename_event_t stats_key_v = {};
            struct app3_POSIX_Rename_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 138;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_POSIX_Rename_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_POSIX_Rename_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_POSIX_Sync_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_POSIX_Sync_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_POSIX_Sync_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_POSIX_Sync_event_t stats_key_v = {};
            struct app3_POSIX_Sync_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 139;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_POSIX_Sync_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_POSIX_Sync_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_POSIX_check_params_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_POSIX_check_params_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_POSIX_check_params_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_POSIX_check_params_event_t stats_key_v = {};
            struct app3_POSIX_check_params_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 140;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_POSIX_check_params_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_POSIX_check_params_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_POSIX_options_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_POSIX_options_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_POSIX_options_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_POSIX_options_event_t stats_key_v = {};
            struct app3_POSIX_options_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 141;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_POSIX_options_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_POSIX_options_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_POSIX_xfer_hints_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_POSIX_xfer_hints_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_POSIX_xfer_hints_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_POSIX_xfer_hints_event_t stats_key_v = {};
            struct app3_POSIX_xfer_hints_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 142;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_POSIX_xfer_hints_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_POSIX_xfer_hints_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_ParseCommandLine_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_ParseCommandLine_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_ParseCommandLine_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_ParseCommandLine_event_t stats_key_v = {};
            struct app3_ParseCommandLine_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 143;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_ParseCommandLine_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_ParseCommandLine_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_ParseLine_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_ParseLine_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_ParseLine_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_ParseLine_event_t stats_key_v = {};
            struct app3_ParseLine_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 144;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_ParseLine_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_ParseLine_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_PrintHeader_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_PrintHeader_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_PrintHeader_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_PrintHeader_event_t stats_key_v = {};
            struct app3_PrintHeader_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 145;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_PrintHeader_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_PrintHeader_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_PrintKeyVal_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_PrintKeyVal_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_PrintKeyVal_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_PrintKeyVal_event_t stats_key_v = {};
            struct app3_PrintKeyVal_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 146;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_PrintKeyVal_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_PrintKeyVal_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_PrintLongSummaryAllTests_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_PrintLongSummaryAllTests_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_PrintLongSummaryAllTests_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_PrintLongSummaryAllTests_event_t stats_key_v = {};
            struct app3_PrintLongSummaryAllTests_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 147;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_PrintLongSummaryAllTests_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_PrintLongSummaryAllTests_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_PrintLongSummaryHeader_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_PrintLongSummaryHeader_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_PrintLongSummaryHeader_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_PrintLongSummaryHeader_event_t stats_key_v = {};
            struct app3_PrintLongSummaryHeader_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 148;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_PrintLongSummaryHeader_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_PrintLongSummaryHeader_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_PrintLongSummaryOneTest_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_PrintLongSummaryOneTest_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_PrintLongSummaryOneTest_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_PrintLongSummaryOneTest_event_t stats_key_v = {};
            struct app3_PrintLongSummaryOneTest_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 149;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_PrintLongSummaryOneTest_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_PrintLongSummaryOneTest_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_PrintReducedResult_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_PrintReducedResult_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_PrintReducedResult_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_PrintReducedResult_event_t stats_key_v = {};
            struct app3_PrintReducedResult_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 150;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_PrintReducedResult_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_PrintReducedResult_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_PrintRemoveTiming_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_PrintRemoveTiming_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_PrintRemoveTiming_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_PrintRemoveTiming_event_t stats_key_v = {};
            struct app3_PrintRemoveTiming_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 151;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_PrintRemoveTiming_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_PrintRemoveTiming_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_PrintRepeatEnd_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_PrintRepeatEnd_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_PrintRepeatEnd_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_PrintRepeatEnd_event_t stats_key_v = {};
            struct app3_PrintRepeatEnd_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 152;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_PrintRepeatEnd_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_PrintRepeatEnd_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_PrintRepeatStart_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_PrintRepeatStart_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_PrintRepeatStart_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_PrintRepeatStart_event_t stats_key_v = {};
            struct app3_PrintRepeatStart_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 153;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_PrintRepeatStart_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_PrintRepeatStart_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_PrintShortSummary_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_PrintShortSummary_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_PrintShortSummary_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_PrintShortSummary_event_t stats_key_v = {};
            struct app3_PrintShortSummary_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 154;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_PrintShortSummary_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_PrintShortSummary_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_PrintTableHeader_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_PrintTableHeader_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_PrintTableHeader_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_PrintTableHeader_event_t stats_key_v = {};
            struct app3_PrintTableHeader_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 155;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_PrintTableHeader_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_PrintTableHeader_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_PrintTestEnds_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_PrintTestEnds_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_PrintTestEnds_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_PrintTestEnds_event_t stats_key_v = {};
            struct app3_PrintTestEnds_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 156;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_PrintTestEnds_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_PrintTestEnds_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_PrintTimestamp_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_PrintTimestamp_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_PrintTimestamp_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_PrintTimestamp_event_t stats_key_v = {};
            struct app3_PrintTimestamp_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 157;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_PrintTimestamp_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_PrintTimestamp_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_QueryNodeMapping_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_QueryNodeMapping_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_QueryNodeMapping_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_QueryNodeMapping_event_t stats_key_v = {};
            struct app3_QueryNodeMapping_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 158;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_QueryNodeMapping_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_QueryNodeMapping_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_ReadConfigScript_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_ReadConfigScript_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_ReadConfigScript_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_ReadConfigScript_event_t stats_key_v = {};
            struct app3_ReadConfigScript_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 159;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_ReadConfigScript_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_ReadConfigScript_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_ReadStoneWallingIterations_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_ReadStoneWallingIterations_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_ReadStoneWallingIterations_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_ReadStoneWallingIterations_event_t stats_key_v = {};
            struct app3_ReadStoneWallingIterations_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 160;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_ReadStoneWallingIterations_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_ReadStoneWallingIterations_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_Regex_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_Regex_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_Regex_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_Regex_event_t stats_key_v = {};
            struct app3_Regex_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 161;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_Regex_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_Regex_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_SetHints_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_SetHints_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_SetHints_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_SetHints_event_t stats_key_v = {};
            struct app3_SetHints_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 162;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_SetHints_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_SetHints_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_ShowFileSystemSize_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_ShowFileSystemSize_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_ShowFileSystemSize_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_ShowFileSystemSize_event_t stats_key_v = {};
            struct app3_ShowFileSystemSize_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 163;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_ShowFileSystemSize_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_ShowFileSystemSize_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_ShowHints_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_ShowHints_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_ShowHints_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_ShowHints_event_t stats_key_v = {};
            struct app3_ShowHints_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 164;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_ShowHints_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_ShowHints_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_ShowSetup_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_ShowSetup_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_ShowSetup_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_ShowSetup_event_t stats_key_v = {};
            struct app3_ShowSetup_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 165;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_ShowSetup_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_ShowSetup_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_ShowTestEnd_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_ShowTestEnd_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_ShowTestEnd_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_ShowTestEnd_event_t stats_key_v = {};
            struct app3_ShowTestEnd_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 166;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_ShowTestEnd_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_ShowTestEnd_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_ShowTestStart_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_ShowTestStart_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_ShowTestStart_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_ShowTestStart_event_t stats_key_v = {};
            struct app3_ShowTestStart_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 167;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_ShowTestStart_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_ShowTestStart_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_StoreStoneWallingIterations_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_StoreStoneWallingIterations_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_StoreStoneWallingIterations_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_StoreStoneWallingIterations_event_t stats_key_v = {};
            struct app3_StoreStoneWallingIterations_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 168;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_StoreStoneWallingIterations_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_StoreStoneWallingIterations_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_StringToBytes_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_StringToBytes_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_StringToBytes_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_StringToBytes_event_t stats_key_v = {};
            struct app3_StringToBytes_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 169;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_StringToBytes_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_StringToBytes_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3__fini_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3__fini_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3__fini_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3__fini_event_t stats_key_v = {};
            struct app3__fini_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 170;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3__fini_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3__fini_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3__init_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3__init_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3__init_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3__init_event_t stats_key_v = {};
            struct app3__init_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 171;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3__init_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3__init_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3__start_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3__start_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3__start_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3__start_event_t stats_key_v = {};
            struct app3__start_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 172;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3__start_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3__start_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_aiori_count_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_aiori_count_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_aiori_count_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_aiori_count_event_t stats_key_v = {};
            struct app3_aiori_count_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 173;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_aiori_count_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_aiori_count_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_aiori_default_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_aiori_default_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_aiori_default_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_aiori_default_event_t stats_key_v = {};
            struct app3_aiori_default_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 174;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_aiori_default_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_aiori_default_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_aiori_get_version_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_aiori_get_version_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_aiori_get_version_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_aiori_get_version_event_t stats_key_v = {};
            struct app3_aiori_get_version_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 175;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_aiori_get_version_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_aiori_get_version_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_aiori_posix_access_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_aiori_posix_access_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_aiori_posix_access_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_aiori_posix_access_event_t stats_key_v = {};
            struct app3_aiori_posix_access_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 176;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_aiori_posix_access_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_aiori_posix_access_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_aiori_posix_mkdir_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_aiori_posix_mkdir_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_aiori_posix_mkdir_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_aiori_posix_mkdir_event_t stats_key_v = {};
            struct app3_aiori_posix_mkdir_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 177;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_aiori_posix_mkdir_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_aiori_posix_mkdir_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_aiori_posix_rmdir_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_aiori_posix_rmdir_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_aiori_posix_rmdir_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_aiori_posix_rmdir_event_t stats_key_v = {};
            struct app3_aiori_posix_rmdir_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 178;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_aiori_posix_rmdir_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_aiori_posix_rmdir_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_aiori_posix_stat_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_aiori_posix_stat_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_aiori_posix_stat_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_aiori_posix_stat_event_t stats_key_v = {};
            struct app3_aiori_posix_stat_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 179;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_aiori_posix_stat_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_aiori_posix_stat_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_aiori_posix_statfs_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_aiori_posix_statfs_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_aiori_posix_statfs_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_aiori_posix_statfs_event_t stats_key_v = {};
            struct app3_aiori_posix_statfs_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 180;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_aiori_posix_statfs_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_aiori_posix_statfs_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_aiori_select_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_aiori_select_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_aiori_select_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_aiori_select_event_t stats_key_v = {};
            struct app3_aiori_select_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 181;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_aiori_select_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_aiori_select_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_aiori_supported_apis_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_aiori_supported_apis_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_aiori_supported_apis_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_aiori_supported_apis_event_t stats_key_v = {};
            struct app3_aiori_supported_apis_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 182;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_aiori_supported_apis_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_aiori_supported_apis_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_airoi_create_all_module_options_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_airoi_create_all_module_options_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_airoi_create_all_module_options_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_airoi_create_all_module_options_event_t stats_key_v = {};
            struct app3_airoi_create_all_module_options_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 183;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_airoi_create_all_module_options_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_airoi_create_all_module_options_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_airoi_update_module_options_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_airoi_update_module_options_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_airoi_update_module_options_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_airoi_update_module_options_event_t stats_key_v = {};
            struct app3_airoi_update_module_options_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 184;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_airoi_update_module_options_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_airoi_update_module_options_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_aligned_buffer_alloc_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_aligned_buffer_alloc_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_aligned_buffer_alloc_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_aligned_buffer_alloc_event_t stats_key_v = {};
            struct app3_aligned_buffer_alloc_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 185;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_aligned_buffer_alloc_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_aligned_buffer_alloc_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_aligned_buffer_free_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_aligned_buffer_free_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_aligned_buffer_free_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_aligned_buffer_free_event_t stats_key_v = {};
            struct app3_aligned_buffer_free_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 186;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_aligned_buffer_free_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_aligned_buffer_free_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_contains_only_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_contains_only_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_contains_only_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_contains_only_event_t stats_key_v = {};
            struct app3_contains_only_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 187;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_contains_only_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_contains_only_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_createGlobalOptions_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_createGlobalOptions_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_createGlobalOptions_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_createGlobalOptions_event_t stats_key_v = {};
            struct app3_createGlobalOptions_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 188;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_createGlobalOptions_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_createGlobalOptions_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_generate_memory_pattern_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_generate_memory_pattern_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_generate_memory_pattern_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_generate_memory_pattern_event_t stats_key_v = {};
            struct app3_generate_memory_pattern_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 189;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_generate_memory_pattern_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_generate_memory_pattern_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_initCUDA_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_initCUDA_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_initCUDA_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_initCUDA_event_t stats_key_v = {};
            struct app3_initCUDA_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 190;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_initCUDA_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_initCUDA_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_init_IOR_Param_t_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_init_IOR_Param_t_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_init_IOR_Param_t_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_init_IOR_Param_t_event_t stats_key_v = {};
            struct app3_init_IOR_Param_t_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 191;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_init_IOR_Param_t_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_init_IOR_Param_t_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_init_clock_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_init_clock_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_init_clock_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_init_clock_event_t stats_key_v = {};
            struct app3_init_clock_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 192;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_init_clock_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_init_clock_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_invalidate_buffer_pattern_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_invalidate_buffer_pattern_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_invalidate_buffer_pattern_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_invalidate_buffer_pattern_event_t stats_key_v = {};
            struct app3_invalidate_buffer_pattern_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 193;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_invalidate_buffer_pattern_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_invalidate_buffer_pattern_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_ior_main_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_ior_main_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_ior_main_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_ior_main_event_t stats_key_v = {};
            struct app3_ior_main_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 194;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_ior_main_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_ior_main_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_ior_run_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_ior_run_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_ior_run_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_ior_run_event_t stats_key_v = {};
            struct app3_ior_run_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 195;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_ior_run_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_ior_run_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_main_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_main_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_main_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_main_event_t stats_key_v = {};
            struct app3_main_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 196;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_main_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_main_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_option_merge_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_option_merge_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_option_merge_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_option_merge_event_t stats_key_v = {};
            struct app3_option_merge_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 197;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_option_merge_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_option_merge_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_option_parse_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_option_parse_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_option_parse_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_option_parse_event_t stats_key_v = {};
            struct app3_option_parse_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 198;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_option_parse_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_option_parse_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_option_parse_key_value_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_option_parse_key_value_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_option_parse_key_value_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_option_parse_key_value_event_t stats_key_v = {};
            struct app3_option_parse_key_value_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 199;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_option_parse_key_value_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_option_parse_key_value_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_option_parse_str_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_option_parse_str_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_option_parse_str_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_option_parse_str_event_t stats_key_v = {};
            struct app3_option_parse_str_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 200;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_option_parse_str_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_option_parse_str_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_option_print_current_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_option_print_current_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_option_print_current_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_option_print_current_event_t stats_key_v = {};
            struct app3_option_print_current_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 201;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_option_print_current_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_option_print_current_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_option_print_help_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_option_print_help_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_option_print_help_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_option_print_help_event_t stats_key_v = {};
            struct app3_option_print_help_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 202;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_option_print_help_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_option_print_help_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_parsePacketType_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_parsePacketType_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_parsePacketType_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_parsePacketType_event_t stats_key_v = {};
            struct app3_parsePacketType_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 203;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_parsePacketType_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_parsePacketType_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_safeMalloc_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_safeMalloc_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_safeMalloc_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_safeMalloc_event_t stats_key_v = {};
            struct app3_safeMalloc_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 204;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_safeMalloc_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_safeMalloc_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_set_o_direct_flag_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_set_o_direct_flag_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_set_o_direct_flag_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_set_o_direct_flag_event_t stats_key_v = {};
            struct app3_set_o_direct_flag_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 205;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_set_o_direct_flag_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_set_o_direct_flag_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_string_to_bytes_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_string_to_bytes_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_string_to_bytes_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_string_to_bytes_event_t stats_key_v = {};
            struct app3_string_to_bytes_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 206;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_string_to_bytes_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_string_to_bytes_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_test_time_elapsed_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_test_time_elapsed_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_test_time_elapsed_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_test_time_elapsed_event_t stats_key_v = {};
            struct app3_test_time_elapsed_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 207;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_test_time_elapsed_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_test_time_elapsed_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_updateParsedOptions_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_updateParsedOptions_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_updateParsedOptions_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_updateParsedOptions_event_t stats_key_v = {};
            struct app3_updateParsedOptions_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 208;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_updateParsedOptions_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_updateParsedOptions_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_update_write_memory_pattern_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_update_write_memory_pattern_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_update_write_memory_pattern_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_update_write_memory_pattern_event_t stats_key_v = {};
            struct app3_update_write_memory_pattern_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 209;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_update_write_memory_pattern_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_update_write_memory_pattern_event_t), 0);
        
            return 0;
        }
        
        
        
            struct app3_verify_memory_pattern_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            
            
        };
        
        
        int trace_app3_verify_memory_pattern_entry(struct pt_regs *ctx ) {
            
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
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
                    
                        
            return 0;
        }

        int trace_app3_verify_memory_pattern_exit(struct pt_regs *ctx) {
            
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
                    
            
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct app3_verify_memory_pattern_event_t stats_key_v = {};
            struct app3_verify_memory_pattern_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 210;
            stats_key->ip = fn->ip;
                    
                        
                        
            struct app3_verify_memory_pattern_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
                    
                       
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            
            events.ringbuf_output(&stats_key_v, sizeof(struct app3_verify_memory_pattern_event_t), 0);
        
            return 0;
        }
        