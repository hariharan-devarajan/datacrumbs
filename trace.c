
        #include <linux/sched.h>
        #include <uapi/linux/limits.h>
        #include <uapi/linux/ptrace.h>
        
        struct fn_key_t {
            u64 ip;
            s64 pid;
        };
        struct fn_t {
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
            key.pid = pid;
            key.ip = 1;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
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
            key.pid = pid;
            key.ip = 1;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_openat_event_t stats_key_v = {};
            struct sys_openat_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 1;
            stats_key->ip = 1;
        
            
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
            key.pid = pid;
            key.ip = 2;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
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
            key.pid = pid;
            key.ip = 2;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_read_event_t stats_key_v = {};
            struct sys_read_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 2;
            stats_key->ip = 2;
        
            
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
            key.pid = pid;
            key.ip = 3;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
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
            key.pid = pid;
            key.ip = 3;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_write_event_t stats_key_v = {};
            struct sys_write_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 3;
            stats_key->ip = 3;
        
            
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
            key.pid = pid;
            key.ip = 4;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
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
            key.pid = pid;
            key.ip = 4;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_close_event_t stats_key_v = {};
            struct sys_close_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 4;
            stats_key->ip = 4;
        
            
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
            key.pid = pid;
            key.ip = 5;
            struct fn_t fn = {};
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
            key.ip = 5;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_copy_file_range_event_t stats_key_v = {};
            struct sys_copy_file_range_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 5;
            stats_key->ip = 5;
        
            
                        
            struct sys_copy_file_range_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 6;
            struct fn_t fn = {};
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
            key.ip = 6;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_execve_event_t stats_key_v = {};
            struct sys_execve_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 6;
            stats_key->ip = 6;
        
            
                        
            struct sys_execve_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 7;
            struct fn_t fn = {};
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
            key.ip = 7;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_execveat_event_t stats_key_v = {};
            struct sys_execveat_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 7;
            stats_key->ip = 7;
        
            
                        
            struct sys_execveat_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 8;
            struct fn_t fn = {};
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
            key.ip = 8;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_exit_event_t stats_key_v = {};
            struct sys_exit_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 8;
            stats_key->ip = 8;
        
            
                        
            struct sys_exit_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 9;
            struct fn_t fn = {};
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
            key.ip = 9;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_faccessat_event_t stats_key_v = {};
            struct sys_faccessat_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 9;
            stats_key->ip = 9;
        
            
                        
            struct sys_faccessat_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 10;
            struct fn_t fn = {};
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
            key.ip = 10;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_fcntl_event_t stats_key_v = {};
            struct sys_fcntl_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 10;
            stats_key->ip = 10;
        
            
                        
            struct sys_fcntl_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
                events.ringbuf_output(&stats_key_v, sizeof(struct sys_fcntl_event_t), 0);
            
            
        
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
            key.pid = pid;
            key.ip = 5;
            struct fn_t fn = {};
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
            key.ip = 5;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_copy_file_range_event_t stats_key_v = {};
            struct sys_copy_file_range_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 5;
            stats_key->ip = 5;
        
            
                        
            struct sys_copy_file_range_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 6;
            struct fn_t fn = {};
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
            key.ip = 6;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_execve_event_t stats_key_v = {};
            struct sys_execve_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 6;
            stats_key->ip = 6;
        
            
                        
            struct sys_execve_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 7;
            struct fn_t fn = {};
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
            key.ip = 7;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_execveat_event_t stats_key_v = {};
            struct sys_execveat_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 7;
            stats_key->ip = 7;
        
            
                        
            struct sys_execveat_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 8;
            struct fn_t fn = {};
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
            key.ip = 8;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_exit_event_t stats_key_v = {};
            struct sys_exit_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 8;
            stats_key->ip = 8;
        
            
                        
            struct sys_exit_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 9;
            struct fn_t fn = {};
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
            key.ip = 9;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_faccessat_event_t stats_key_v = {};
            struct sys_faccessat_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 9;
            stats_key->ip = 9;
        
            
                        
            struct sys_faccessat_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 10;
            struct fn_t fn = {};
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
            key.ip = 10;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_fcntl_event_t stats_key_v = {};
            struct sys_fcntl_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 10;
            stats_key->ip = 10;
        
            
                        
            struct sys_fcntl_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 11;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
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
            key.pid = pid;
            key.ip = 11;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_fallocate_event_t stats_key_v = {};
            struct sys_fallocate_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 11;
            stats_key->ip = 11;
        
            
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
            key.pid = pid;
            key.ip = 12;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
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
            key.pid = pid;
            key.ip = 12;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_fdatasync_event_t stats_key_v = {};
            struct sys_fdatasync_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 12;
            stats_key->ip = 12;
        
            
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
            key.pid = pid;
            key.ip = 13;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
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
            key.pid = pid;
            key.ip = 13;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_flock_event_t stats_key_v = {};
            struct sys_flock_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 13;
            stats_key->ip = 13;
        
            
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
            key.pid = pid;
            key.ip = 14;
            struct fn_t fn = {};
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
            key.ip = 14;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_fsopen_event_t stats_key_v = {};
            struct sys_fsopen_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 14;
            stats_key->ip = 14;
        
            
                        
            struct sys_fsopen_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 15;
            struct fn_t fn = {};
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
            key.ip = 15;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_fstatfs_event_t stats_key_v = {};
            struct sys_fstatfs_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 15;
            stats_key->ip = 15;
        
            
                        
            struct sys_fstatfs_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
                events.ringbuf_output(&stats_key_v, sizeof(struct sys_fstatfs_event_t), 0);
            
            
        
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
            key.pid = pid;
            key.ip = 14;
            struct fn_t fn = {};
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
            key.ip = 14;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_fsopen_event_t stats_key_v = {};
            struct sys_fsopen_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 14;
            stats_key->ip = 14;
        
            
                        
            struct sys_fsopen_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 15;
            struct fn_t fn = {};
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
            key.ip = 15;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_fstatfs_event_t stats_key_v = {};
            struct sys_fstatfs_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 15;
            stats_key->ip = 15;
        
            
                        
            struct sys_fstatfs_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 16;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
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
            key.pid = pid;
            key.ip = 16;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_fsync_event_t stats_key_v = {};
            struct sys_fsync_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 16;
            stats_key->ip = 16;
        
            
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
            key.pid = pid;
            key.ip = 17;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
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
            key.pid = pid;
            key.ip = 17;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_ftruncate_event_t stats_key_v = {};
            struct sys_ftruncate_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 17;
            stats_key->ip = 17;
        
            
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
            key.pid = pid;
            key.ip = 18;
            struct fn_t fn = {};
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
            key.ip = 18;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_io_pgetevents_event_t stats_key_v = {};
            struct sys_io_pgetevents_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 18;
            stats_key->ip = 18;
        
            
                        
            struct sys_io_pgetevents_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
                events.ringbuf_output(&stats_key_v, sizeof(struct sys_io_pgetevents_event_t), 0);
            
            
        
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
            key.pid = pid;
            key.ip = 18;
            struct fn_t fn = {};
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
            key.ip = 18;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_io_pgetevents_event_t stats_key_v = {};
            struct sys_io_pgetevents_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 18;
            stats_key->ip = 18;
        
            
                        
            struct sys_io_pgetevents_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 19;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
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
            key.pid = pid;
            key.ip = 19;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_lseek_event_t stats_key_v = {};
            struct sys_lseek_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 19;
            stats_key->ip = 19;
        
            
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
            key.pid = pid;
            key.ip = 20;
            struct fn_t fn = {};
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
            key.ip = 20;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_memfd_create_event_t stats_key_v = {};
            struct sys_memfd_create_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 20;
            stats_key->ip = 20;
        
            
                        
            struct sys_memfd_create_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 21;
            struct fn_t fn = {};
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
            key.ip = 21;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_migrate_pages_event_t stats_key_v = {};
            struct sys_migrate_pages_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 21;
            stats_key->ip = 21;
        
            
                        
            struct sys_migrate_pages_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 22;
            struct fn_t fn = {};
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
            key.ip = 22;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_mlock_event_t stats_key_v = {};
            struct sys_mlock_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 22;
            stats_key->ip = 22;
        
            
                        
            struct sys_mlock_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 23;
            struct fn_t fn = {};
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
            key.ip = 23;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_mmap_event_t stats_key_v = {};
            struct sys_mmap_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 23;
            stats_key->ip = 23;
        
            
                        
            struct sys_mmap_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 24;
            struct fn_t fn = {};
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
            key.ip = 24;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_msync_event_t stats_key_v = {};
            struct sys_msync_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 24;
            stats_key->ip = 24;
        
            
                        
            struct sys_msync_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
                events.ringbuf_output(&stats_key_v, sizeof(struct sys_msync_event_t), 0);
            
            
        
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
            key.pid = pid;
            key.ip = 20;
            struct fn_t fn = {};
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
            key.ip = 20;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_memfd_create_event_t stats_key_v = {};
            struct sys_memfd_create_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 20;
            stats_key->ip = 20;
        
            
                        
            struct sys_memfd_create_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 21;
            struct fn_t fn = {};
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
            key.ip = 21;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_migrate_pages_event_t stats_key_v = {};
            struct sys_migrate_pages_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 21;
            stats_key->ip = 21;
        
            
                        
            struct sys_migrate_pages_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 22;
            struct fn_t fn = {};
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
            key.ip = 22;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_mlock_event_t stats_key_v = {};
            struct sys_mlock_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 22;
            stats_key->ip = 22;
        
            
                        
            struct sys_mlock_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 23;
            struct fn_t fn = {};
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
            key.ip = 23;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_mmap_event_t stats_key_v = {};
            struct sys_mmap_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 23;
            stats_key->ip = 23;
        
            
                        
            struct sys_mmap_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 24;
            struct fn_t fn = {};
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
            key.ip = 24;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_msync_event_t stats_key_v = {};
            struct sys_msync_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 24;
            stats_key->ip = 24;
        
            
                        
            struct sys_msync_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 25;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
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
            key.pid = pid;
            key.ip = 25;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_pread64_event_t stats_key_v = {};
            struct sys_pread64_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 25;
            stats_key->ip = 25;
        
            
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
            key.pid = pid;
            key.ip = 26;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
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
            key.pid = pid;
            key.ip = 26;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_preadv_event_t stats_key_v = {};
            struct sys_preadv_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 26;
            stats_key->ip = 26;
        
            
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
            key.pid = pid;
            key.ip = 27;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
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
            key.pid = pid;
            key.ip = 27;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_preadv2_event_t stats_key_v = {};
            struct sys_preadv2_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 27;
            stats_key->ip = 27;
        
            
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
            key.pid = pid;
            key.ip = 28;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
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
            key.pid = pid;
            key.ip = 28;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_pwrite64_event_t stats_key_v = {};
            struct sys_pwrite64_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 28;
            stats_key->ip = 28;
        
            
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
            key.pid = pid;
            key.ip = 29;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
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
            key.pid = pid;
            key.ip = 29;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_pwritev_event_t stats_key_v = {};
            struct sys_pwritev_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 29;
            stats_key->ip = 29;
        
            
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
            key.pid = pid;
            key.ip = 30;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
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
            key.pid = pid;
            key.ip = 30;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_pwritev2_event_t stats_key_v = {};
            struct sys_pwritev2_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 30;
            stats_key->ip = 30;
        
            
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
            key.pid = pid;
            key.ip = 31;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
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
            key.pid = pid;
            key.ip = 31;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_readahead_event_t stats_key_v = {};
            struct sys_readahead_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 31;
            stats_key->ip = 31;
        
            
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
            key.pid = pid;
            key.ip = 32;
            struct fn_t fn = {};
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
            key.ip = 32;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_readlinkat_event_t stats_key_v = {};
            struct sys_readlinkat_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 32;
            stats_key->ip = 32;
        
            
                        
            struct sys_readlinkat_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
                events.ringbuf_output(&stats_key_v, sizeof(struct sys_readlinkat_event_t), 0);
            
            
        
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
            key.pid = pid;
            key.ip = 32;
            struct fn_t fn = {};
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
            key.ip = 32;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_readlinkat_event_t stats_key_v = {};
            struct sys_readlinkat_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 32;
            stats_key->ip = 32;
        
            
                        
            struct sys_readlinkat_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 33;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
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
            key.pid = pid;
            key.ip = 33;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_readv_event_t stats_key_v = {};
            struct sys_readv_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 33;
            stats_key->ip = 33;
        
            
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
            key.pid = pid;
            key.ip = 34;
            struct fn_t fn = {};
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
            key.ip = 34;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_renameat_event_t stats_key_v = {};
            struct sys_renameat_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 34;
            stats_key->ip = 34;
        
            
                        
            struct sys_renameat_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 35;
            struct fn_t fn = {};
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
            key.ip = 35;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_renameat2_event_t stats_key_v = {};
            struct sys_renameat2_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 35;
            stats_key->ip = 35;
        
            
                        
            struct sys_renameat2_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 36;
            struct fn_t fn = {};
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
            key.ip = 36;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_statfs_event_t stats_key_v = {};
            struct sys_statfs_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 36;
            stats_key->ip = 36;
        
            
                        
            struct sys_statfs_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 37;
            struct fn_t fn = {};
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
            key.ip = 37;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_statx_event_t stats_key_v = {};
            struct sys_statx_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 37;
            stats_key->ip = 37;
        
            
                        
            struct sys_statx_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 38;
            struct fn_t fn = {};
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
            key.ip = 38;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_sync_event_t stats_key_v = {};
            struct sys_sync_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 38;
            stats_key->ip = 38;
        
            
                        
            struct sys_sync_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 39;
            struct fn_t fn = {};
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
            key.ip = 39;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_sync_file_range_event_t stats_key_v = {};
            struct sys_sync_file_range_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 39;
            stats_key->ip = 39;
        
            
                        
            struct sys_sync_file_range_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 40;
            struct fn_t fn = {};
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
            key.ip = 40;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_syncfs_event_t stats_key_v = {};
            struct sys_syncfs_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 40;
            stats_key->ip = 40;
        
            
                        
            struct sys_syncfs_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
                events.ringbuf_output(&stats_key_v, sizeof(struct sys_syncfs_event_t), 0);
            
            
        
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
            key.pid = pid;
            key.ip = 34;
            struct fn_t fn = {};
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
            key.ip = 34;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_renameat_event_t stats_key_v = {};
            struct sys_renameat_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 34;
            stats_key->ip = 34;
        
            
                        
            struct sys_renameat_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 35;
            struct fn_t fn = {};
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
            key.ip = 35;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_renameat2_event_t stats_key_v = {};
            struct sys_renameat2_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 35;
            stats_key->ip = 35;
        
            
                        
            struct sys_renameat2_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 36;
            struct fn_t fn = {};
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
            key.ip = 36;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_statfs_event_t stats_key_v = {};
            struct sys_statfs_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 36;
            stats_key->ip = 36;
        
            
                        
            struct sys_statfs_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 37;
            struct fn_t fn = {};
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
            key.ip = 37;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_statx_event_t stats_key_v = {};
            struct sys_statx_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 37;
            stats_key->ip = 37;
        
            
                        
            struct sys_statx_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 38;
            struct fn_t fn = {};
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
            key.ip = 38;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_sync_event_t stats_key_v = {};
            struct sys_sync_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 38;
            stats_key->ip = 38;
        
            
                        
            struct sys_sync_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 39;
            struct fn_t fn = {};
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
            key.ip = 39;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_sync_file_range_event_t stats_key_v = {};
            struct sys_sync_file_range_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 39;
            stats_key->ip = 39;
        
            
                        
            struct sys_sync_file_range_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 40;
            struct fn_t fn = {};
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
            key.ip = 40;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_syncfs_event_t stats_key_v = {};
            struct sys_syncfs_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 40;
            stats_key->ip = 40;
        
            
                        
            struct sys_syncfs_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts);
            stats->dur = bpf_ktime_get_ns() - fn->ts;
        
            
            
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
            key.pid = pid;
            key.ip = 41;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
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
            key.pid = pid;
            key.ip = 41;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
                    
            
            struct sys_writev_event_t stats_key_v = {};
            struct sys_writev_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = 41;
            stats_key->ip = 41;
        
            
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
                                 
            
                events.ringbuf_output(&stats_key_v, sizeof(struct sys_writev_event_t), 0);
            
            
        
            return 0;
        }
        
        
        
