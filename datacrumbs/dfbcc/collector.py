from abc import ABC, abstractmethod
class BCCCollector(ABC):
    entry_fn: str
    exit_fn: str

    def __init__(self) -> None:
        self.filter_pid = """
            u64 id = bpf_get_current_pid_tgid();
            u32 pid = id;
            u64* start_ts = pid_map.lookup(&pid);
            if (start_ts == 0 || pid == 0)                                      
                return 0;
        """
        self.capture_entry_fn = """
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t fn = {};
            fn.ts = bpf_ktime_get_ns();
            fn.ip = PT_REGS_IP(ctx);
            // bpf_trace_printk("Tracing IP \%d",fn.ip);
            fn_pid_map.update(&key, &fn);
        """
        self.lookup_fn = """
            struct fn_key_t key = {};
            key.id = id;
            struct fn_t *fn = fn_pid_map.lookup(&key);
            if (fn == 0) return 0; // missed entry
        """
        
        
        self.sys_custom_functions = """
        DFEVENTSTRUCT
        int syscall__trace_entry_DFFUNCTION(struct pt_regs *ctx DFENTRYARGS) {
            DFFILTERPID
            DFFNENTRY
            DFENTRYCMD   
            return 0;
        }

        int sys__trace_exit_DFFUNCTION(struct pt_regs *ctx) {
            DFFILTERPID
            DFFNLOOKUP            
            DFCAPTUREEVENTKEY
            DFEXITCMDKEY
            DFCAPTUREEVENTVALUE
            DFEXITCMDSTATS
            // bpf_trace_printk("Submitting CUSTOM SYS IP \%d",fn->ip); 
            DFSUBMITEVENT
            DFEXITSTATSCLEAN
            return 0;
        }
        """.replace(
            "DFFILTERPID", self.filter_pid
        ).replace(
            "DFFNENTRY", self.capture_entry_fn
        ).replace(
            "DFFNLOOKUP", self.lookup_fn
        )
        
        self.custom_functions = """
        
        DFEVENTSTRUCT
        
        int trace_DFCAT_DFFUNCTION_entry(struct pt_regs *ctx DFENTRYARGS) {
            DFFILTERPID            
            DFFNENTRY            
            DFENTRYCMD            
            return 0;
        }

        int trace_DFCAT_DFFUNCTION_exit(struct pt_regs *ctx) {
            DFFILTERPID            
            DFFNLOOKUP            
            DFCAPTUREEVENTKEY            
            DFEXITCMDKEY            
            DFCAPTUREEVENTVALUE            
            DFEXITCMDSTATS           
            // bpf_trace_printk("Submitting CUSTOM TRACE IP \%d",fn->ip); 
            DFSUBMITEVENT
            return 0;
        }
        """.replace(
            "DFFILTERPID", self.filter_pid
        ).replace(
            "DFFNENTRY", self.capture_entry_fn
        ).replace(
            "DFFNLOOKUP", self.lookup_fn
        )
        self.sys_gen_functions = """
        int syscall__trace_entry_generic(struct pt_regs *ctx) {
            DFFILTERPID
            DFFNENTRY   
            return 0;
        }

        int sys__trace_exit_generic(struct pt_regs *ctx) {
            DFFILTERPID
            DFFNLOOKUP            
            DFCAPTUREEVENTKEY
            DFCAPTUREEVENTVALUE
            // bpf_trace_printk("Submitting GEN SYS IP \%d",fn->ip);
            DFSUBMITEVENT
            DFEXITSTATSCLEAN
            return 0;
        }
        """.replace(
            "DFFILTERPID", self.filter_pid
        ).replace(
            "DFFNENTRY", self.capture_entry_fn
        ).replace(
            "DFFNLOOKUP", self.lookup_fn
        )
        
        self.gen_functions = """
        struct generic_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
        };         
        int trace_generic_entry(struct pt_regs *ctx) {
            DFFILTERPID            
            DFFNENTRY            
            return 0;
        }

        int trace_generic_exit(struct pt_regs *ctx) {
            DFFILTERPID            
            DFFNLOOKUP            
            DFCAPTUREEVENTKEY            
            DFCAPTUREEVENTVALUE      
            // bpf_trace_printk("Submitting GEN TRACE IP \%d",fn->ip);      
            DFSUBMITEVENT
            return 0;
        }
        """.replace(
            "DFFILTERPID", self.filter_pid
        ).replace(
            "DFFNENTRY", self.capture_entry_fn
        ).replace(
            "DFFNLOOKUP", self.lookup_fn
        )

    def get_generic_functions(self):
        bpf_text = ""
        bpf_text += self.gen_functions
        bpf_text += self.sys_gen_functions
        return bpf_text