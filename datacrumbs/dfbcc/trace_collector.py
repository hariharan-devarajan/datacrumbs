
from datacrumbs.dfbcc.collector import BCCCollector
from datacrumbs.common.constants import *
from datacrumbs.common.enumerations import TraceType

class BCCTraceCollector(BCCCollector):
    entry_fn: str
    exit_fn: str

    def __init__(self) -> None:
        super().__init__()
        self.stats_key_create = """
            struct DFCAT_DFFUNCTION_event_t stats_key_v = {};
            struct DFCAT_DFFUNCTION_event_t *stats_key = &stats_key_v;
            stats_key->id = id;
            stats_key->event_id = DFEVENTID;
            stats_key->ip = fn->ip;
        """
        
        self.stats_value_create = """            
            struct DFCAT_DFFUNCTION_event_t* stats = stats_key;
            stats->ts = (fn->ts  - *start_ts) / 1000;
            stats->dur = bpf_ktime_get_ns() - fn->ts / 1000;
            if (stats->dur == 0) stats->dur = 1;
        """
        
        if self.config.trace_type == TraceType.PERF:
            self.stats_submit = """
                events.perf_submit(ctx, &stats_key_v, sizeof(struct DFCAT_DFFUNCTION_event_t)); 
            """
        elif self.config.trace_type == TraceType.RING_BUFFER:
            self.stats_submit = """
                events.ringbuf_output(&stats_key_v, sizeof(struct DFCAT_DFFUNCTION_event_t), 0);
            """
        
        self.event_specific_struct = """
            struct DFCAT_DFFUNCTION_event_t {                                                       
            u64 id;
            u64 event_id;
            u64 ip;
            u64 ts;                                                                   
            u64 dur;
            DFENTRY_STRUCT
            DFEXIT_STRUCT
        };
        """
        self.stats_clean = """
        """
        
        self.sys_custom_functions = self.sys_custom_functions.replace(
            "DFCAPTUREEVENTKEY", self.stats_key_create
        ).replace(
            "DFCAPTUREEVENTVALUE", self.stats_value_create
        ).replace(
            "DFSUBMITEVENT", self.stats_submit
        ).replace(
            "DFEVENTSTRUCT", self.event_specific_struct
        ).replace(
            "DFEXITSTATSCLEAN", self.stats_clean
        )
        
        self.custom_functions = self.custom_functions.replace(
            "DFCAPTUREEVENTKEY", self.stats_key_create
        ).replace(
            "DFCAPTUREEVENTVALUE", self.stats_value_create
        ).replace(
            "DFSUBMITEVENT", self.stats_submit
        ).replace(
            "DFEVENTSTRUCT", self.event_specific_struct
        ).replace(
            "DFEXITSTATSCLEAN", self.stats_clean
        )
        
        self.sys_gen_functions = self.sys_gen_functions.replace(
            "DFCAPTUREEVENTKEY", self.stats_key_create
        ).replace(
            "DFCAPTUREEVENTVALUE", self.stats_value_create
        ).replace(
            "DFSUBMITEVENT", self.stats_submit
        ).replace(
            "DFEXITSTATSCLEAN", self.stats_clean
        ).replace(
            "DFEVENTID", f"{SYS_GEN_FUNC}"
        ).replace(
            "DFCAT_DFFUNCTION", "generic"
        )
        
        self.gen_functions = self.gen_functions.replace(
            "DFCAPTUREEVENTKEY", self.stats_key_create
        ).replace(
            "DFCAPTUREEVENTVALUE", self.stats_value_create
        ).replace(
            "DFSUBMITEVENT", self.stats_submit
        ).replace(
            "DFEXITSTATSCLEAN", self.stats_clean
        ).replace(
            "DFEVENTID", f"{KER_GEN_FUNC}"
        ).replace(
            "DFCAT_DFFUNCTION", "generic"
        )
        
        self.user_gen_functions = self.user_gen_functions.replace(
            "DFCAPTUREEVENTKEY", self.stats_key_create
        ).replace(
            "DFCAPTUREEVENTVALUE", self.stats_value_create
        ).replace(
            "DFSUBMITEVENT", self.stats_submit
        ).replace(
            "DFEXITSTATSCLEAN", self.stats_clean
        ).replace(
            "DFEVENTID", f"{USR_GEN_FUNC}"
        ).replace(
            "DFCAT_DFFUNCTION", "generic"
        )
