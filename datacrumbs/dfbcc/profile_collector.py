
from datacrumbs.dfbcc.collector import BCCCollector
class BCCProfileCollector(BCCCollector):
    entry_fn: str
    exit_fn: str

    def __init__(self) -> None:
        super().__init__()
        self.stats_key_create = """
            struct stats_key_t stats_key_v = {};
            struct stats_key_t *stats_key = &stats_key_v;
            stats_key->trange = (fn->ts  - *start_ts) / INTERVAL_RANGE;
            stats_key->event_id = DFEVENTID;
            stats_key->id = id;
            stats_key->ip = DFEVENTID;
        """
        
        self.stats_value_create = """
            struct stats_t zero_stats = {};
            struct stats_t *stats = fn_map.lookup_or_init(stats_key, &zero_stats);
            stats->time += bpf_ktime_get_ns() - fn->ts;
            stats->freq++;
        """
        
        self.stats_submit = ""
        
        self.event_specific_struct = ""
        
        self.stats_clean = """
        """
        
        self.sys_functions = self.sys_functions.replace(
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
        
        self.functions = self.functions.replace(
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
