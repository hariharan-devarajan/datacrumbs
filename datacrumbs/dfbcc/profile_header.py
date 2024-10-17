
from datacrumbs.dfbcc.header import BCCHeader

class BCCProfileHeader(BCCHeader):
    def __init__(self):
        super().__init__()
        self.entry_struct = """
        """
        self.exit_struct = """
            u64 size_sum;
        """

        self.data_structures += """
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
            DFENTRY_STRUCT
            DEXIT_STRUCT
        };
        """.replace(
            "DFENTRY_STRUCT", self.entry_struct
        ).replace(
            "DEXIT_STRUCT", self.exit_struct
        )
        self.events_ds += """
        BPF_HASH(fn_map, struct stats_key_t, struct stats_t, 2 << 16); // emit events to python
        """

    def __str__(self) -> str:
        return self.includes + self.data_structures + self.events_ds + self.util
