class BCCHeader:
    def __init__(self):

        self.entry_struct = """
        """
        self.exit_struct = """
            u64 size_sum;
        """

        self.includes = """
        #include <linux/sched.h>
        #include <uapi/linux/limits.h>
        #include <uapi/linux/ptrace.h>
        """

        self.data_structures = """
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
        struct fn_key_t {
            s64 pid;
        };
        struct fn_t {
            u64 ts;
            u64 ip;
            DFENTRY_STRUCT
        };
        struct file_t {
          u64 id;
          int fd;  
        };
        struct filename_t {
            char fname[256];
        };
        """.replace(
            "DFENTRY_STRUCT", self.entry_struct
        ).replace(
            "DEXIT_STRUCT", self.exit_struct
        )
        self.events_ds = """
        BPF_HASH(pid_map, u32, u64); // map for apps to collect data
        BPF_HASH(fn_pid_map, struct fn_key_t, struct fn_t); // collect start time and ip for apps
        BPF_HASH(fn_map, struct stats_key_t, struct stats_t, 2 << 16); // emit events to python
        BPF_HASH(file_hash, u32, struct filename_t);
        BPF_HASH(latest_hash, u64, u32);
        BPF_HASH(latest_fd, u64, int);
        BPF_HASH(fd_hash, struct file_t, u32);
        BPF_HASH(pid_hash, u64, u64);
        """
        self.util = """
        static u64 get_hash(u64 id) {
            u64 first_hash = 1;
            u64* hash_value = pid_hash.lookup_or_init(&id, &first_hash);
            (*hash_value)++;
            return *hash_value;
        }
        """

    def __str__(self) -> str:
        return self.includes + self.data_structures + self.events_ds + self.util
