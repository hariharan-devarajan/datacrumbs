
class BCCHeader:
    def __init__(self):
        self.includes = """
        #include <linux/sched.h>
        #include <uapi/linux/limits.h>
        #include <uapi/linux/ptrace.h>
        """

        self.data_structures = """
        struct stats_key_t {
            u64 trange;
            u64 id;
            u64 ip;
        };
        struct stats_t {
            u64 time;
            s64 count;
        };
        struct fn_key_t {
            s64 pid;
        };
        struct fn_t {
            u64 ip;
            u64 ts;
        };
        """

        self.events_ds = """
        BPF_HASH(pid_map, u32, u64); // map for apps to collect data
        BPF_HASH(fn_pid_map, struct fn_key_t, struct fn_t); // collect start time and ip for apps
        BPF_HASH(fn_map, struct stats_key_t, struct stats_t, 2 << 16); // emit events to python
        """
    def __str__(self) -> str:
        return self.includes + self.data_structures + self.events_ds