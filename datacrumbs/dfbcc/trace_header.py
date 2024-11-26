
from datacrumbs.dfbcc.header import BCCHeader

class BCCTraceHeader(BCCHeader):
    def __init__(self):
        super().__init__()
        self.events_ds += """
        BPF_RINGBUF_OUTPUT(events, 1 << 16); // emit events to python
        // BPF_PERF_OUTPUT(events); // emit events to python
        """

    def __str__(self) -> str:
        return self.includes + self.data_structures + self.events_ds + self.util
