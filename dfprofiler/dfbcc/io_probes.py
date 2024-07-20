from typing import *
import logging
from bcc import BPF
from dfprofiler.dfbcc.collector import BCCCollector
from dfprofiler.dfbcc.probes import BCCFunctions, BCCProbes
from dfprofiler.common.enumerations import ProbeType
from dfprofiler.configs.configuration_manager import ConfigurationManager


class IOProbes:
    config: ConfigurationManager
    probes: List[BCCProbes]

    def __init__(self) -> None:
        self.config = ConfigurationManager.get_instance()
        self.probes = []
        self.probes.append(
            BCCProbes(
                ProbeType.SYSTEM,
                "sys",
                [
                    BCCFunctions("openat"),
                    BCCFunctions("read"),
                    BCCFunctions("write"),
                    BCCFunctions("close"),
                    BCCFunctions("copy_file_range"),
                    BCCFunctions("execve"),
                    BCCFunctions("execveat"),
                    BCCFunctions("exit"),
                    BCCFunctions("faccessat"),
                    BCCFunctions("fcntl"),
                    BCCFunctions("fallocate"),
                    BCCFunctions("fdatasync"),
                    BCCFunctions("flock"),
                    BCCFunctions("fsopen"),
                    BCCFunctions("fstatfs"),
                    BCCFunctions("fsync"),
                    BCCFunctions("ftruncate"),
                    BCCFunctions("io_pgetevents"),
                    BCCFunctions("lseek"),
                    BCCFunctions("memfd_create"),
                    BCCFunctions("migrate_pages"),
                    BCCFunctions("mlock"),
                    BCCFunctions("mmap"),
                    BCCFunctions("msync"),
                    BCCFunctions("pread64"),
                    BCCFunctions("preadv"),
                    BCCFunctions("preadv2"),
                    BCCFunctions("pwrite64"),
                    BCCFunctions("pwritev"),
                    BCCFunctions("pwritev2"),
                    BCCFunctions("readahead"),
                    BCCFunctions("readlinkat"),
                    BCCFunctions("readv"),
                    BCCFunctions("renameat"),
                    BCCFunctions("renameat2"),
                    BCCFunctions("statfs"),
                    BCCFunctions("statx"),
                    BCCFunctions("sync"),
                    BCCFunctions("sync_file_range"),
                    BCCFunctions("syncfs"),
                    BCCFunctions("writev"),
                ],
            )
        )
        self.probes.append(
            BCCProbes(
                ProbeType.KERNEL,
                "os_cache",
                [
                    BCCFunctions("add_to_page_cache_lru"),
                    BCCFunctions("mark_page_accessed"),
                    BCCFunctions("account_page_dirtied"),
                    BCCFunctions("mark_buffer_dirty"),
                    BCCFunctions("do_page_cache_ra"),
                    BCCFunctions("__page_cache_alloc"),
                ],
            )
        )
        self.probes.append(
            BCCProbes(
                ProbeType.KERNEL,
                "ext4",
                [
                    BCCFunctions("ext4_file_write_iter"),
                    BCCFunctions("ext4_file_open"),
                    BCCFunctions("ext4_sync_file"),
                    BCCFunctions("ext4_alloc_da_blocks"),
                    BCCFunctions("ext4_da_release_space"),
                    BCCFunctions("ext4_da_reserve_space"),
                    BCCFunctions("ext4_da_write_begin"),
                    BCCFunctions("ext4_da_write_end"),
                    BCCFunctions("ext4_discard_preallocations"),
                    BCCFunctions("ext4_fallocate"),
                    BCCFunctions("ext4_free_blocks"),
                    BCCFunctions("ext4_readpage"),
                    BCCFunctions("ext4_remove_blocks"),
                    BCCFunctions("ext4_sync_fs"),
                    BCCFunctions("ext4_truncate"),
                    BCCFunctions("ext4_write_begin"),
                    BCCFunctions("ext4_write_end"),
                    BCCFunctions("ext4_writepage"),
                    BCCFunctions("ext4_writepages"),
                    BCCFunctions("ext4_zero_range"),
                ],
            )
        )
        self.probes.append(
            BCCProbes(
                ProbeType.KERNEL,
                "vfs",
                [BCCFunctions("vfs", "^vfs_.*"), BCCFunctions("rw_verify_area")],
            )
        )
        self.probes.append(
            BCCProbes(
                ProbeType.USER,
                "c",
                [
                    BCCFunctions("open"),
                    BCCFunctions("open64"),
                    BCCFunctions("creat"),
                    BCCFunctions("creat64"),
                    BCCFunctions("close_range"),
                    BCCFunctions("closefrom"),
                    BCCFunctions("close"),
                    BCCFunctions("read"),
                    BCCFunctions("pread"),
                    BCCFunctions("pread64"),
                    BCCFunctions("write"),
                    BCCFunctions("pwrite"),
                    BCCFunctions("pwrite64"),
                    BCCFunctions("lseek"),
                    BCCFunctions("lseek64"),
                    BCCFunctions("fdopen"),
                    BCCFunctions("fileno"),
                    BCCFunctions("fileno_unlocked"),
                    BCCFunctions("mmap"),
                    BCCFunctions("mmap64"),
                    BCCFunctions("munmap"),
                    BCCFunctions("msync"),
                    BCCFunctions("mremap"),
                    BCCFunctions("madvise"),
                    BCCFunctions("shm_open"),
                    BCCFunctions("shm_unlink"),
                    BCCFunctions("memfd_create"),
                    BCCFunctions("fsync"),
                    BCCFunctions("fdatasync"),
                    BCCFunctions("fcntl"),
                    BCCFunctions("malloc"),
                    BCCFunctions("calloc"),
                    BCCFunctions("realloc"),
                    BCCFunctions("posix_memalign"),
                    BCCFunctions("valloc"),
                    BCCFunctions("memalign"),
                    BCCFunctions("pvalloc"),
                    BCCFunctions("aligned_alloc"),
                    BCCFunctions("free"),
                ],
            )
        )
        self.probes.append(
            BCCProbes(
                ProbeType.KERNEL,
                "block",
                [BCCFunctions("block", "^block_.*")],
            )
        )
        self.probes.append(
            BCCProbes(
                ProbeType.KERNEL,
                "huge_memory",
                [BCCFunctions("huge_memory", "^nm_.*")],
            )
        )
        self.probes.append(
            BCCProbes(
                ProbeType.KERNEL,
                "io_uring",
                [BCCFunctions("io_uring", "^io_uring_.*")],
            )
        )
        self.probes.append(
            BCCProbes(
                ProbeType.KERNEL,
                "iocost",
                [BCCFunctions("iocost", "^iocost_.*")],
            )
        )
        self.probes.append(
            BCCProbes(
                ProbeType.KERNEL,
                "iomap",
                [BCCFunctions("iomap", "^iomap_.*")],
            )
        )
        self.probes.append(
            BCCProbes(
                ProbeType.KERNEL,
                "iommu",
                [
                    BCCFunctions("add_device_to_group"),
                    BCCFunctions("attach_device_to_domain"),
                    BCCFunctions("io_page_fault"),
                    BCCFunctions("map"),
                    BCCFunctions("remove_device_from_group"),
                    BCCFunctions("unmap"),
                ],
            )
        )
        self.probes.append(
            BCCProbes(
                ProbeType.KERNEL,
                "kmem",
                [BCCFunctions("kmem", "^km.*"),
                 BCCFunctions("kfree"),
                 BCCFunctions("mm", "^mm.*"),],
            )
        )

    def collector_fn(self, collector: BCCCollector, category_fn_map, count: int):
        bpf_text = ""
        for probe in self.probes:
            for fn in probe.functions:
                count = count + 1
                text = collector.get_wrapper_functions()
                text = text.replace("DFCAT", probe.category)
                text = text.replace("DFFUNCTION", fn.name)
                text = text.replace("DFEVENTID", str(count))
                category_fn_map[count] = (probe.category, fn)
                bpf_text += text

        return (bpf_text, category_fn_map, count)

    def attach_probes(self, bpf: BPF, collector: BCCCollector) -> None:
        for probe in self.probes:
            for fn in probe.functions:
                try:
                    if ProbeType.SYSTEM == probe.type:
                        fnname = bpf.get_syscall_prefix().decode() + fn.name
                        bpf.attach_kprobe(
                            event_re=fnname,
                            fn_name=f"trace_{probe.category}_{fn.name}_entry",
                        )
                        bpf.attach_kretprobe(
                            event_re=fnname,
                            fn_name=f"trace_{probe.category}_{fn.name}_exit",
                        )
                    elif ProbeType.KERNEL == probe.type:
                        fname = fn.name
                        if fn.regex:
                            fname = fn.regex
                        bpf.attach_kprobe(
                            event_re=fname,
                            fn_name=f"trace_{probe.category}_{fn.name}_entry",
                        )
                        bpf.attach_kretprobe(
                            event_re=fname,
                            fn_name=f"trace_{probe.category}_{fn.name}_exit",
                        )
                    elif ProbeType.USER == probe.type:
                        library = probe.category
                        if probe.category in self.config.user_libraries:
                            library = self.config.user_libraries[probe.category]
                            bpf.add_module(library)
                        bpf.attach_uprobe(
                            name=library,
                            sym=fn.name,
                            fn_name=f"trace_{probe.category}_{fn.name}_entry",
                        )
                        bpf.attach_uretprobe(
                            name=library,
                            sym=fn.name,
                            fn_name=f"trace_{probe.category}_{fn.name}_exit",
                        )
                except Exception as e:
                    logging.warn(
                        f"Unable attach probe  {probe.category} to io function {fn.name} due to {e}"
                    )
