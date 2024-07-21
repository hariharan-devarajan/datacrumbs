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
                    BCCFunctions(
                        "openat",
                        entry_args=", int dfd, const char *filename, int flags",
                        entry_cmd="""
                        struct filename_t fname_i;
                        int len = bpf_probe_read_user_str(&fname_i.fname, sizeof(fname_i.fname), filename);
                        //fname_i.fname[len-1] = '\\0';
                        u32 filehash = get_hash(id);
                        bpf_trace_printk(\"Hash value is %d for filename \%s\",filename,filehash);
                        file_hash.update(&filehash, &fname_i);
                        latest_hash.update(&id, &filehash);
                        """,
                        exit_cmd_key="""
                        u32* hash_ptr = latest_hash.lookup(&id);
                        if (hash_ptr != 0) {
                            stats_key.file_hash = *hash_ptr; 
                        }
                        """,
                        exit_cmd_stats="""
                        if (hash_ptr != 0) {
                            int fd = PT_REGS_RC(ctx);
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = fd;
                            fd_hash.update(&file_key, hash_ptr);
                        }
                        """,
                    ),
                    BCCFunctions(
                        "read",
                        entry_args="""
                        , int fd, void *data, u64 count
                        """,
                        entry_cmd="""
                        latest_fd.update(&id,&fd);
                        """,
                        exit_cmd_stats="""
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 """,
                        exit_cmd_key="""
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u32* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key.file_hash = *hash_ptr; 
                            }
                        }
                        """,
                    ),
                    BCCFunctions(
                        "write",
                        entry_args="""
                        , int fd, const void *data, u64 count
                        """,
                        entry_cmd="""
                        latest_fd.update(&id,&fd);
                        """,
                        exit_cmd_stats="""
                                 stats->size_sum += PT_REGS_RC(ctx);
                                 """,
                        exit_cmd_key="""
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u32* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key.file_hash = *hash_ptr; 
                            }
                        }
                        """,
                    ),
                    BCCFunctions(
                        "close",
                        entry_args="""
                        , int fd
                        """,
                        entry_cmd="""
                        latest_fd.update(&id,&fd);
                        """,
                        exit_cmd_key="""
                        int* fd_ptr = latest_fd.lookup(&id);
                        if (fd_ptr != 0 ) {
                            struct file_t file_key = {};
                            file_key.id = id;
                            file_key.fd = *fd_ptr;
                            u32* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key.file_hash = *hash_ptr; 
                            }
                        }
                        """,
                    ),
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
                "io_uring",
                [BCCFunctions("io_uring", "^io_uring_.*")],
            )
        )

    def collector_fn(self, collector: BCCCollector, category_fn_map, count: int):
        bpf_text = ""
        for probe in self.probes:
            for fn in probe.functions:
                count = count + 1
                if ProbeType.SYSTEM == probe.type:
                    text = collector.sys_functions
                else:
                    text = collector.functions
                text = text.replace("DFCAT", probe.category)
                text = text.replace("DFFUNCTION", fn.name)
                text = text.replace("DFEVENTID", str(count))
                text = text.replace("DFENTRYCMD", fn.entry_cmd)
                text = text.replace("DFEXITCMDSTATS", fn.exit_cmd_stats)
                text = text.replace("DFEXITCMDKEY", fn.exit_cmd_key)
                text = text.replace("DFENTRYARGS", fn.entry_args)
                category_fn_map[count] = (probe.category, fn)
                bpf_text += text

        return (bpf_text, category_fn_map, count)

    def attach_probes(self, bpf: BPF, collector: BCCCollector) -> None:
        for probe in self.probes:
            for fn in probe.functions:
                try:
                    if ProbeType.SYSTEM == probe.type:
                        fnname = bpf.get_syscall_prefix().decode() + fn.name
                        # logging.debug(
                        #     f"attaching name {fnname} with {fn.name} for cat {probe.category}"
                        # )
                        bpf.attach_kprobe(
                            event=fnname,
                            fn_name=f"syscall__trace_entry_{fn.name}",
                        )
                        bpf.attach_kretprobe(
                            event=fnname,
                            fn_name=f"sys__trace_exit_{fn.name}",
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
                        else:
                            bpf.attach_kprobe(
                                event=fname,
                                fn_name=f"trace_{probe.category}_{fn.name}_entry",
                            )
                            bpf.attach_kretprobe(
                                event=fname,
                                fn_name=f"trace_{probe.category}_{fn.name}_exit",
                            )
                    elif ProbeType.USER == probe.type:
                        library = probe.category
                        fname = fn.name
                        is_regex = False
                        if fn.regex:
                            is_regex = True
                            fname = fn.regex
                        if probe.category in self.config.user_libraries:
                            library = self.config.user_libraries[probe.category]["link"]
                            bpf.add_module(library)

                        if is_regex:
                            bpf.attach_uprobe(
                                name=library,
                                sym_re=fname,
                                fn_name=f"trace_{probe.category}_{fn.name}_entry",
                            )
                            bpf.attach_uretprobe(
                                name=library,
                                sym_re=fname,
                                fn_name=f"trace_{probe.category}_{fn.name}_exit",
                            )
                        else:
                            bpf.attach_uprobe(
                                name=library,
                                sym=fname,
                                fn_name=f"trace_{probe.category}_{fn.name}_entry",
                            )
                            bpf.attach_uretprobe(
                                name=library,
                                sym=fname,
                                fn_name=f"trace_{probe.category}_{fn.name}_exit",
                            )
                except Exception as e:
                    logging.warn(
                        f"Unable attach probe  {probe.category} to io function {fn.name} due to {e}"
                    )
