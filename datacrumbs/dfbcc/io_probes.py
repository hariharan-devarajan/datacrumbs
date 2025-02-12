from typing import *
import re
from tqdm import tqdm
import json
from bcc import BPF
from datacrumbs.dfbcc.collector import BCCCollector
from datacrumbs.dfbcc.probes import BCCFunctions, BCCProbes
from datacrumbs.common.enumerations import ProbeType
from datacrumbs.configs.configuration_manager import ConfigurationManager


class IOProbes:
    config: ConfigurationManager
    probes: List[BCCProbes]
    regex_functions: Set[str]

    def __init__(self) -> None:
        self.config = ConfigurationManager.get_instance()
        self.regex_functions = set()
        self.probes = []
        self.probes.append(
            BCCProbes(
                ProbeType.SYSTEM,
                "sys",
                list(filter(None, [
                    self.get_bcc_function(
                        "openat",
                        entry_struct=[("uint64", "file_hash")],
                        entry_args=", int dfd, const char *filename, int flags",
                        entry_cmd="""
                        struct filename_t fname_i;
                        u64 filename_len = sizeof(fname_i.fname);
                        int len = bpf_probe_read_user_str(&fname_i.fname, filename_len, filename);
                        //fname_i.fname[len-1] = '\\0';
                        u64 filehash = get_hash(fname_i.fname, filename_len);
                        bpf_trace_printk(\"Hash value is %d for filename \%s\",filehash,filename);
                        file_hash.update(&filehash, &fname_i);
                        latest_hash.update(&key, &filehash);
                        """,
                        exit_cmd_key="""
                        u64* hash_ptr = latest_hash.lookup(&key);
                        if (hash_ptr != 0) {
                            stats_key->file_hash = *hash_ptr; 
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
                        is_custom = True,
                    ),
                    self.get_bcc_function(
                        "read",                        
                        entry_struct=[("uint64", "file_hash")],                        
                        exit_struct=[("uint64", "size_sum")],
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
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        """,
                        is_custom = True,
                    ),
                    self.get_bcc_function(
                        "write",                        
                        entry_struct=[("uint64", "file_hash")],                        
                        exit_struct=[("uint64", "size_sum")],
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
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        """,
                        is_custom = True,
                    ),
                    self.get_bcc_function(
                        "close",
                        entry_struct=[("uint64", "file_hash")],
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
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        """,
                        is_custom = True,
                    ),
                    self.get_bcc_function("copy_file_range"),
                    self.get_bcc_function("execve"),
                    self.get_bcc_function("execveat"),
                    self.get_bcc_function("exit"),
                    self.get_bcc_function(
                        "faccessat"
                    ),
                    self.get_bcc_function("fcntl"),
                    self.get_bcc_function(
                        "fallocate",
                        entry_struct=[("uint64", "file_hash")],
                        entry_args="""
                        , int fd, int mode, int offset, int len
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
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        """,
                        is_custom = True,
                    ),
                    self.get_bcc_function(
                        "fdatasync",
                        entry_struct=[("uint64", "file_hash")],
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
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        """,
                        is_custom = True,
                    ),
                    self.get_bcc_function(
                        "flock",
                        entry_struct=[("uint64", "file_hash")],
                        entry_args="""
                        , int fd, int cmd
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
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        """,
                        is_custom = True,
                    ),
                    self.get_bcc_function("fsopen"),
                    self.get_bcc_function("fstatfs"),
                    self.get_bcc_function(
                        "fsync",
                        entry_struct=[("uint64", "file_hash")],
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
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        """,
                        is_custom = True,
                    ),
                    self.get_bcc_function(
                        "ftruncate",
                        entry_struct=[("uint64", "file_hash")],
                        entry_args="""
                        , int fd, int length
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
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        """,
                        is_custom = True,
                    ),
                    self.get_bcc_function("io_pgetevents"),
                    self.get_bcc_function(
                        "lseek",
                        entry_struct=[("uint64", "file_hash")],
                        entry_args="""
                        , int fd, int offset, int whence
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
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        """,
                        is_custom = True,
                    ),
                    self.get_bcc_function("memfd_create"),
                    self.get_bcc_function("migrate_pages"),
                    self.get_bcc_function("mlock"),
                    self.get_bcc_function("mmap"),
                    self.get_bcc_function("msync"),
                    self.get_bcc_function(
                        "pread64",                        
                        entry_struct=[("uint64", "file_hash")],                        
                        exit_struct=[("uint64", "size_sum")],
                        entry_args="""
                        , int fd, void *buf, u64 count, u64 pos
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
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        """,
                        is_custom = True,
                    ),
                    self.get_bcc_function(
                        "preadv",                        
                        entry_struct=[("uint64", "file_hash")],                        
                        exit_struct=[("uint64", "size_sum")],
                        entry_args="""
                        , int fd, u64 buf, u64 vlen, u64 pos_l, u64 pos_h
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
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        """,
                        is_custom = True,
                    ),
                    self.get_bcc_function(
                        "preadv2",                        
                        entry_struct=[("uint64", "file_hash")],                        
                        exit_struct=[("uint64", "size_sum")],
                        entry_args="""
                        , int fd, u64 buf, u64 vlen, u64 pos_l, u64 pos_h, u64 flags
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
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        """,
                        is_custom = True,
                    ),
                    self.get_bcc_function(
                        "pwrite64",                        
                        entry_struct=[("uint64", "file_hash")],                        
                        exit_struct=[("uint64", "size_sum")],
                        entry_args="""
                        , int fd, const void *data, u64 count, u64 pos
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
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        """,
                        is_custom = True,
                    ),
                    self.get_bcc_function(
                        "pwritev",                        
                        entry_struct=[("uint64", "file_hash")],                        
                        exit_struct=[("uint64", "size_sum")],
                        entry_args="""
                        , int fd, u64 buf, u64 vlen, u64 pos_l, u64 pos_h
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
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        """,
                        is_custom = True,
                    ),
                    self.get_bcc_function(
                        "pwritev2",                        
                        entry_struct=[("uint64", "file_hash")],                        
                        exit_struct=[("uint64", "size_sum")],
                        entry_args="""
                        , int fd, u64 buf, u64 vlen, u64 pos_l, u64 pos_h, u64 flags
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
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        """,
                        is_custom = True,
                    ),
                    self.get_bcc_function(
                        "readahead",                        
                        entry_struct=[("uint64", "file_hash")],                        
                        exit_struct=[("uint64", "size_sum")],
                        entry_args="""
                        , int fd, u64 offset, u64 count
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
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        """,
                        is_custom = True,
                    ),
                    self.get_bcc_function(
                        "readlinkat"
                    ),
                    self.get_bcc_function(
                        "readv",                        
                        entry_struct=[("uint64", "file_hash")],                        
                        exit_struct=[("uint64", "size_sum")],
                        entry_args="""
                        , int fd, u64 vec, u64 vlen
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
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        """,
                        is_custom = True,
                    ),
                    self.get_bcc_function(
                        "renameat"
                    ),
                    self.get_bcc_function(
                        "renameat2"
                    ),
                    self.get_bcc_function("statfs"),
                    self.get_bcc_function("statx"),
                    self.get_bcc_function("sync"),
                    self.get_bcc_function("sync_file_range"),
                    self.get_bcc_function("syncfs"),
                    self.get_bcc_function(
                        "writev",                        
                        entry_struct=[("uint64", "file_hash")],                        
                        exit_struct=[("uint64", "size_sum")],
                        entry_args="""
                        , int fd, u64 vec, u64 vlen
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
                            u64* hash_ptr = fd_hash.lookup(&file_key);
                            if (hash_ptr != 0) {
                                stats_key->file_hash = *hash_ptr; 
                            }
                        }
                        """,
                        is_custom = True,
                    ),
                ])),
            )
        )
        self.probes.append(
            BCCProbes(
                ProbeType.KERNEL,
                "os_cache",
                list(filter(None, [
                    self.get_bcc_function("add_to_page_cache_lru"),
                    self.get_bcc_function("mark_page_accessed"),
                    self.get_bcc_function("account_page_dirtied"),
                    self.get_bcc_function("mark_buffer_dirty"),
                    self.get_bcc_function("do_page_cache_ra"),
                    self.get_bcc_function("page_cache_pipe_buf_release"),
                    self.get_bcc_function("__page_cache_alloc"),
                    self.get_bcc_function("__do_page_cache_readahead"),
                ])),
            )
        )
        # # https://fossd.anu.edu.au/linux/v2.6.18-rc4/source/fs/read_write.c#L247
        self.probes.append(
            BCCProbes(
                ProbeType.KERNEL,
                "vfs",
                list(filter(None, [
                 self.get_bcc_function("vfs_read"),
                 self.get_bcc_function("vfs_write"),
                 self.get_bcc_function("vfs_readv"),
                 self.get_bcc_function("vfs_writev"),
                 self.get_bcc_function("do_sendfile"),
                 self.get_bcc_function("rw_verify_area"),
                 self.get_bcc_function("wait_on_page_bit"),
                 self.get_bcc_function("find_get_pages_contig"),
                 self.get_bcc_function("grab_cache_page_nowait"),
                 self.get_bcc_function("read_cache_page"),
                ])),
            )
        )
        self.probes.append(
            BCCProbes(
                ProbeType.USER,
                "c",
                list(filter(None, [
                    self.get_bcc_function("fopen"),
                    self.get_bcc_function("fopen64"),
                    self.get_bcc_function("fclose"),
                    self.get_bcc_function("fread"),
                    self.get_bcc_function("fwrite"),
                    self.get_bcc_function("ftell"),
                    self.get_bcc_function("fseek"),
                    self.get_bcc_function("open"),
                    self.get_bcc_function("open64"),
                    self.get_bcc_function("creat"),
                    self.get_bcc_function("creat64"),
                    self.get_bcc_function("close_range"),
                    self.get_bcc_function("closefrom"),
                    self.get_bcc_function("close"),
                    self.get_bcc_function("read"),
                    self.get_bcc_function("pread"),
                    self.get_bcc_function("pread64"),
                    self.get_bcc_function("write"),
                    self.get_bcc_function("pwrite"),
                    self.get_bcc_function("pwrite64"),
                    self.get_bcc_function("lseek"),
                    self.get_bcc_function("lseek64"),
                    self.get_bcc_function("fdopen"),
                    self.get_bcc_function("fileno"),
                    self.get_bcc_function("fileno_unlocked"),
                    self.get_bcc_function("mmap"),
                    self.get_bcc_function("mmap64"),
                    self.get_bcc_function("munmap"),
                    self.get_bcc_function("msync"),
                    self.get_bcc_function("mremap"),
                    self.get_bcc_function("madvise"),
                    self.get_bcc_function("shm_open"),
                    self.get_bcc_function("shm_unlink"),
                    self.get_bcc_function("memfd_create"),
                    self.get_bcc_function("fsync"),
                    self.get_bcc_function("fdatasync"),
                    self.get_bcc_function("fcntl"),
                    self.get_bcc_function("malloc"),
                    self.get_bcc_function("calloc"),
                    self.get_bcc_function("realloc"),
                    self.get_bcc_function("posix_memalign"),
                    self.get_bcc_function("valloc"),
                    self.get_bcc_function("memalign"),
                    self.get_bcc_function("pvalloc"),
                    self.get_bcc_function("aligned_alloc"),
                    self.get_bcc_function("free"),
                ])),
            )
        )
        
        # with open(self.config.function_file) as json_file:
        #     kernel_functions = json.load(json_file)
        #     for cat, functions in kernel_functions.items():
        #         fn_list = []
        #         for fn in functions:
        #             self.config.tool_logger.debug(f"Added {cat}, {fn} I/O probe")
        #             fn_list.append(self.get_bcc_function(fn))
        #         self.probes.append(BCCProbes(ProbeType.KERNEL, cat, fn_list))
        
        
        # self.probes.extend(self.get_bcc_functions(b".*page.*"))
        # self.probes.extend(self.get_bcc_functions(b".*aio.*"))
        # self.probes.extend(self.get_bcc_functions(b".*vfs.*"))
        # self.probes.extend(self.get_bcc_functions(b".*file.*"))
        # self.probes.extend(self.get_bcc_functions(b".*bio.*"))
        self.probes.extend(self.get_bcc_functions(b".*ext4.*"))
        # self.probes.extend(self.get_bcc_functions(b".*block.*"))
        
        # self.probes.extend(self.get_bcc_functions(b".*llseek.*"))
        # self.probes.extend(self.get_bcc_functions(b".*io_uring.*"))
        # self.probes.extend(self.get_bcc_functions(b".*lru.*"))
        # self.probes.extend(self.get_bcc_functions(b".*swap.*"))
        # self.probes.extend(self.get_bcc_functions(b".*buffer.*"))
        # self.probes.extend(self.get_bcc_functions(b".*nr.*"))
        # self.probes.extend(self.get_bcc_functions(b".*map.*"))
        self.config.tool_logger.info(f"Added {len(self.regex_functions)} I/O probes")
        
        

    def collector_fn(self, collector: BCCCollector, category_fn_map, count: int):
        bpf_text = ""
        for probe in self.probes:
            for fn in probe.functions:
                if fn.is_custom:
                    count = count + 1
                    if ProbeType.SYSTEM == probe.type:
                        text = collector.sys_custom_functions
                    else:
                        text = collector.custom_functions
                    text = text.replace("DFCAT", probe.category)
                    text = text.replace("DFFUNCTION", fn.name)
                    text = text.replace("DFEVENTID", str(count))
                    text = text.replace("DFENTRYCMD", fn.entry_cmd)
                    text = text.replace("DFEXITCMDSTATS", fn.exit_cmd_stats)
                    text = text.replace("DFEXITCMDKEY", fn.exit_cmd_key)
                    text = text.replace("DFENTRYARGS", fn.entry_args)
                    text = text.replace("DFENTRY_STRUCT", fn.entry_struct_str)
                    text = text.replace("DFEXIT_STRUCT", fn.exit_struct_str)
                    bpf_text += text
                    category_fn_map[count] = (probe.category, fn)

        return (bpf_text, category_fn_map, count)
    def is_function_valid(self, function_name):
        return  "." not in function_name and "$" not in function_name

    def get_bcc_functions(self, regex):
        matches = BPF.get_kprobe_functions(regex)
        probes = []
        bcc_list = {}
        for line in tqdm(matches, desc=f"Matching for {regex}"):
            if line.decode() not in self.regex_functions and self.is_function_valid(line.decode()):
                self.config.tool_logger.debug(f"Adding {line.decode()} to probe")
                self.regex_functions.add(line.decode())
                value = BPF.ksym(BPF.ksymname(line), show_module=True).decode()
                value = list(filter(None, re.split('\]|\[| ', value)))
                function_name = value[0]
                module = value[1]
                if self.is_function_valid(function_name):
                    if module not in bcc_list:
                        bcc_list[module] = []
                    bcc_list[module].append(BCCFunctions(function_name))
            else:
                self.config.tool_logger.debug(f"Skipping {line.decode()} to probe")
        for key, value in bcc_list.items():
            probes.append(BCCProbes(ProbeType.KERNEL, key, value))
        return probes

    def get_bcc_function(self, function_name,
        entry_struct: List[Tuple] = [],
        exit_struct: List[Tuple] = [],
        entry_args: str = "",
        entry_cmd: str = "",
        exit_cmd_stats: str = "",
        exit_cmd_key: str = "",
        is_custom = True,):
        if function_name not in self.regex_functions:
            self.regex_functions.add(function_name)            
            return BCCFunctions(function_name, 
                                entry_struct=entry_struct, 
                                exit_struct=exit_struct,
                                entry_args=entry_args,
                                entry_cmd=entry_cmd,
                                exit_cmd_stats=exit_cmd_stats,
                                exit_cmd_key=exit_cmd_key,
                                is_custom=is_custom,)
        else:
            return None
            

    def attach_probes(self, bpf: BPF, collector: BCCCollector) -> None:
        self.config.tool_logger.info("Attaching I/O Probes")
        for probe in tqdm(self.probes, "attach I/O probes"):
            for fn in tqdm(probe.functions, f"attach {probe.category} functions"):
                try:
                    if ProbeType.SYSTEM == probe.type:
                        fnname = bpf.get_syscall_prefix().decode() + fn.name
                        # self.config.tool_logger.debug(
                        #     f"attaching name {fnname} with {fn.name} for cat {probe.category}"
                        # )
                        
                        if fn.is_custom:
                            bpf.attach_kprobe(
                                event=fnname,
                                fn_name=f"syscall__trace_entry_{fn.name}",
                            )
                            bpf.attach_kretprobe(
                                event=fnname,
                                fn_name=f"sys__trace_exit_{fn.name}",
                            )
                        else:
                            bpf.attach_kprobe(
                                event=fnname,
                                fn_name=f"syscall__trace_entry_generic",
                            )
                            bpf.attach_kretprobe(
                                event=fnname,
                                fn_name=f"sys__trace_exit_generic",
                            )
                    elif ProbeType.KERNEL == probe.type:
                        fname = fn.name
                        if fn.is_custom:
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
                        else:
                            self.config.tool_logger.debug(f"Attaching Probe function {fn.name} from {probe.category}")
                            if fn.regex:
                                fname = fn.regex
                                bpf.attach_kprobe(
                                    event_re=fname,
                                    fn_name=f"trace_generic_entry",
                                )
                                bpf.attach_kretprobe(
                                    event_re=fname,
                                    fn_name=f"trace_generic_exit",
                                )
                            else:
                                bpf.attach_kprobe(
                                    event=fname,
                                    fn_name=f"trace_generic_entry",
                                )
                                bpf.attach_kretprobe(
                                    event=fname,
                                    fn_name=f"trace_generic_exit",
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
                        if fn.is_custom:
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
                        else:
                            if is_regex:
                                bpf.attach_uprobe(
                                    name=library,
                                    sym_re=fname,
                                    fn_name=f"trace_generic_entry",
                                )
                                bpf.attach_uretprobe(
                                    name=library,
                                    sym_re=fname,
                                    fn_name=f"trace_generic_exit",
                                )
                            else:
                                bpf.attach_uprobe(
                                    name=library,
                                    sym=fname,
                                    fn_name=f"trace_generic_entry",
                                )
                                bpf.attach_uretprobe(
                                    name=library,
                                    sym=fname,
                                    fn_name=f"trace_generic_exit",
                                )
                except Exception as e:
                    self.config.tool_logger.warn(
                        f"Unable attach probe  {probe.category} to io function {fn.name} due to {e}"
                    )
