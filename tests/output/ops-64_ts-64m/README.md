# Analysis results

## WRITE DIRECT I/O

```bash
name                          cat   
ext4_dio_write_iter           kernel    0.000086
ext4_inode_extension_cleanup  kernel     0.00002
write                         sys       0.000593
obj_cgroup_uncharge_pages     kernel    0.000001
ext4_file_write_iter          kernel    0.000139
vfs_write                     vfs       0.000475
```

## Write Buffered I/O

```bash
name                      cat   
ext4_buffered_write_iter  kernel    0.000005
write                     sys       0.000051
ext4_file_write_iter      kernel     0.00001
vfs_write                 vfs        0.00004
```

## Read Direct I/O

```bash
name                 cat   
ext4_dirty_inode     kernel    0.000055
ext4_file_read_iter  kernel    0.000114
read                 sys       0.000276
vfs_read             vfs       0.000183
__ext4_journal_stop  kernel    0.000004
```

## Read Buffered I/O

```bash
name                    cat   
ext4_dirty_inode        kernel    0.000007
ext4_file_read_iter     kernel    0.000023
generic_file_read_iter  kernel    0.000018
read                    sys       0.000059
vfs_read                vfs       0.000031
__ext4_journal_stop     kernel    0.000005
filemap_read            kernel    0.000012
```
