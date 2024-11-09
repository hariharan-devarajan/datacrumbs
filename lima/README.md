# Lima eBPF Environment

This is for running an environment for development with lima
 
## Usage

```bash
limactl start --network=lima:user-v2 --name=ebpf lima/ebpf.yaml
```

If you are coming back to it from later:

```bash
limactl start ebpf
```

It says it doesn't reach running status, but I don't see any errors in the logs, and the shell works:

```bash
limactl shell ebpf
```

## Clean Up

You can stop:

```bash
limactl stop ebpf
```

or just nuke it!

```bash
limactl delete ebpf
```
