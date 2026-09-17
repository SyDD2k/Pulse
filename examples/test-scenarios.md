# Test scenarios

Run the agent first, then use a second terminal.

## CPU and scheduling

```bash
stress-ng --cpu 4 --timeout 60s
stress-ng --switch 16 --timeout 60s
```

Expected: CPU/context switch charts move and, with thresholds crossed, an incident appears.

## Memory

```bash
stress-ng --vm 2 --vm-bytes 70% --timeout 60s
```

Expected: memory and page-fault metrics move. Avoid an overly aggressive test on a machine with important work.

## Disk

```bash
fio --name=randwrite --filename=/tmp/ebpfca-fio-test --size=512M --bs=4k --iodepth=16 --rw=randwrite --direct=1 --runtime=60
```

Expected: disk byte counters and block latency move. Remove `/tmp/ebpfca-fio-test` manually afterward if desired.
