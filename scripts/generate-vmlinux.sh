#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="${root_dir}/bpf/vmlinux.h"

if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
  echo "Kernel BTF was not found at /sys/kernel/btf/vmlinux." >&2
  echo "Use a BTF-enabled Fedora kernel or install matching kernel support packages." >&2
  exit 1
fi

bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${output}"
echo "Generated ${output}. Rebuild with: make bpf"
