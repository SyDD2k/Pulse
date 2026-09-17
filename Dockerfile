FROM fedora:40 AS bpf-builder
RUN dnf install -y clang llvm make kernel-devel bpftool libbpf-devel && dnf clean all
WORKDIR /src
COPY bpf/ bpf/
RUN make -C bpf

FROM golang:1.22-bookworm AS go-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=bpf-builder /src/bpf/ebpfca.bpf.o bpf/ebpfca.bpf.o
RUN CGO_ENABLED=0 go build -o /ebpfca ./cmd/ebpfca

FROM fedora:40
RUN dnf install -y libbpf procps-ng && dnf clean all
WORKDIR /app
COPY --from=go-builder /ebpfca /app/ebpfca
COPY configs/ /app/configs/
COPY --from=bpf-builder /src/bpf/ebpfca.bpf.o /app/bpf/ebpfca.bpf.o
EXPOSE 9090
ENTRYPOINT ["/app/ebpfca", "-config", "/app/configs/ebpfca.yml"]
