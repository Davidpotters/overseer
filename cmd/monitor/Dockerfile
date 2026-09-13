FROM golang:1.27-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev \
    && rm -rf /var/lib/apt/lists/*
# clang -target bpf doesn't pick up Debian's multiarch header layout on
# its own (linux/types.h -> asm/types.h resolves under
# /usr/include/<triplet>/asm, not /usr/include/asm) -- confirmed the
# actual path on this exact image before symlinking, not guessed.
RUN ln -s /usr/include/$(uname -m)-linux-gnu/asm /usr/include/asm
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal/ internal/
COPY cmd/monitor/ cmd/monitor/
WORKDIR /src/cmd/monitor
RUN go generate ./...
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/monitor .

# Monitor is the one component in this project that legitimately needs
# elevated privilege (CAP_BPF/CAP_PERFMON, or --privileged in this dev
# setup) to load its eBPF probe -- see threat-model.md's Boundary 2.
# Every other component in this repo runs fully unprivileged; this one
# deliberately does not use a nonroot distroless base.
FROM gcr.io/distroless/static-debian12:latest
COPY --from=build /out/monitor /monitor
ENTRYPOINT ["/monitor"]
