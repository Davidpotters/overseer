FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal/ internal/
COPY cmd/halt/ cmd/halt/
WORKDIR /src/cmd/halt
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/halt .

# Halt needs no elevated Linux privilege of its own -- its power comes
# entirely from the Docker socket mounted into it at run time, a real,
# separate, and narrower privilege boundary than Monitor's eBPF
# capability. Runs as nonroot like Report; the socket access, not the
# container's own privilege, is what makes this component powerful.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/halt /halt
ENTRYPOINT ["/halt"]
