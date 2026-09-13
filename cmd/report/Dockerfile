FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal/ internal/
COPY cmd/report/ cmd/report/
WORKDIR /src/cmd/report
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/report .

# Unlike Monitor, Report only ever reads files and writes its own log --
# it needs no elevated privilege at all, so it gets the same nonroot
# distroless treatment as Guardrail's webhook.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/report /report
ENTRYPOINT ["/report"]
