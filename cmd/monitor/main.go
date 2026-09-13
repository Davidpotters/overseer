// Command monitor watches process execs from outside the target --
// a custom eBPF tracepoint probe, not the target's own self-reported
// activity -- and appends each one to Overseer's shared,
// hash-chained audit log for Report to read.
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 execwatch bpf/execwatch.c

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/Davidpotters/overseer/internal/audit"
)

// event mirrors bpf/execwatch.c's `struct event` byte for byte -- field
// order and sizes must match exactly, since it's decoded straight out of
// the ring buffer's raw bytes.
type event struct {
	TimestampNs uint64
	Pid         uint32
	Tgid        uint32
	CgroupID    uint64
	Comm        [16]byte
	Filename    [256]byte
}

func main() {
	auditPath := flag.String("audit-log", "/var/log/overseer/audit.log", "path to the hash-chained audit log")
	cgroupPath := flag.String("cgroup-path", "", "only record execs from this cgroup (cgroupfs path); empty = record everything visible")
	flag.Parse()

	var targetCgroupID uint64
	if *cgroupPath != "" {
		id, err := cgroupIDFromPath(*cgroupPath)
		if err != nil {
			log.Fatalf("resolving target cgroup id from %s: %v", *cgroupPath, err)
		}
		targetCgroupID = id
		log.Printf("scoping capture to cgroup %s (id=%d)", *cgroupPath, targetCgroupID)
	} else {
		log.Printf("no --cgroup-path given, recording execs from every visible process")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock limit: %v", err)
	}

	// 0o777, not 0o755: Monitor runs as root (needs eBPF privilege) but
	// Report runs unprivileged and must be able to create its own
	// alert-log file in this same shared directory -- a directory
	// holding nothing but metadata-only log files, same reasoning as
	// audit.go's 0o644 on the files themselves.
	auditDir := filepath.Dir(*auditPath)
	if err := os.MkdirAll(auditDir, 0o777); err != nil {
		log.Fatalf("creating audit log directory: %v", err)
	}
	// MkdirAll only applies the given mode when it actually creates the
	// directory -- Docker itself pre-creates a named volume's mount
	// point (root-owned, 0o755) before this process ever runs, so
	// MkdirAll alone silently leaves that mode in place. Chmod forces it
	// regardless of which case this is. Found by testing the real
	// container, not anticipated up front.
	if err := os.Chmod(auditDir, 0o777); err != nil {
		log.Fatalf("setting audit log directory permissions: %v", err)
	}
	w, err := audit.OpenWriter(*auditPath)
	if err != nil {
		log.Fatalf("opening audit log: %v", err)
	}
	defer w.Close()

	var objs execwatchObjects
	if err := loadExecwatchObjects(&objs, nil); err != nil {
		log.Fatalf("loading BPF objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %v", err)
	}
	defer rd.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		rd.Close()
	}()

	log.Println("monitor attached, watching process execs...")
	var e event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("monitor shutting down")
				return
			}
			log.Printf("reading ringbuf: %v", err)
			continue
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("parsing event: %v", err)
			continue
		}
		if targetCgroupID != 0 && e.CgroupID != targetCgroupID {
			continue
		}

		comm := cStr(e.Comm[:])
		filename := cStr(e.Filename[:])
		rec, err := w.Append(audit.Event{
			Source:    "monitor",
			EventType: "exec",
			CgroupID:  e.CgroupID,
			PID:       e.Pid,
			TGID:      e.Tgid,
			Comm:      comm,
			Filename:  filename,
		})
		if err != nil {
			log.Printf("appending to audit log: %v", err)
			continue
		}
		log.Printf("[exec] seq=%d pid=%d comm=%s filename=%s", rec.Seq, e.Pid, comm, filename)
	}
}

func cStr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func cgroupIDFromPath(path string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}
