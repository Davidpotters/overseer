// Package audit implements Overseer's shared, hash-chained, append-only
// event log: each record stores a hash derived from the previous one,
// so altering an earlier entry breaks the chain for everything after
// it. The same tamper-evidence pattern real audit-trail systems use,
// adapted here to Monitor's lower-level syscall events.
//
// Monitor and Report both import this package, but that is a shared
// data format, not a shared trust boundary: Report only ever reads this
// log and emits alerts. It has no imported or callable path to Halt --
// see threat-model.md's Boundary 4.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// GenesisHash is the PrevHash of the very first record in a log --
// there is nothing before it to chain to.
var GenesisHash = strings.Repeat("0", 64)

// Event is the observation itself, independent of the chaining
// metadata around it. Source names which component produced it
// ("monitor", "halt"); EventType names what kind of observation it is
// ("exec" for now -- more types arrive as Monitor grows more
// tracepoints).
type Event struct {
	Source    string `json:"source"`
	EventType string `json:"event_type"`
	CgroupID  uint64 `json:"cgroup_id,omitempty"`
	PID       uint32 `json:"pid,omitempty"`
	TGID      uint32 `json:"tgid,omitempty"`
	Comm      string `json:"comm,omitempty"`
	Filename  string `json:"filename,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// Record is one hash-chained, append-only entry.
type Record struct {
	Seq       uint64    `json:"seq"`
	Timestamp time.Time `json:"timestamp"`
	Event     Event     `json:"event"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
}

// Writer appends records to a log file, chaining each one to the last.
//
// A Writer assumes it is the sole writer of its file: it keeps the
// chain's tip (lastHash, seq) in memory rather than re-reading the file
// on every append. Two independent Writer instances appending to the
// same path would each hold a stale, diverging view of the tip and
// silently corrupt the chain the moment they interleave -- this is
// exactly why Report owns a separate log file for its own alerts
// instead of appending into Monitor's, even though both import this
// same package. Found while designing Report, not after shipping it.
type Writer struct {
	mu       sync.Mutex
	f        *os.File
	lastHash string
	seq      uint64
}

// OpenWriter opens (creating if needed) the log at path and, if it
// already holds records, resumes the chain from its last entry instead
// of silently starting a new one -- a restart must not look like a gap.
func OpenWriter(path string) (*Writer, error) {
	// 0o644, not 0o600: Monitor (root, for eBPF) and Report (unprivileged)
	// both need to open this file, and the log holds metadata only --
	// syscall/exec facts, never payload content (see threat-model.md's
	// Boundary 3) -- so read access being wide isn't a confidentiality
	// concern. Only the owning process's Writer can append to it.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}
	w := &Writer{f: f, lastHash: GenesisHash}
	if last, err := readLastRecord(path); err == nil && last != nil {
		w.lastHash = last.Hash
		w.seq = last.Seq
	}
	return w, nil
}

// Append writes one new event, chained to whatever was written last.
func (w *Writer) Append(ev Event) (Record, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.seq++
	r := Record{
		Seq:       w.seq,
		Timestamp: time.Now().UTC(),
		Event:     ev,
		PrevHash:  w.lastHash,
	}
	r.Hash = computeHash(r)

	line, err := json.Marshal(r)
	if err != nil {
		w.seq--
		return Record{}, fmt.Errorf("encoding record: %w", err)
	}
	line = append(line, '\n')
	if _, err := w.f.Write(line); err != nil {
		w.seq--
		return Record{}, fmt.Errorf("writing record: %w", err)
	}
	if err := w.f.Sync(); err != nil {
		return Record{}, fmt.Errorf("syncing record: %w", err)
	}
	w.lastHash = r.Hash
	return r, nil
}

// Close releases the underlying file handle.
func (w *Writer) Close() error {
	return w.f.Close()
}

// ReadAll returns every record in the log, in order.
func ReadAll(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}
	defer f.Close()

	var records []Record
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("parsing record: %w", err)
		}
		records = append(records, r)
	}
	return records, scanner.Err()
}

// VerifyChain walks the whole log and confirms every record's hash and
// prev_hash link up correctly. It returns the sequence number of the
// first broken record, if any -- this is the actual tamper-detection
// mechanism, not just a claim that hash chaining "would" catch tampering.
func VerifyChain(path string) (ok bool, brokenAtSeq uint64, err error) {
	records, err := ReadAll(path)
	if err != nil {
		return false, 0, err
	}

	prev := GenesisHash
	for _, r := range records {
		if r.PrevHash != prev {
			return false, r.Seq, nil
		}
		if computeHash(r) != r.Hash {
			return false, r.Seq, nil
		}
		prev = r.Hash
	}
	return true, 0, nil
}

func readLastRecord(path string) (*Record, error) {
	records, err := ReadAll(path)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}
	last := records[len(records)-1]
	return &last, nil
}

func computeHash(r Record) string {
	r.Hash = ""
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
