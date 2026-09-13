// Command report reads Monitor's audit log and turns raw exec events
// into signals a human can act on. It only ever emits an alert -- it has
// no imported or callable path to Halt at all (see threat-model.md's
// Boundary 4, the PDP/PEP separation). Report's own alerts are written
// to a *separate* hash-chained log it owns outright, never appended
// into Monitor's log -- see internal/audit's Writer doc comment for why
// two independent writers on one chain doesn't work.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Davidpotters/overseer/internal/audit"
)

func main() {
	auditPath := flag.String("audit-log", "/var/log/overseer/audit.log", "path to Monitor's hash-chained audit log (read-only)")
	alertPath := flag.String("alert-log", "/var/log/overseer/alerts.log", "path to Report's own hash-chained alert log")
	allowedExecCSV := flag.String("allowed-exec", "echo", "comma-separated basenames the watched agent is allowed to exec")
	burstThreshold := flag.Int("burst-threshold", 20, "alert if more than this many execs from one cgroup land within -burst-window")
	burstWindow := flag.Duration("burst-window", 2*time.Second, "sliding window for the process-burst/resource-budget rule")
	pollInterval := flag.Duration("poll-interval", time.Second, "how often to check the audit log for new records")
	flag.Parse()

	allowed := map[string]bool{}
	for _, name := range strings.Split(*allowedExecCSV, ",") {
		if name = strings.TrimSpace(name); name != "" {
			allowed[name] = true
		}
	}

	log.Printf("verifying audit log integrity before trusting anything in it: %s", *auditPath)
	ok, brokenAt, err := audit.VerifyChain(*auditPath)
	if err != nil {
		log.Fatalf("could not verify audit log: %v", err)
	}
	if !ok {
		log.Fatalf("TAMPER DETECTED: audit log hash chain is broken at seq=%d -- refusing to trust any record in it", brokenAt)
	}
	log.Printf("audit log chain verified clean")

	alertDir := filepath.Dir(*alertPath)
	if err := os.MkdirAll(alertDir, 0o777); err != nil {
		log.Fatalf("creating alert log directory: %v", err)
	}
	// Best-effort only, unlike Monitor's matching chmod: in the normal
	// deployment Monitor (running as root) already owns and widened this
	// directory, and chmod on a directory you don't own fails with
	// EPERM even when the existing mode already permits what you need --
	// confirmed directly, not assumed. If the directory genuinely isn't
	// writable, OpenWriter below fails with a clear error instead.
	_ = os.Chmod(alertDir, 0o777)
	alertWriter, err := audit.OpenWriter(*alertPath)
	if err != nil {
		log.Fatalf("opening alert log: %v", err)
	}
	defer alertWriter.Close()

	var lastSeenSeq uint64
	recentExecsByCgroup := map[uint64][]time.Time{}
	burstAlreadyAlerted := map[uint64]bool{}
	// A single logical exec attempt shows up as several raw execve
	// syscalls -- libc's execvp-style PATH search retries the same call
	// once per PATH directory until one candidate succeeds, all under
	// the same pid. Measured directly against this project's own toy
	// agent: one disallowed `id` call and one burst of `sleep` calls (two
	// events, by any human reading) produced 320 raw unauthorized_exec
	// alerts before this map existed -- an alert nobody would trust,
	// exactly the alert-fatigue failure mode real rule-tuning guidance
	// warns about. Deduping by pid collapses each process's PATH-search
	// retries into the one alert a human actually needs.
	unauthorizedExecAlerted := map[uint32]bool{}

	log.Printf("report watching %s (allowed execs: %v)", *auditPath, sortedKeys(allowed))
	for {
		records, err := audit.ReadAll(*auditPath)
		if err != nil {
			log.Printf("reading audit log: %v", err)
			time.Sleep(*pollInterval)
			continue
		}

		for _, r := range records {
			if r.Seq <= lastSeenSeq {
				continue
			}
			lastSeenSeq = r.Seq
			if r.Event.EventType != "exec" {
				continue
			}

			// Burst status is recomputed for THIS record, inline, not
			// only once at the end of the whole batch -- measured
			// directly against this project's own demo, a burst of 330
			// execs completes faster than one poll tick, so an
			// end-of-batch-only check would never get the chance to
			// suppress anything within it. Recomputing per record is
			// what actually lets the process_burst alert take over
			// mid-batch instead of after it.
			cg := r.Event.CgroupID
			recentExecsByCgroup[cg] = pruneOlderThan(append(recentExecsByCgroup[cg], r.Timestamp), r.Timestamp, *burstWindow)
			bursting := len(recentExecsByCgroup[cg]) > *burstThreshold

			if bursting && !burstAlreadyAlerted[cg] {
				emit(alertWriter, "P1", "process_burst", r,
					fmt.Sprintf("%d execs from cgroup %d within %s (threshold %d)", len(recentExecsByCgroup[cg]), cg, *burstWindow, *burstThreshold))
				burstAlreadyAlerted[cg] = true
			}

			// Once a cgroup is already flagged as bursting, an
			// individual unauthorized-exec alert for one more exec in
			// that same burst adds nothing a human doesn't already have
			// from the P1 alert -- suppressed, not just deduped by pid.
			base := filepath.Base(r.Event.Filename)
			if !bursting && base != "" && base != "." && !allowed[base] && !unauthorizedExecAlerted[r.Event.PID] {
				unauthorizedExecAlerted[r.Event.PID] = true
				emit(alertWriter, "P2", "unauthorized_exec", r,
					fmt.Sprintf("exec'd %q, not on the allow-list %v", base, sortedKeys(allowed)))
			}
		}

		// A cgroup that's gone quiet should be able to raise a fresh
		// burst alert later -- decay the window even on ticks with no
		// new records to prune it against.
		now := time.Now()
		for cg, times := range recentExecsByCgroup {
			kept := pruneOlderThan(times, now, *burstWindow)
			recentExecsByCgroup[cg] = kept
			if len(kept) <= *burstThreshold {
				burstAlreadyAlerted[cg] = false
			}
		}

		time.Sleep(*pollInterval)
	}
}

func emit(w *audit.Writer, severity, rule string, source audit.Record, detail string) {
	rec, err := w.Append(audit.Event{
		Source:    "report",
		EventType: "alert",
		CgroupID:  source.Event.CgroupID,
		PID:       source.Event.PID,
		Comm:      source.Event.Comm,
		Detail:    fmt.Sprintf("severity=%s rule=%s: %s", severity, rule, detail),
	})
	if err != nil {
		log.Printf("appending alert: %v", err)
		return
	}
	log.Printf("[ALERT %s] seq=%d rule=%s cgroup=%d pid=%d comm=%s: %s",
		severity, rec.Seq, rule, source.Event.CgroupID, source.Event.PID, source.Event.Comm, detail)
}

func pruneOlderThan(times []time.Time, ref time.Time, window time.Duration) []time.Time {
	kept := times[:0]
	for _, t := range times {
		if ref.Sub(t) <= window {
			kept = append(kept, t)
		}
	}
	return kept
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
