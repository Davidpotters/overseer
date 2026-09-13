// Command halt stops a target for real. It is never invoked by Report,
// never invoked automatically by anything in this repo -- it exists
// only to be run by a human who has looked at an alert and decided to
// act (see threat-model.md's Boundary 6). It talks to the Docker Engine
// API directly over the Unix socket rather than shelling out to the
// `docker` CLI or importing a full SDK, so the runtime image stays a
// single small binary with nothing extra to abuse if it were ever
// compromised.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Davidpotters/overseer/internal/audit"
)

func main() {
	target := flag.String("target", "", "container id or name to halt (required)")
	reason := flag.String("reason", "", "why this halt is being triggered -- required, goes in the audit trail")
	confirm := flag.Bool("yes-really-halt", false, "must be set explicitly; this tool refuses to run without it")
	socketPath := flag.String("docker-socket", "/var/run/docker.sock", "path to the Docker Engine API socket")
	alertLog := flag.String("alert-log", "/var/log/overseer/alerts.log", "hash-chained log to record this halt action in")
	flag.Parse()

	if *target == "" || *reason == "" {
		fmt.Fprintln(os.Stderr, `usage: halt -target <container> -reason "..." -yes-really-halt`)
		os.Exit(2)
	}
	if !*confirm {
		fmt.Fprintln(os.Stderr, "refusing to halt without -yes-really-halt -- this is a human-triggered action, never an automated one")
		os.Exit(1)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", *socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}

	// SIGKILL via the kill endpoint, not a graceful stop -- a graceful
	// stop sends SIGTERM, which a process can install a handler for and
	// ignore. SIGKILL can't be caught, blocked, or routed around by
	// anything running inside the target. That guarantee is the entire
	// point of this component.
	killURL := fmt.Sprintf("http://unix/containers/%s/kill", *target)
	req, err := http.NewRequest(http.MethodPost, killURL, nil)
	if err != nil {
		log.Fatalf("building request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("calling docker: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	success := resp.StatusCode == http.StatusNoContent

	if w, err := audit.OpenWriter(*alertLog); err != nil {
		log.Printf("warning: could not record halt in audit log: %v", err)
	} else {
		detail := fmt.Sprintf("target=%s reason=%q docker_status=%d success=%v", *target, *reason, resp.StatusCode, success)
		if _, err := w.Append(audit.Event{Source: "halt", EventType: "halt", Detail: detail}); err != nil {
			log.Printf("warning: could not record halt in audit log: %v", err)
		}
		w.Close()
	}

	if !success {
		log.Fatalf("halt FAILED: docker returned %d: %s", resp.StatusCode, string(body))
	}
	log.Printf("halt issued: %s (reason: %s)", *target, *reason)

	// Success here only means the Docker API accepted the request --
	// verify the target's actual state afterward rather than trusting
	// that. This is the same discipline as Guardrail's admission tests:
	// check the real state, don't assume a 204 means the job is done.
	verifyStopped(client, *target)
}

func verifyStopped(client *http.Client, target string) {
	resp, err := client.Get(fmt.Sprintf("http://unix/containers/%s/json", target))
	if err != nil {
		log.Printf("could not verify post-halt state: %v", err)
		return
	}
	defer resp.Body.Close()

	var info struct {
		State struct {
			Running bool   `json:"Running"`
			Status  string `json:"Status"`
		} `json:"State"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		log.Printf("could not parse post-halt state: %v", err)
		return
	}
	if info.State.Running {
		log.Printf("WARNING: target still reports Running=true after halt (status=%s) -- treat this as halt failing to hold, not succeeding", info.State.Status)
		os.Exit(1)
	}
	log.Printf("verified: target's actual runtime state is %q, not running", info.State.Status)
}
