# Overseer

A control-plane component that watches an AI system from outside it. Not
an agent itself -- it has one job: notice when a system under watch is
doing something it shouldn't, tell a human, and be able to stop it. It
never acts on its own judgment; a human decides whether to pull the
trigger.

**Status: design phase.** Threat model and the first architecture
decision are written; no application code yet.

## The three verbs

- **Monitor** -- capture what the watched system is actually doing, at a
  layer it can't reach or falsify. A system's own self-reported logs
  aren't trustworthy evidence about itself; this project observes from
  the kernel side (eBPF) instead of trusting anything the target claims
  about its own behavior.
- **Report** -- turn raw observation into a signal worth a human's
  attention. The hard part isn't detecting a violation, it's not crying
  wolf: an alert nobody trusts at 2am is decoration, not security.
- **Halt** -- stop the target for real: kill the process, revoke a
  credential, cut its network path. Triggered only by an explicit human
  command. If this project ever halted something on its own judgment, it
  would have become the thing it's supposed to watch.

## Why eBPF, and why not just Falco

Falco (the CNCF standard for this) was tried first and tested live in
this project's own dev environment before being ruled out -- its eBPF
driver genuinely captures kernel syscalls here, but its rule-matching
engine never fired on anything, default rules or hand-written ones. That
result, and the reasoning for building a small custom eBPF capture
instead, is a permanent design decision, not a workaround glossed over
after the fact.

## License

[MIT](LICENSE)
