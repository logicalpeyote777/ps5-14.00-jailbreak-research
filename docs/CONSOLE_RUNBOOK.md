# Console runbook, PS5 14.00, first boot after the offline period

Everything below is already armed. This is the order to do things in and what each
answer means. Console time is the scarce resource; do not spend it on modules that
waste it.

## 0. State as left

| item | value |
|---|---|
| sweep | running, `python3 sweep.py`, pushes one module per plan |
| queue | 139 modules, priority order below |
| current plan | `API-availability` as plan 570 |
| idle-park fix | applied, parked idle plan bumps `plan_id` each cycle so a live-but-idle page re-reports and the sweep un-parks |
| DNS | `manuals.playstation.net` → `192.168.1.70` active; shell domain **not** applied |
| shell-domain flip | staged: `/opt/AGENTS/Ares/tmp/dns_shell.sh apply\|revert\|status` |

## 1. First action: let the head of queue run untouched

Do not change anything for the first ~10 minutes. The sweep pushes the priority
modules in this order and each one answers a distinct question:

| # | module | what a good answer looks like | what it decides |
|---|---|---|---|
| 0 | `API-availability` | which APIs exist on the 14.00 guide browser | whether the rest of the queue is even runnable |
| 1 | `CVE-2026-43720-trigger` | `same=false` | **entry is live on 14.00** (vs the 14.10-only upstream confirmation) |
| 2 | `43720-bitmap-trigger` | `REENTRY-DIFFERENT-CTX` | second door open; `patched-same-ctx` = closed |
| 3 | `CVE-2026-43720-rw` | bidirectional | the R/W primitive itself |
| 4 | `CVE-2026-43720-leak` | `integer-read-live` | DAZ-immune read works |
| 5 | `FontFace-reclaim-leak` | `LEAK` + `heap_pointers` at `+0x58`/`+0x68` | **WebProcess ASLR defeated** |
| 6 | `ntfusion-iterator-confusion` | `CONFUSED` with `control_clean=true` | iterator confusion reachable |
| 7-12 | `K4-fdtype-{ctl,websocket,fetch,msgchan,worker,sse}` | which arm reports `corrupted` | **confirms or falsifies the tblB CVE-2026-45251 prediction** |

The K4 arms are the single most valuable thing on the queue: one arm showing
corruption on one fd class and not the others settles the static classification
that is currently capped at "confidenza media".

## 2. Budget warning, the K-modules are expensive

| family | declared `timeout_ms` | observed |
|---|---|---|
| `K0-*` | 45 000 | `K0-canary-a` completed at 40 004 ms |
| `K2-sock_abort-*` | 75 000 |, |
| `K1-ws_churn-*`, `K3-worker_churn-*` | 135 000 | churn classes exceed 46 s |

The 14 K-modules cost **20+ minutes of console time**. They are slow, not stuck.
Do not interrupt them.

## 3. Do NOT run these first, they waste console time

Re-running the 17 modules that produced no verdict, with a 150 s hard timeout and a
220 s virtual budget on patched Chromium:

| result | count | meaning for the console |
|---|---|---|
| `NO_OUTPUT` | 10 | no verdict in 150 s even on a desktop engine, will burn WebProcess reloads on the PS5 |
| ran, never finished | 4 | `pg_begin`/`pg_log`/`pg_report` but no `pg_end` |
| resolved by the longer timeout | 3 | `aborted` (attempt 3), `unknown` (no crash), `patched` (`leaks: 0`) |

The 10 `NO_OUTPUT` are `CVE-2022-22620`, `CVE-2025-43441`, `CVE-2026-20652`,
`CVE-2026-20665`, `CVE-2026-28907`, `CVE-2026-28984-dom`, `CVE-2026-43660`,
`CVE-2026-43670`, `CVE-2026-64781`, `CVE-2026-65332`, `CVE-2026-65340`.
With `MAX_CRASHES = 2` each one can eat two passes before being skipped.
**Run them last, or not at all.**

## 4. Reading the results

Compare every `pg_end` against the two negative baselines now on disk:

- `probe/chromium_negative_baseline.json`, the 13 head-of-queue modules
- `probe/chromium_core_driven_baseline.json`, all 112 core-driven modules

**A module that reports the same outcome on patched Chromium as its headline
"vulnerable" outcome is a false positive.** Across the 112 core-driven modules
there were **zero** such cases, so the queue is clean in that specific sense.

Read deaths as **confirmed live handlers**, not dead ends: a crash means the
handler is present and ran deep enough to touch a bad pointer.

## 5. If the guide browser cannot reach the kernel

The browser path is a **userland** entry. WebKit UAF gives WebProcess **heap**
r/w; the kernel stage needs an **arbitrary kernel write**. Different address
spaces. Two open questions decide whether the handoff is even possible from here:

1. Can the guide WebProcess make syscalls at all, and what is its Capsicum state?
2. Can it reach routing sockets (Relapse's `rtmsg2` KASLR route)?

If both are no, the browser entry must hand off to the game/loader path and the
WebKit primitives become a userland-only result.

## 6. The kernel stage: a characterized mechanism that is not yet an exploit

**CORRECTION 2026-11-07.** The previous headline here read "The kernel stage has
no mechanism" and declared the kind swap **abandoned** on the grounds that
"nothing on the `sysctl(2)` operation path reads `oid_kind`". That was wrong,
and it contradicted the finding this engagement is actually built on.

**What was verified instead:** `oid_kind` *is* read on the operation path. The
gates at `0xffffffff9e947ec2`, `0xffffffff9e947ed` and `0xffffffff9e947ed4`
test it, and the swap `0x80048002 -> 0x70048002` leaves `CTLTYPE` (`& 0xf = 2`)
untouched while flipping one `test`/`je` so the kernel skips `PRIV_SYSCTL_WRITE`.
**The kind swap is a permission-check bypass, not a type confusion.** That
characterization is our novel contribution: zero occurrences of `80048002`,
`70048002`, `CTLFLAG`, `PRIV_SYSCTL`, `oid_kind` or `suser` across the eight
main upstream documents.

**What is still true, and is the actual headline:** a permission bypass is not a
memory-safety violation. It changes who is allowed to write; it does not by
itself produce an arbitrary kernel write. The `sysctl` write branch was measured
and found bounded, the bound is on `len` (`req->+0x38 - req->+0x40`), there is
no bound on `oid_arg1`, direction is user -> `oid_arg1` via `rep movsq`, with
0 chaining and 0 amplification. **So the mechanism is characterized and the
exploit is still missing. Those are two different gaps and solving one does not
solve the other.**

Cross-checked against the upstream landscape: **there is no public kernel exploit
for 14.00 or 14.10 at all.** Relapse stops at 13.60. Upstream's own blocker is
recorded as "no address of JS-owned memory", the same wall we are at.

## 7. When leaving the console again

Leave the sweep running. It parks itself and preserves the queue. To stop cleanly:

```
cd /opt/AGENTS/Ares/engagements/ps5-1400-kernel/probe
for p in $(pgrep -f "swee[p].py"); do kill $p; done
```

Revert the shell-domain flip if it was applied:
`/opt/AGENTS/Ares/tmp/dns_shell.sh revert`

---

## 8. Matrix room ID, corrected

The room ID carried in earlier notes was **wrong by transcription**:

| | value |
|---|---|
| wrong (in prior notes) | `!JbVcVYRPqBWEgYrdj:chill.servebeer.com` |
| **correct** | `!JbVcVUyRPqBWEgYrdj:chill.servebeer.com` |

The dropped `Uy` made every send fail with `No such room with id ... found`, and
`matrix_notify.py` masks it by falling back to a direct login that also fails
(`LoginError: 'user_id' is a required property`).

Discovery method: the bot's nio store at
`/opt/AGENTS/Ares/matrix/matrix_store/*.db`, table `encryptedrooms`, column
`room_id` (not `id`, column 0 is the internal row key).

**Verified delivery contract:** the primary path is the bot HTTP listener on
`127.0.0.1:8772/send` (pid 223923). `exit 0` from `matrix_notify.py` means the
bot returned 200. Confirm independently with
`matrix_read.py "<room>" 3`, done, message visible at 07:46.

Note: a `[vault_env] load failed (vault auth failed: 429)` line on stderr is
unrelated to delivery, the bot HTTP path does not use the vault.
