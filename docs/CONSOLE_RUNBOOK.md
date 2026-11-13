# Console runbook for PS5 14.00

Rewritten 2026-11-09 after verifying every countable fact. The previous version of this file was
stale on all of them: it said the sweep was running (it is not), that the queue held 139 modules
(the library holds 167 and the served plan holds 2), and that the current plan was `API-availability`
at plan 570. **A runbook is read at the moment the console appears, so a stale one is worse than
none.**

**And the rewrite went stale within hours, on its own numbers.** Registering the blocked-thread probe
bumped the served plan to `plan_id 2640` with 3 tests while this file still said 2639 with 2. **A
hand-maintained count drifts the moment anything is registered.** Read the live values instead of
trusting the table:

```
curl -sk http://127.0.0.1:8000/plan | python3 -c "import json,sys; p=json.load(sys.stdin); \
  print(p['plan_id'], p['poll_ms'], [(t['tier'], len(t['code'])) for t in p['tests']])"
```

**Run from the host, not the container.** The probe server listens on the host's loopback; from inside
the container `127.0.0.1:8000` is the container's own and returns an empty body, which then fails
JSON parsing with an error that says nothing about the real cause.

## 0. State as verified, not as remembered

**The consolidated pre-flight lives in `kernel-hunt/preflight-consolidated-1400.md`: thirteen things
verified offline against six device-only unknowns, the order that maximises information per console
minute, and what each output means. Read that before the console comes on.**

| item | verified value |
|---|---|
| Save-path runner | `auto_test_1400.py` under `supervise_test.sh`, waiting on TCP 9026 at 192.168.1.91/.92 |
| Supervisor | restarts the runner only on rc=3 (no foothold). rc=143 from a kill restarts it too |
| Probe server | `probe_server.py --port 8000`, alive, nginx vhost `manuals.playstation.net` proxies to it |
| Landing page | now `agent.html` (5428 B, md5 `40acf1f2…`), the self-driving polling loop |
| Live plan | `plan_id 2640`, `poll_ms 2500`, 3 tests: `byteview-stability` (5761 B), `history-addrof` (5285 B), `blocked-thread` (3391 B) |
| Probe library | 167 entries in `pg_tests.json`. **The library is not the queue** |
| Sweep | **NOT running.** `pgrep -f sweep.py` matching is the ssh command line self-match, not a real process |
| DNS | `manuals.playstation.net` rewritten to this host by **AdGuard**, not by anything on the host. `getent` on the host resolves to Akamai and that is expected |
| Save packages | 5 built, all at `ACCOUNT_ID_PLACEHOLDER`, verified intact |

**The primary route is the save path, not the browser.** The save path reaches kernel arbitrary r/w
through `ipv6_kernel_rw`. The browser path is secondary and currently capped at userland.

## 1. Before anything else: try the placeholder import, then get the account ID if needed

**A stick is already prepared.** As of 2026-11-13 the `KONBOOT` stick on `mac17`
(`192.168.1.17`, reached from ai-srv with the `mac17` ssh alias) was reformatted exFAT with an MBR
scheme and loaded with the foothold save, both files sha256-verified against the source on ai-srv:

```
/Volumes/KONBOOT/PS4/SAVEDATA/ACCOUNT_ID_PLACEHOLDER/savedata      104 857 600 B  75169f5f...
/Volumes/KONBOOT/PS4/SAVEDATA/ACCOUNT_ID_PLACEHOLDER/savedata.bin          96 B  4f954291...
```

**Two things to know about that stick.** The reformat erased its Kon-Boot bootability (`grldr`,
`konboot*.img`, `EFI/`, `menu.lst`). And `diskutil list external` shows the TYPE column as
`Windows_NTFS` after an exFAT format, which is not an error: the MBR type code for exFAT is `0x07`,
shared with NTFS, so trust `diskutil info` (`File System Personality: ExFAT`) over the TYPE column.

**Any command aimed at mac17 needs the explicit `ssh mac17` wrapper.** A block run without it lands on
ai-srv and reports `diskutil: command not found` plus a missing `/Volumes/KONBOOT`, which reads like a
dead stick but is only the wrong host looking at it.

**Try the import with the placeholder folder before asking for the account id.** The folder name is the
*source* account id, a piece of metadata, not necessarily a check against the logged-in user. The PS4
transfer lists saves from any account on the stick and lets you pick the local account to assign them to,
and gezine's save has already been imported onto consoles where the gezine account was not present. Both
point to the PS5 tolerating a folder name that is not the logged-in account's hex16.

```
# copy PS4/SAVEDATA/ACCOUNT_ID_PLACEHOLDER/ to a USB stick (exFAT or FAT32)
# PS5: Settings > Saved Data (PS4 Saved Data) > USB Extended Storage > Save Data in USB Storage Device
# if Raspberry Cube (CUSA16074) appears, import it
```

**If it imports, the account-id blocker is gone and no rename is needed.** If it does not appear or fails,
get the account id and rename:

```
cd /opt/AGENTS/Ares/engagements/ps5-1400-kernel/kernel-hunt
python3 prepare_usb_saves.py <account_id_decimale>
python3 prepare_usb_saves.py --check
```

**The save binds to the PSN account, not the console.** The folder under `PS4/SAVEDATA/` must carry
the account id as 16 lowercase hex digits. The conversion is self-tested against gezine's known
`param.sfo` pair `8028911461577375126` → `6f6c6c6f7061bd96` before anything is touched.
`--revert` puts the placeholder back.

**Run `prepare_usb_saves.py` on the host, not in the container.** The saves live in the host's `/tmp`
(`/tmp/test1_gezine`, `/tmp/test2_loader_pad_plain`, ...). The container has its own `/tmp` that does
not hold them, so `--check` run from the container reports `MANCANTE` for every save. **That is the
wrong place to look, not a lost save.** Same class as the probe-server loopback trap: a check run in the
container against a path that exists only on the host returns an emptiness that names nothing about the
cause. Verify with `ls -d /tmp/<dir>` over `sshcmd.js` before declaring a save missing. As of this
writing both primary saves are confirmed intact on the host: `test1_gezine` 104857600 B sha256
`75169f5f…`, `test2_loader_pad_plain` 104857600 B sha256 `5a4eb393…`.

## 1b. Confirm the trigger is actually polling before wasting a console session

**The runner is what fires when the console comes on. If it silently stopped polling, the foothold is
never taken even with the PS5 on and the right save installed, and a whole console session is lost for
nothing.** The log does not tell you: `wait_foothold` logs only at entry and at timeout, so silence is
correct behaviour and cannot distinguish "polling" from "stuck in one long sleep".

**CPU time does not answer either.** Two reads 12 seconds apart both show `TIME 00:00:00`, `STAT S`,
which a process blocked on a single long sleep also shows. `strace` produced no output here.

**What does answer is sampling `/proc/net/tcp` on the host.** Port 9026 is `0x2342`:

```
for i in $(seq 1 22); do
  line=$(grep ":2342" /proc/net/tcp | head -1)
  [ -n "$line" ] && echo "$(echo $line | awk '{print $4}') $(echo $line | awk '{print $3}')"
  sleep 1
done
```

**Observed, with the hex decoded little-endian:** `5B01A8C0` = 192.168.1.91, `5C01A8C0` =
192.168.1.92. **The runner tries both candidates, about 3 seconds each, and cycles.** State is
`02` SYN-SENT with nothing coming back, **not even a RST**, which is what a powered-off console with
ICMP blocked looks like. A RST would have meant a live host with a closed port; no packet at all means
the host is off. **The distinction reads without turning anything on.**

**If `02` never appears across 20 seconds, the runner is not polling and the console session should be
postponed until the trigger is fixed.**

## 2. Test 1, the foothold. Costs about five minutes, zero build

Install Raspberry Cube (CUSA16074). Import `test1_gezine` over USB in **binary** transfer mode, with
the game installed but **not started**. Start the game.

**Ask for a photo of the on-screen notification before doing anything else.** The loader prints:

```lua
notify(string.format("remote lua loader\nrunning on %s %s%s\nlistening on %s",
    PLATFORM, console_model, FW_VERSION, network_str))
```

| field | what it settles |
|---|---|
| `PLATFORM` | whether the loader sees `ps5`. **If it reads `ps4`, every PS5 offset conclusion is void** and the gate is not the problem |
| `console_model` | confirms CFI-2000 |
| `FW_VERSION` | from `get_version()`, and it is **exactly the string `kernel_offset.lua` looks up to decide the `DATA_BASE_ALLPROC` gate** |
| `IP:porta` | which of .91/.92 is live, without guessing |

**This costs nothing, needs no network, and arrives even if the socket never answers.**

## 3. Test 2, the objective. The supervisor drives it

Once 9026 opens the runner fires step 0 then the payload. **Do not close Raspberry Cube during or
after the test.** The documented panic (issue #133) is at game CLOSE, not during r/w.

| output | meaning |
|---|---|
| `round-trip OK (read+write proved) @ <addr>` | **objective proved** |
| `[read] inside_kdata legge "evf cv"` | arbitrary read proved |
| `TEST2 PASS (discovery parziale)` | **objective reached**, post-exploitation skipped |
| `fw not yet supported for jailbreaking` | **not a failure of the objective.** The gate exits `post_exploitation_ps5()`, not `kexploit()`. The r/w is already established before it |
| `TEST2 FAIL: round-trip canary non completato` | the primitive itself is broken |
| `TEST2 FAIL: exploit state 'kernel_rw' assente` | the payload exploit did not run |
| `unable to find softc !!` / `unable to init iommu !!` / `unable to patch qa flags !!` | the IOMMU vuln is patched. Closes plan B with a named reason |

**A Lua error in the exploit is caught, shown, and cleaned up, so a failed attempt does not leave the
game holding dangling resources.** The exploit body runs inside `run_with_coroutine`
(`misc.lua:88-95`), which resumes the coroutine and on error returns the message plus a traceback
instead of letting it propagate. `lapse.lua:2052` prints that error (it reaches us over the socket,
because `print` is rewritten to write to the client fd), and then the cleanup at `lapse.lua:2056` runs
regardless of the error: it closes `block_fd` and `unblock_fd`, frees the groom AIOs, deletes the block
AIO, and closes the socket descriptors. `main.lua:85-90` also writes the error to the client fd.
**So a failed exploit on 14.00 gives a visible traceback and still releases the AIO and fd resources,
which matters under the do-not-brick constraint: a failed attempt is not supposed to be the thing that
crashes the game.** The residual risk is the partial-success case, where the double free already
happened and the cleanup touches memory the exploit already corrupted; that is inherent to the
technique, not to the error handling.

**Step 0 runs first and must show `kernel_rw_initialized` false.** If it reads true, something
already fired and the baseline is not clean, so a PASS cannot be credited to the current run.

**Step 0 is read-only and isolated: every field is wrapped in its own `pcall` (`safe()` in
`fingerprint.lua:9`), so a missing field returns `n/d` and never crashes the fingerprint or the
chain.** It captures `lua_version`, `pid`, the nine loader modules, the firmware from both the syscall
and the offsets module, `kernel_rw_initialized`, and `storage_kernel_rw`, bounded by
`FINGERPRINT_BEGIN`/`FINGERPRINT_END`/`FINGERPRINT DONE`.

**One cross-plan nuance to read the log correctly: step 0 runs once, before plan A, not between the
plans.** If plan A fails to PASS but leaves `rw_initialized = true` and the `kernel_rw` storage written,
plan B runs on plan A's leftover state, and the test after plan B reads plan A's storage. **A PASS there
is still kernel r/w demonstrated, so the objective holds; it just cannot be attributed to plan B
specifically.** Distinguishing the two would need a step 0 re-run between the plans, which the objective
does not require.

**Plan B (`p2jb_handoff`) is the only route to a full jailbreak on 14.00.** It has no table gate and
does runtime discovery. Plan A reaches the r/w objective but loses everything below its gate.

## 4. Browser path, secondary

The landing page polls `/plan`. To add a probe you must do **both** steps, and neither warns if you
skip one:

```
python3 register_history_probe.py     # into the library
python3 add_to_live_plan.py           # into the served plan
```

**Three independent layers where "the test is written" did not mean "the test runs":**

| layer | failure | how to catch it |
|---|---|---|
| library vs plan | `pg_tests.json` is not the queue | `/plan` serves a different count than the library has |
| frozen update | the plan keeps the old code | code length in the plan differs from the library |
| landing page | `/` serves a page that never asks for the plan | md5 of the served page vs `agent.html` |

**None of the three raises an error. Each produces a silence that reads as "the test found nothing."**

Verify the chain from the client side:

```
curl -sk --resolve manuals.playstation.net:443:127.0.0.1 https://manuals.playstation.net/ | md5sum
curl -sk --resolve manuals.playstation.net:443:127.0.0.1 https://manuals.playstation.net/plan
```

**The `history.state` probe is not lethal.** `replaceState` does not UAF anything, so unlike the
lethal cycles it does not require reopening the page.

## 5. What the browser path cannot reach

The browser path is a **userland** entry. WebKit UAF gives the WebProcess **heap** r/w; the kernel
stage needs an **arbitrary kernel write**. Different address spaces.

**The kind swap `0x80048002 -> 0x70048002` is a permission-check bypass, not a type confusion.**
`CTLTYPE` (`& 0xf = 2`) is untouched; the flip makes the kernel skip `PRIV_SYSCTL_WRITE`. **A
permission bypass is not a memory-safety violation.** The `sysctl` write branch was measured bounded:
the bound is on `len` (`req->+0x38 - req->+0x40`), no bound on `oid_arg1`, direction user →
`oid_arg1` via `rep movsq`, 0 chaining, 0 amplification. **The mechanism is characterized and the
exploit is still missing. Those are two different gaps and solving one does not solve the other.**

**There is no public kernel exploit for 14.00 or 14.10 at all.** Relapse stops at 13.60.

## 6. Leaving the console again

**Do not close Raspberry Cube.** Leave the runner and supervisor up; they wait through the whole
`--wait` window and the supervisor restarts on rc=3.

To stop the automation, **kill the supervisor, not the runner.** The supervisor is the loop and the
runner is one iteration of it: a `kill <runner_pid>` is seen as a crash (rc=143, SIGTERM) and the
supervisor starts a new runner 120 seconds later. **Killing the runner does not stop the automation.**

```
ps -eo pid,etime,cmd | grep -E "supervise_test|auto_test_1400"
kill <supervise_test.sh PID>     # this stops it
```

**Never `pkill -f` on a pattern that appears in your own ssh command line**, which is why
`pgrep -f sweep.py` looked like it had found something.

Revert the saves to the placeholder if the account id was applied for a test:

```
python3 prepare_usb_saves.py --revert
```

The DNS rewrite stays: it is AdGuard's, and removing it breaks the browser entry.

## 7. Matrix room ID, corrected

The room ID carried in earlier notes was wrong by transcription:

| | value |
|---|---|
| wrong (in prior notes) | `!JbVcVYRPqBWEgYrdj:chill.servebeer.com` |
| **correct** | `!JbVcVUyRPqBWEgYrdj:chill.servebeer.com` |

The dropped `Uy` made every send fail with `No such room with id ... found`, and `matrix_notify.py`
masks it by falling back to a direct login that also fails (`LoginError: 'user_id' is a required
property`). Discovery method: the bot's nio store at `/opt/AGENTS/Ares/matrix/matrix_store/*.db`,
table `encryptedrooms`, column `room_id`.

**Verified delivery contract:** the primary path is the bot HTTP listener on `127.0.0.1:8772/send`.
`exit 0` from `matrix_notify.py` means the bot returned 200. Confirm independently with
`matrix_read.py "<room>" 3`. A `[vault_env] load failed (vault auth failed: 429)` line on stderr is
unrelated to delivery.
