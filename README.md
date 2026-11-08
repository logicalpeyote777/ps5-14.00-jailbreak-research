# PS5 firmware 14.00 — jailbreak research

**Open research toward a jailbreak of PlayStation 5 firmware 14.00, reached entirely through the
system User's Guide browser.** No game installed, no loader, no USB — arbitrary JavaScript in
the guide's WebProcess and a live console.

**Status: not jailbroken.** The userland chain works and is measured. The kernel side is
characterised but not exploited. What is here is the honest state of both, with the raw output
next to every claim.

**Target:** PlayStation 5 (CFI-2000) Digital Edition, firmware 14.00
**Entry:** User's Guide browser, via DNS rewrite of `manuals.playstation.net`
**Research:** logicalpeyote — Morini Computers

---

## The headline result

**The `sysctl` kind swap that the community has used as a black box since 13.60 is not a type
confusion. It is a permission-check bypass.**

`0x80048002 → 0x70048002` leaves `CTLTYPE` (`kind & 0xf = 2`) untouched, so no type dispatch
is confused. What moves is a single `test`/`je` pair, and what that branch guards is
`PRIV_SYSCTL_WRITE`. The kernel stops asking whether you are allowed — it does not start
copying your bytes anywhere.

**A permission bypass is not a write primitive.** That distinction is the contribution, and it
narrows what the swap can be used for.

---

## What we have, on device

| | |
|---|---|
| **CVE-2026-43720** | **VULNERABLE** — re-entrancy unguarded on this build (`same=false`) |
| **Bidirectional read/write** | proven in **both directions as separate assertions** over the reclaimed object |
| **Iterator confusion** | a second, orthogonal confusion at gate level |
| **API map** | 25 Web APIs of the guide WebProcess mapped, including `sharedWorker` available while `worker` is `SecurityError` |
| **Writable OIDs** | 303 writable vs 332 read-only, under the corrected model |

**Every link of the userland chain is confirmed:** re-entrant `getContext()` → distinct
inner/outer wrapper → same-type reclaim → bidirectional read/write. **What the chain does not
reach is an address** — it reads and writes a window it cannot locate.

## What we do not have

**Two independent gaps, and solving one does not solve the other:**

1. **A code leak is missing.** Neither we nor upstream has one.
2. **No kernel bug yielding read/write has been found.** The kind swap is a permission bypass,
   not a memory-safety violation — so finding the leak does not hand over the kernel bug.

Seven candidate routes to the leak were closed on device, each with a **different class of
evidence**, so the set does not share one failure mode that could invalidate all seven.

---

## Contents

### The paper

| File | What it is |
|---|---|
| **[`PAPER.md`](PAPER.md)** | **The full write-up** — the kind-swap characterisation, the gate chain with disassembly, the OID scan, the userland primitives with their raw output, the closed branches with their evidence classes, and the methodology including retractions. |
| **[`index.html`](index.html)** | The same paper as a **styled, readable page** (Morini Computers template). Served live at the Pages link above. |

### Research notes

| File | What it covers |
|---|---|
| [`docs/CHAIN.md`](docs/CHAIN.md) | **The corrected working chain**, with the two dead ends from the earlier formulation marked as dead and why. Read this first if you want to know what to try next. |
| [`docs/xotext-and-delta-method-14.00.md`](docs/xotext-and-delta-method-14.00.md) | **`xotext`** — execute-only text. Why signature-scanning module text is impossible, and the reframe from *reading code* to *reading data that contains code addresses*. |
| [`docs/xotext-scope-webkit-base-derivation-14.00.md`](docs/xotext-scope-webkit-base-derivation-14.00.md) | **How the base of a module is derived without reading its code** — the working chain from a DOM element through a vtable in `.data.rel.ro` to a code address, and the scope limits of the `xotext` claim. |
| [`docs/deltas-are-family-specific-14.00.md`](docs/deltas-are-family-specific-14.00.md) | **Why the constant deltas cannot be inherited.** Computed per firmware: stable for three fields within 12.xx, different on 10.00, and `thread_list` unstable even inside 12.xx. |
| [`docs/return-address-classifier-14.00.md`](docs/return-address-classifier-14.00.md) | **Classifying return-address candidates** — frequency-based data-word exclusion (the stack canary trap), anchor selection by semantics, and type validation before apply. Validated against a real 25-of-38 candidate case. |
| [`docs/sametype-reclaim-correction-14.00.md`](docs/sametype-reclaim-correction-14.00.md) | **Why an `ArrayBuffer` spray is the wrong reclaim object** — a zeroed spray leaves a null vtable and every C++ method faults. Same-type reclaim keeps it valid. |
| [`docs/reclaim-identity-probe-14.00.md`](docs/reclaim-identity-probe-14.00.md) | The probe design for asking whether an allocated buffer is the freed object, and why the marker has to be a double rather than a byte pattern. |
| [`docs/two-phase-runner-14.00.md`](docs/two-phase-runner-14.00.md) | **The two-phase probe runner** — non-lethal census first, the lethal probe last, so one page load yields several results instead of one. |
| [`docs/CONSOLE_RUNBOOK.md`](docs/CONSOLE_RUNBOOK.md) | **Operating runbook** — how the self-driving console harness works, the differential baseline against patched Chromium, and how to leave the rig parked. |

---

## Method notes worth knowing

**A crash is a result, not noise.** Several crashes we had filed as failures turned out to be the
primitive working correctly against a protection we did not know was there.

**A negative is only as strong as its oracle.** A probe that never touched its subject reports
the same "nothing found" as one that looked and found nothing. Wherever possible the probes
carry a live baseline that proves the channel was working.

**The biggest defect was in our own tooling.** A reporting helper rewritten without a `return`
silently broke **125 of 146 probes** while they kept reporting normally. A check that passes on
broken code is worse than a check that is absent.

**Retractions are kept, not deleted.** Several earlier conclusions were wrong and are recorded as
retracted rather than quietly removed.

---

## Caveats

- The kernel characterisation is from a **13.60** dump — the only image available. The console
  runs 14.00 and no 14.00 kernel image is available. The mechanism is expected to carry; the
  offsets are 13.60-anchored and need re-anchoring.
- `SYSCTL_NR` is **199** on this kernel, not FreeBSD's 202. The community `syscall_map` uses
  FreeBSD numbering; mixing the two spaces calls the wrong syscall — and it *answers*, so it
  does not look wrong.
- Several upstream results cited here are on **14.10**, not 14.00. Mechanisms transfer;
  verification does not.

---

**Rendered paper:** <https://logicalpeyote777.github.io/ps5-14.00-jailbreak-research/>
