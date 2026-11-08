# PS5 firmware 14.00: jailbreak research

**Open research toward a jailbreak of PlayStation 5 firmware 14.00, reached entirely through the
system User's Guide browser.** No game installed, no loader, no USB: arbitrary JavaScript in
the guide's WebProcess and a live console.

**Status: not jailbroken.** The userland chain works and is measured. The kernel side is
characterised but not exploited. What is here is the honest state of both, with the raw output
next to every claim.

**Target:** PlayStation 5 (CFI-2000) Digital Edition, firmware 14.00
**Entry:** User's Guide browser, via DNS rewrite of `manuals.playstation.net`
**Research:** logicalpeyote, Morini Computers

---

## The headline result

**The `sysctl` kind swap that the community has used as a black box since 13.60 is not a type
confusion. It is a permission-check bypass.**

`0x80048002 → 0x70048002` leaves `CTLTYPE` (`kind & 0xf = 2`) untouched, so no type dispatch
is confused. What moves is a single `test`/`je` pair, and what that branch guards is
`PRIV_SYSCTL_WRITE`. The kernel stops asking whether you are allowed. It does not start
copying your bytes anywhere.

**A permission bypass is not a write primitive.** That distinction is the contribution, and it
narrows what the swap can be used for.

---

## What we have, on device

| | |
|---|---|
| **CVE-2026-43720** | **VULNERABLE**: re-entrancy unguarded on this build (`same=false`) |
| **Bidirectional read/write** | proven in **both directions as separate assertions** over the reclaimed object |
| **Iterator confusion** | a second, orthogonal confusion at gate level |
| **API map** | 25 Web APIs of the guide WebProcess mapped, including `sharedWorker` available while `worker` is `SecurityError` |
| **Writable OIDs** | 303 writable vs 332 read-only |

**Every link of the userland chain is confirmed:** re-entrant `getContext()` → distinct
inner/outer wrapper → same-type reclaim → bidirectional read/write. **What the chain does not
reach is an address:** it reads and writes a window it cannot locate.

## What we do not have

**Two independent gaps, and solving one does not solve the other:**

1. **A code leak is missing.** Neither we nor upstream has one.
2. **No kernel bug yielding read/write has been found.** The kind swap is a permission bypass,
   not a memory-safety violation, so finding the leak does not hand over the kernel bug.

Ten candidate routes to the leak were closed on device, each with a **different class of
evidence**, so the set does not share one failure mode that could invalidate all of them.

**The gap is not ours alone.** On 4 November 2026 Jose Coixao, the author of Prolapse, the
most prominent jailbreak candidate aimed at this firmware range, stated publicly that the AIO
memory his exploit needs cannot be corrupted here: *"for now i think we are currently out of
luck for ps5 on 14.00 and 14.10."* He names two other developers who reached the same
conclusion, and says he agrees with them. **The candidate that was expected to carry 14.00 is,
by its own author's account, stopped at the same wall this note describes.**

**The most useful of the negatives:** everywhere an engine object was looked into through a
typed interface, what came back was the type of the interface, not the memory underneath.
Three independent probes say it: float setters survive an address-shaped write, an address
spray reads back as ≈98.8 rather than as pointers, and a reversed reclaim returns 720 of 720
float-like words with zero object headers under the alias. **The canvas UAF is not a route to
the leak. It needs a different class of bug, not a better offset.**

## Kernel-side: the 14.00 artifact is in hand, the kernel image is not

A real, verified **PS5 firmware 14.00 PUP** is now on disk:

```
Path       : kernel-hunt/fw1400/ps5-sys-14.00.pup
Size       : 1 260 600 832 bytes
SHA256     : 1eb4b18451e0f064fc23b5bd4c95cae7f6489f9ad1148b5dfb0d66452a108ebc
Source     : archive.midnightchannel.net, "PS5 Official Retail System Firmware v14.00", 2026-09-18
Magic @0x00: SLB2
BLS  @0x24 : 0x4B2339D5
```

The BLS value matches the 14.00 fingerprint recorded before the file was acquired, so the
identification is a confirmation against a prior prediction rather than a label applied after
the fact.

**A decrypted 14.00 kernel image still does not exist.** The container is encrypted at Layer 1,
and the blocker is now named rather than assumed:

```
Key     : PUP container key (Layer 1)
Lives   : Titania Security Processor
Used by : encsrv_decrypt_header()
ioctl   : 0xC0184402
Device  : /dev/pup_update0
```

The key is universal, identical on every PS5 from firmware 1.0 onward, so one extraction makes
every PUP past and future decryptable on a PC. Extraction needs a jailbroken console at
**firmware 13.60 or below**, which is where Byepervisor reaches. **The 14.00 console cannot
extract the key that unlocks its own firmware.**

---

## Contents

### The paper

| File | What it is |
|---|---|
| **[`PAPER.md`](PAPER.md)** | **The full write-up**: the kind-swap characterisation, the gate chain with disassembly, the OID scan, the userland primitives with their raw output, the closed branches with their evidence classes, and the methodology. |
| **[`index.html`](index.html)** | The same paper as a **styled, readable page** (Morini Computers template). Served live at the Pages link below. |

### Research notes

| File | What it covers |
|---|---|
| [`docs/pup-1400-acquisition-and-l1-block-14.00.md`](docs/pup-1400-acquisition-and-l1-block-14.00.md) | **The 14.00 PUP acquisition and the Layer 1 block.** Byte-level verification, the named blocker, and the independent confirmation from `TitaniaPy`. |
| [`docs/CHAIN.md`](docs/CHAIN.md) | **The working chain**, with the two dead ends marked and why. Read this first if you want to know what to try next. |
| [`docs/xotext-and-delta-method-14.00.md`](docs/xotext-and-delta-method-14.00.md) | **`xotext`, execute-only text.** Why signature-scanning module text is impossible, and the reframe from *reading code* to *reading data that contains code addresses*. |
| [`docs/xotext-scope-webkit-base-derivation-14.00.md`](docs/xotext-scope-webkit-base-derivation-14.00.md) | **How the base of a module is derived without reading its code**: the working chain from a DOM element through a vtable in `.data.rel.ro` to a code address, and the scope limits of the `xotext` claim. |
| [`docs/deltas-are-family-specific-14.00.md`](docs/deltas-are-family-specific-14.00.md) | **Why the constant deltas cannot be inherited.** Computed per firmware: stable for three fields within 12.xx, different on 10.00, and `thread_list` unstable even inside 12.xx. |
| [`docs/return-address-classifier-14.00.md`](docs/return-address-classifier-14.00.md) | **Classifying return-address candidates**: frequency-based data-word exclusion (the stack canary trap), anchor selection by semantics, and type validation before apply. Validated against a real 25-of-38 candidate case. |
| [`docs/sametype-reclaim-correction-14.00.md`](docs/sametype-reclaim-correction-14.00.md) | **Why an `ArrayBuffer` spray is the wrong reclaim object**: a zeroed spray leaves a null vtable and every C++ method faults. Same-type reclaim keeps it valid. |
| [`docs/reclaim-identity-probe-14.00.md`](docs/reclaim-identity-probe-14.00.md) | The probe design for asking whether an allocated buffer is the freed object, and why the marker has to be a double rather than a byte pattern. |
| [`docs/two-phase-runner-14.00.md`](docs/two-phase-runner-14.00.md) | **The two-phase probe runner**: non-lethal census first, the lethal probe last, so one page load yields several results instead of one. |
| [`docs/CONSOLE_RUNBOOK.md`](docs/CONSOLE_RUNBOOK.md) | **Operating runbook**: how the self-driving console harness works, the differential baseline against patched Chromium, and how to leave the rig parked. |

---

## Method notes worth knowing

**A crash is a result, not noise.** A death attributed to a flaky primitive closes a line of
inquiry; the same death attributed to an execute-only page opens one. The difference is not in
the event, only in what is done with it.

**A negative is only as strong as its oracle.** A probe that never touched its subject reports
the same "nothing found" as one that looked and found nothing. Wherever possible the probes
carry a live baseline that proves the channel was working.

**A gate must be run against a known-negative before it is trusted on an unknown.** Automation
that transforms a corpus reports what it intended. Unless the output is independently counted
against the input, "0 files changed" and "145 files changed" both arrive as exit code 0.

**Frequency is evidence of persistence, not of identity.** A candidate set that clusters hard on
one value has most likely found a constant.

---

## Caveats

- The kernel characterisation is from a **13.60** dump. The console runs 14.00 and a real 14.00
  PUP is now available, but **no decrypted 14.00 kernel image exists**: the container key is
  one extraction away, on a console class that is not currently at hand. The mechanism is
  expected to carry; the offsets are 13.60-anchored and need re-anchoring.
- `SYSCTL_NR` is **199** on this kernel, not FreeBSD's 202. The community `syscall_map` uses
  FreeBSD numbering; mixing the two spaces calls the wrong syscall, and it *answers*, so it
  does not look wrong.
- Several upstream results cited here are on **14.10**, not 14.00. Mechanisms transfer;
  verification does not.

---

**Rendered paper:** <https://logicalpeyote777.github.io/ps5-14.00-jailbreak-research/>
