# PUP 14.00 acquisition and the Layer 1 block

Engagement `ps5-1400-kernel`. 2026-11-08.

**Summary: a real, verified PS5 firmware 14.00 PUP is now in hand. A decrypted 14.00 kernel
image still is not. The distance between the two is one named key with one named precondition.**

This is the largest kernel-side result of the session, and it changes the status of every static
claim in the paper from "the file does not exist" to "the file exists and here is exactly what is
missing to open it".

---

## 1. The artifact

```
Path       : kernel-hunt/fw1400/ps5-sys-14.00.pup
Size       : 1 260 600 832 bytes
SHA256     : 1eb4b18451e0f064fc23b5bd4c95cae7f6489f9ad1148b5dfb0d66452a108ebc
Source     : archive.midnightchannel.net, "PS5 Official Retail System Firmware v14.00", 2026-09-18
Magic @0x00: SLB2
BLS  @0x24 : 0x4B2339D5
```

**[verified]** All values read directly from the file on the host.

**The identification was made in the right order.** The 14.00 BLS fingerprint had already been
recorded before this file was acquired. Reading `@0x24` from the artifact (`d5 39 23 4b`,
little-endian) produced `0x4B2339D5`, which matches. That makes it a confirmation against a
prior prediction rather than a label applied after the fact.

**The archive itself is validated independently.** The 14.10 PUP, downloaded separately, has a
sha256 matching its own published 14.10 entry. The source produced a byte-correct file for one
firmware, which is what makes its 14.00 file trustworthy for the other.

## 2. What we still do not have

A **decrypted kernel image** for 14.00. The PUP is a container, and the container is encrypted.

This is the distinction that matters, and the two statements must not be collapsed into either
"we have it" or "it does not exist":

| | Status |
|---|---|
| 14.00 PUP (encrypted container) | **Acquired and verified** |
| 14.00 decrypted kernel image | **Still absent** |
| Reason for the absence | **Known and named** (see §3) |

## 3. The block: Layer 1

```
Key     : PUP container key (Layer 1)
Lives   : Titania Security Processor
Used by : encsrv_decrypt_header()
ioctl   : 0xC0184402
Device  : /dev/pup_update0
```

**The key is universal.** It is identical on every PS5 from firmware 1.0 onward. Extracted once,
every PUP past and future becomes decryptable on a PC. It is not per-console, not per-firmware,
and not rotated.

**The precondition is the console, not the cryptography.** Extraction requires a jailbroken PS5
at firmware **13.60 or below**, which is the ceiling of Byepervisor. The 14.00 console under
test cannot extract the key that unlocks its own firmware. **No console in that range is
currently available.**

## 4. The Layer 1 boundary is visible in the bytes

Comparing the 14.00 and 14.10 PUPs at offset `0x400`:

```
14.00 @0x400: 5414 f5ee 1001 0132 0400 0000 b005 e00d | f6a0 655a 93b6 ...
14.10 @0x400: 5414 f5ee 1001 0132 0400 0000 b005 e00d | 158b b56a 2a44 ...
              ^^^^^^^^^^^^^ identical in cleartext ^^^^^^^^  ^^ encrypted, different
```

**Sixteen bytes of shared cleartext header followed by immediately divergent ciphertext.** That
is the structural signature of a container key applied at a fixed offset: the header layout is
common, the payload encryption is not, and the transition point is sharp. Both files read
directly from disk.

## 5. Independent confirmation from the opposite direction

`deepkicks/TitaniaPy` ([github.com/deepkicks/TitaniaPy](https://github.com/deepkicks/TitaniaPy),
pushed 2026-10-16) built a PC-side PUP/BLS parser and tested every known key against real 14.00
and 14.10 PUPs. It reached the same wall and described the same four-layer structure:

| Layer | Purpose | Their status |
|---|---|---|
| 0 | PBKDF2 master key derivation | Solved |
| 1 | PUP container encryption | **Blocked, key not public** |
| 2 | PUP segment-level encryption | Blocked (depends on Layer 1) |
| 3 | Inner firmware encryption | Solved |

Their own summary: *"The tool is one key away from full PUP decryption."* Their extraction path
names the same device, a dump of the `pup_update0` ioctl handler, and the same precondition:
*"If you have a jailbroken PS5 on FW 13.60 or below."*

**Two independent directions, same conclusion, same named blocker.** We arrived from a console
that cannot reach the key. They arrived from a PC tool that cannot find it published. The
intersection is the answer.

## 6. What this changes for the paper

**Nothing about the scope rule, and this is not a relaxation.** Every static kernel conclusion in
the paper is drawn from the **13.60** dump and is offered as a characterisation of that kernel
plus a hypothesis about 14.00. That is unchanged and unchanged in force.

What changed is the **character of the gap**. It went from an absent file to:

1. An artifact that **exists, is identified, and is byte-verified**.
2. A blocker that is **named down to the ioctl number and the security processor**.
3. A precondition that is **specific and finite**: one jailbroken console at 13.60 or below.

**The 14.00 kernel is now one key away rather than one discovery away.** That is a materially
different position to be in, and it is worth writing down precisely because it is easy to lose:
the next person to pick this up should not have to rediscover that the file is obtainable or that
the blocker is Layer 1 rather than something harder.

## 7. What would close it

Any one of:

- A jailbroken PS5 at firmware 13.60 or below, to run the extraction against
  `/dev/pup_update0`.
- Publication of the Layer 1 key by anyone who has it.
- A software path to the Titania security processor that does not require the console, which
  nobody has demonstrated.

**Not tested by us:** the extraction itself. We have characterised the blocker and confirmed it
from two directions. We have not run a payload that reads the key.
