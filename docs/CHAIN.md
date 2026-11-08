# CATENA CORRETTA — PS5 14.00 (aggiornata 2026-11-07, round 26)

**Questo file sostituisce la "catena di lavoro attuale" dell'obiettivo del goal,
che contiene due passi CHIUSI. Se leggi questo file, ignora i passi (2) e (3)
dell'obiettivo: sono morti, non "difficili".**

## I due passi morti dell'obiettivo

| Passo dell'obiettivo | Perche' e' morto | Evidenza |
|---|---|---|
| **(2) lettura a offset arbitrario via forge del lineDash Vector** | `NO-REACHABLE-OFFSET`. L'oracolo vivo dice `baseline: 4` e `bidirectional: true`, ma il forge non raggiunge offset arbitrari. | `probe_log.jsonl`, modulo lineDash, UA PS5/14.00 |
| **(3) scan pattern byte (5f c3 / 5e c3 / ...) per ricostruire wk_gadgetmap** | Ucciso da **xotext** (execute-only text) + dal fatto che **chi ha il jailbreak funzionante non ha mai letto un byte di codice WebKit**. | `xotext-scope-webkit-base-derivation-14.00.md`; Prolapse `main.js:158-212` |

## La catena corretta

```
[1] ANCORAGGIO IN MEMORIA LEGGIBILE   <-- SIAMO QUI. plan 1189 reclaim-sametype-1400
     Domanda: il nostro oggetto reclaimed e' una regione di cui conosciamo
     contenuto E posizione?
     Forma giusta: RECLAIM STESSO TIPO (secondo CanvasRenderingContext2D),
     NON ArrayBuffer spray.
     Perche': zeroed ArrayBuffer spray -> null vtable -> OGNI metodo C++ crasha
     (documentato upstream a v12: p568_arraybuffer_768_reclaim.js).

[2] leakval  ->  vtable (.data.rel.ro = DATI, non testo)  ->  base WebKit
     Catena reale di chi funziona:
       DOM element -> leakval -> +0x18 -> read8 -> vtable -> indirizzo di codice
     Zero lettura di codice. Il ramo legacy vtable-only ha fired 0 volte in 81 run:
     serve il percorso host-constructor (__ps5NativeCtor) con validazione
     banda-moduli + allineamento pagina (0x800000000..0x900000000, %0x4000==0).

[3] syscall  ->  return-address + DELTAS MISURATI, non ereditati
     syscall_wrapper = slot_expect + delta.
     ATENZIONE: i deltas NON sono universali.
       12.xx: sw +0x162C  sj +0x3BB8  lj +0x3C11   (stabili tra 12.00 e 12.40)
       10.00: sw +0x14DC  sj +0x3A68  lj +0x3AC1   (DIVERSI)
       thread_list: 12.00=0x4AA1D  12.40=0x4E9FD   (instabile ANCHE dentro 12.xx)
     La stabilita' e' una proprieta' del CAMPO, non della tabella.
     Per il 14.00: MISURARE, non ereditare. Servono 2 return address distinti.
     Firma syscall: 49 89 ca 0f 05 c3 (mov r10,rcx; syscall; ret)
     Convenzione: rva = file_off - 0x4000

[4] fuzz kernel 14.00 vivo -> trova il bug kernel
[5] kernel r/w -> jailbreak
```

## Il blocker comune con upstream (convergenza verificata 2026-11-07)

> *"The hard blocker named by both eras is unchanged: **no address of JS-owned
> memory**. p599 leaks engine addresses (T1, W1, T2, W2) only."*
> *"buffer absolute VA unknown (**can't self-reference**)"*
> *"the two-phase UAF gives a heap leak but **not R/W or code exec**."*

**Loro (ZigZagBoi1, 2901 probe, jailbreak funzionante su altre versioni) sono
fermi allo stesso punto nostro. Nessuno dei due ha l'indirizzo di memoria JS-owned.**

## Branchi chiusi con evidenza (NON riaprire)

1. **FontFace UAF** — crash dentro `document.fonts.load()`, 15 run verbatim upstream.
   **Nota: chiuso per LA NOSTRA FORMA** (secondo `load()` sulle stesse facce =
   `S2-b`=0, identico al loro). **La forma `fresh-face-per-phase + GC` completo
   NON e' mai stata provata da noi e loro la dimostrano funzionante su 14.10.**
2. **lineDash Vector m_size** — `NO-REACHABLE-OFFSET`, oracolo vivo `baseline: 4`
3. **alias-window pointer deref** — `NO-POINTER-IN-WINDOW`, 12 slot bit grezzi
4. **vtable code-slot** — `slots=88 codeish=0`
5. **setter float64 come canale di puntatore** — `SETTER-NORMALIZES-DENORMAL`
   (FTZ azzera nel path del setter, non nella rappresentazione)
6. **canvas backing store** — `data_len=64` tutto zero, `putImageData` non commitma
7. **ArrayBuffer spray + metodo C++** — null vtable, crash (upstream v12)

## Vincoli operativi

- WebProcess guida: `worker`=SecurityError (Capsicum), no wasm/webgl/indexedDB
- OOM su spray >~2.3 KB
- **La pagina muore dopo ogni UAF: ogni sonda costa un reopen fisico**
- Mai `sudo` sui file di stato probe (flippa ownership e blocca il teammate)
- Loro su 14.10, noi su 14.00: **i meccanismi si trasferiscono, le verifiche no**

## Novita' nostra (verificata 2026-11-07)

**Caratterizzazione dello swap `oid_kind` come permission-check bypass
(non type confusion).** Cerca nel listing completo del repo upstream piu' attivo:
**nessun doc nomina `sysctl` / `oid_kind` / `PRIV_SYSCTL` / `CTLFLAG` / swap.**
Paper: 11 728 parole, md5 `7b1e83cc00c02d751c87c522a448ad62`.
