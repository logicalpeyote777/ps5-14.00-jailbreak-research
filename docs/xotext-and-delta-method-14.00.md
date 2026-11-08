# xotext e il metodo a delta, il piano di scan del testo era sbagliato (PS5 14.00)

Engagement `ps5-1400-kernel`. 2026-11-07. Solo 14.00.

**Fonte:** `1nk1/PS5-Prolapse` `docs/PROJECT_HANDOFF.md` §9.2, riga 899,
e `tools/lkfind.js` (10 734 B). Loro: jailbreak funzionante e
hardware-verified su 13.60.

## 1. Il piano statico è bloccato anche per loro

> *"It needs a real sprx; **there is no 13.60 one locally, which is
> precisely why the runtime calibrate tile exists.**"*

Verifica sul nostro host:

```
find /opt/AGENTS/Ares -iname "*.sprx"   -> 0 risultati
ps5-sys.pup  1 261 408 256 B   (L1 cifrato: 8 chiavi, tutte HIGH_ENTROPY)
ps5-rec.pup  1 418 890 240 B
strings ps5-sys.pup | grep .sprx -> nessuna stringa leggibile
```

**Il path "estrai il `.sprx` dal PUP e farci girare `lkfind.js`" non è
praticabile da noi, e non lo è nemmeno per chi il jailbreak ce l'ha
funzionante.**

## 2. Il testo è execute-only, lo scan del testo è impossibile

> *"Signature-scanning libkernel **text** is impossible (the libraries are
> **xotext**; reading code through the R/W primitive **faults and kills the
> process**)."*

**Questo uccide il nostro piano storico**, *"scan del testo WebKit per
`5f c3` / `5e c3` / `5a c3` / `59 c3` per ricostruire la `wk_gadgetmap`"*, e **potrebbe spiegare diversi dei nostri crash**: non lettura sbagliata, ma
lettura di una pagina che non è leggibile per costruzione.

**CORREZIONE (verificata dopo):** la fonte parla **solo di `libkernel`**.
Non c'è menzione di WebKit insieme a xotext. **Non affermiamo che il testo
WebKit sia xotext: non è testato da loro.** Ciò che sappiamo è più utile, il loro metodo **non legge mai testo di codice**: la base WebKit viene da
`__ps5NativeCtor` (globale JS) o dalla vtable in `.data.rel.ro`, che è
dati. Vedi `xotext-scope-webkit-base-derivation-14.00.md`.

## 3. Il loro metodo: non si scanna codice, si legge il ritorno

> *"But the **parked stack is readable data**, and the return address sitting
> in it **is** `slot_expect`."*

Si legge lo **stack** (dati leggibili), si trova un **return address** e lo
si usa come àncora. Tutto il resto si deriva a **delta costanti**, identici
in entrambi i gruppi 12.x:

```
syscall_wrapper - slot_expect = +0x162C
setjmp          - slot_expect = +0x3BB8
longjmp         - slot_expect = +0x3C11
```

**Nessuno scan di codice execute-only. Un indirizzo letto dallo stack + una
costante.**

## 4. Tre dettagli che sono costati run veri, da copiare

| | |
|---|---|
| **Anchor-first pick** | Il primo picker scelse il frame più alto: `0x2198D`, il **thread-entry trampoline**, semantica sbagliata. Il valore giusto `0x1988B` era nella lista di candidati tutto il tempo (frame-validated a `stack+0x7fc28`). Un àncora nota vince sempre quando è presente. |
| **Data-word exclusion** | **25 candidati su 38** erano `libkernel+0x751D0` = **`__stack_chk_guard`**, una parola *di dati* copiata in molti frame, **non** un return address. Va collassata ed esclusa. Confermato indipendentemente da `OFFSET_lk___stack_chk_guard`. |
| **BigInt discipline** | `slot_expect + DELTAS.x` lanciò `Invalid mix of BigInt and other type`, e lo lanciò **dopo** che la riga sbagliata era già stata applicata e persistita. I delta sono BigInt literal e `JSON.stringify` richiede un replacer. |

**Il secondo è la trappola che avremmo preso in pieno:** scansionando lo
stack per "valori che sembrano puntatori" il **65% dei candidati sarebbe
stato il canary dello stack**, non un return address.

## 5. Validazione di `lkfind.js`, fatta ora, 6/6

Costruita immagine sintetica con le firme ai offset noti di 10.00
(`file_off = rva + 0x4000`):

```
[ok]   syscall_wrapper  expected 0x1A5B7  got 0x1A5B7
[ok]   setjmp           expected 0x1CB43  got 0x1CB43
[ok]   longjmp          expected 0x1CB9C  got 0x1CB9C
[ok]   slot_expect      expected 0x190DB  got 0x190DB
[ok]   thread_list      expected 0x64218  got 0x64218
[ok]   pop_rsp          expected 0x343AA  got 0x343AA

METHOD VALIDATED on 10.00 (6/6). A row produced for another firmware
by this tool is now trustworthy.
```

**La disciplina del validatore è esemplare e l'abbiamo vista all'opera:** al
primo tentativo `thread_list` era `absent` perché il `lea rax,[rip+X]` era
stato messo a 64 byte prima della firma invece che **entro i 16 richiesti**.
Il tool ha risposto:

```
METHOD NOT VALIDATED (1 mismatch). Do NOT trust a row from this run:
check the image, the --strip convention, and that the file really is libkernel_web.
```

**Rifiuta il run anche con 5/6 match.** È la stessa disciplina del §7.8
applicata a monte, e qui è *nel tool*, non nella nostra attenzione.

## 6. Il blocco nostro per replicare il calibrate

**Il metodo di Prolapse legge lo stack di un worker. Loro hanno
`worker_rop`.** Noi no: `worker` è **SecurityError (Capsicum)** nel
WebProcess della guida.

**Domanda che decide il prossimo passo: qual è il nostro stack leggibile?**

| # | Candidato | Stato |
|---|---|---|
| 1 | Stack del thread principale JS | da verificare se raggiungibile con la R/W |
| 2 | `ArrayBuffer` allocato da noi in cui qualcosa ritorna, analogo del "parked stack" | da costruire |
| 3 | Backing store del canvas | già sotto test con `pixel-bytewrite` |

**Se uno dei tre è leggibile e contiene un return address di
`libkernel_web`, i delta danno `syscall_wrapper` senza toccare codice
execute-only.**

## 7. Cosa resta valido del piano firme

Le **firme restano l'asset giusto**, cambia il **supporto** su cui
applicarle:

| | Prima | Ora |
|---|---|---|
| Target | testo WebKit / testo libkernel | **stack e dati leggibili** |
| Metodo | scan di byte pattern nel codice | **return address + delta costanti** |
| Vincolo |, | **xotext: mai leggere codice con la R/W** |

**`pop_rsp` come controllo negativo resta prezioso:** la sua assenza da
`libkernel_web` in 12.xx è ciò che dice che il `pop rsp` va preso da
WebKit. Un negativo che indica dove guardare.

## 8. File

- `tools_lkfind.js`, scanner validato 6/6
- `docs_PROJECT_HANDOFF.md`, 52 827 B, §9.2 è il pezzo chiave
- `rop.js` (19 165 B), `syscalls.js` (16 469 B), scaricati, da leggere
- `/tmp/lkw_synth_1000c.sprx`, immagine di validazione
