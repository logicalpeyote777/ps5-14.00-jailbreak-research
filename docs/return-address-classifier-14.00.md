# Libreria di classificazione return-address — testata sul caso reale (PS5 14.00)

Engagement `ps5-1400-kernel`. 2026-11-07. Solo 14.00.

**Reframe registrato:** non *"leakare la base WebKit leggendo codice"*, ma
**"leakare la base leggendo DATI che contengono indirizzi di codice"**.
`xotext` non è un ostacolo — è la spiegazione dei nostri crash, e la
conseguenza operativa è netta: **mai passare dalla R/W su un indirizzo di
testo.**

## 1. Perché offline e non come sonda

Il bytewrite non ha ancora sparato. Costruire la sonda nuova prima di
vedere il suo verdetto significa indovinare il supporto. **La classificazione
invece è indipendente dal supporto**: si applica a qualunque lista di
candidati arrivi, ed è pronta come una chiamata invece che come un'attività.

## 2. Stato del bytewrite — non ancora eseguito

```
ultimo evento log : 17:14:41   PTRS-CTRL n=0   <- pixel probe VECCHIO, pre-fix
pg_tests.json     : 17:19:53   <- i moduli corretti sono installati DOPO
F1/F2/F3/HEAPQWORD nel log : 0 occorrenze
```

**L'ultimo `n=0` visibile è l'artefatto `ImageData.length` appena corretto,
non un dato.** Il bytewrite corretto è armed e in attesa del reopen.

## 3. Le tre regole implementate, ognuna da un run perso a monte

### 3.1 Data-word exclusion — per FREQUENZA, non per valore

Non si cerca "il valore del canary". Si esclude **ciò che si ripete in
troppi frame**:

```js
limit = max(2, floor(frameCount * 0.25))
// frameCount = 38  ->  limit = 9
```

`__stack_chk_guard` (`OFFSET_lk___stack_chk_guard = 0x000751D0`) è
l'istanza nota, ma la regola è generale: una parola replicata in molti frame
è **dato**, non ritorno. **Il canary appare in molti frame, quindi sembra un
hit forte quando è il segnale più debole che c'è.**

### 3.2 Anchor selection per semantica, non per ordine

Un'àncora nota vince sempre quando è presente. Senza àncora: il candidato
**meno replicato**, marcato `verified: false` — come fanno loro, un restore
non verificato deve dirlo forte.

**Il trampoline `0x2198D` che gli ammazzò il primo run non vince nemmeno
senza àncora**, perché la selezione è per minor ripetizione e non per
altezza del frame.

### 3.3 Type validation pre-apply

Il loro fallimento: `slot_expect + DELTAS.x` lanciò `Invalid mix of BigInt
and other type` — **dopo** che la riga sbagliata era già stata applicata e
persistita. Qui la validazione è una funzione che si chiama **prima** di
scrivere nel piano; se fallisce, non si applica nulla.

## 4. Test contro il caso reale di Prolapse

38 candidati: 25 canary + il trampoline sbagliato + il valore giusto in
lista.

```
=== CASO REALE: 38 candidati ===
input: 38   tenuti: 13   esclusi: 1   limite: 9
esclusi marcati canary: [ '751d0 x25' ]
PICK: 0x1988b  verified=true  (anchor-match)
GIUSTO? SI

=== SENZA ANCORA (il trampoline NON deve vincere) ===
PICK: 0x1988b  verified=false
il trampoline 0x2198D ha vinto? NO - bene

=== TYPE VALIDATION PRE-APPLY ===
bigint + bigint : {"ok":true}
bigint + number : {"ok":false,"reason":"type mix: base=bigint a:number"}
number + number : {"ok":true}
number + float  : {"ok":false,"reason":"type mix: base=number bad:float"}

=== SOLO CANARY: nessun candidato valido ===
tenuti: 0   pick: null
```

**Quattro proprietà verificate:**

| Proprietà | Esito |
|---|---|
| Il canary viene escluso | ✓ 25/25 esclusi per frequenza |
| Il valore giusto viene preso | ✓ `0x1988B` con àncora, `verified: true` |
| Il trampoline sbagliato non vince | ✓ nemmeno senza àncora |
| Nessun falso positivo sul solo-canary | ✓ `pick: null`, non un valore a caso |

## 5. API della libreria

```js
analyse(cands, { frameCount, anchors, maxRepeatRatio, base, size })
  -> { input, kept, excluded:[{value,count,isCanary}], limit,
       pick:{value, verified, how, count, inCodeRange} }

excludeDataWords(cands, frameCount, maxRepeatRatio) -> { kept, excluded, limit }
pickAnchor(kept, anchors)                           -> { value, verified, how }
validateDeltaTypes(base, deltas)                    -> { ok, reason }
inCodeRange(v, base, size)                          -> bool
LK_CANARY = 0x751D0
```

**`inCodeRange` è il gancio per il passo dopo:** una volta che si ha la base
di `libkernel_web`, verifica che un candidato cada davvero nel modulo — e
**che non cada in testo execute-only** prima di tentare qualsiasi lettura.

## 6. Ordine dei candidati confermato

| # | Candidato | Stato |
|---|---|---|
| 1 | Backing store del canvas | **Fase 4 del bytewrite — armed, in attesa di sparare** |
| 2 | `ArrayBuffer` nostro in cui qualcosa ritorna | pronto da costruire, replicabile senza worker |
| 3 | Stack del thread JS principale | per ultimo — per raggiungerlo serve già un puntatore allo stack |

**Il candidato 3 è circolare come primo passo. L'1 e il 2 no.**

## 7. File

- `classify.js` — libreria testata (module.exports, riusabile dalle sonde)
- `xotext-and-delta-method-14.00.md` — il reframe e la validazione di `lkfind.js`
- `imagedata-wrapper-bug-14.00.md` — il bug che rendeva falso il nostro `n=0`
