# Sonda 2 — il nostro ArrayBuffer è l'oggetto liberato? (PS5 14.00)

Engagement `ps5-1400-kernel`. 2026-11-07. Solo 14.00.

## 1. Il dato che apre la sonda

Bytewrite reale, pagina viva:

```
ALIAS idx=4   BIDIR ok=true
F1-ROUNDTRIP: bytes=1024  diff=1020  firstDiff=4  DIVERGENT
F2-CROSS    : put@inner get@alias  diff=1017  firstDiff=4  NO-CROSS
CTRL-BASE   : wrapper_len=undefined  type=ImageData  data_len=64  first=0,0,0,0,...
```

**`F1` è `put`→`get` sullo STESSO contesto e non round-tripisce.** Non è un
problema di alias: **il canvas non commitma.** Continuare a chiedere byte al
canvas è sterile indipendentemente da quale canale si usa.

**Candidato 1 (backing store canvas) chiuso:** il canale byte esiste come
API, ma il buffer non è quello reclaimed e contiene 64 byte di zero.

**Nota sul fix `.data`:** senza di esso `data_len` non sarebbe esistito e
non avremmo potuto dire che sono 64 byte di zero. **Il fix ha trasformato un
artefatto in un dato.**

## 2. Il reframe della sonda

**Non chiede byte al canvas. Chiede: il nostro ArrayBuffer è l'oggetto
liberato?**

```
1. baseline: leggo la finestra alias
2. alloco ArrayBuffer di taglia oggetto liberato (768 B per Prolapse)
3. rileggo la finestra
4. SCRIVO un marker nei NOSTRI buffer e rileggo
```

**Se `alias.getTransform().a` mostra `0x4141414141414141` — un double
scritto NOI dentro il nostro ArrayBuffer — allora controlliamo la memoria
dell'oggetto liberato.**

**È il punto di ancoraggio che manca.** Con una regione di cui conosciamo
**contenuto e posizione**, il leak slot di Prolapse
(`targetHolder.q2 = obj` → `aimFor(holderAddr + 0x20, 8)`) diventa
replicabile.

## 3. Risponde anche alla domanda "esiste UNQUEQUE puntatore?"

**L'header di un ArrayBuffer contiene un data pointer.** Se lo leggiamo
attraverso l'alias, quel puntatore è nostro. La sonda fa il **censimento
puntatori** su baseline e post-reclaim.

## 4. Verdetti

| Verdetto | Significato |
|---|---|
| `OUR-BUFFER-IS-THE-FREE-OBJECT` | **il reclaim funziona** → punto di ancoraggio acquisito |
| `POINTER-FOUND-IN-WINDOW` | nessun reclaim ma c'è un puntatore → si parte da lì |
| `NO-RECLAIM-NO-POINTER` | **nessun ancoraggio in memoria** — il problema non è la ricerca del leak ma la sua assenza, e va trattato come tale |

## 5. Dettagli tecnici

```
4 taglie: 768, 512, 1024, 192  x 16 buffer = 39 936 B   (prudente vs OOM)
marker: 0x4141414141414141 = double 2261634.5098
        riconoscibile e non confondibile con float64 semantici del canvas
identificatore per buffer: byte (si*16+k) -> si sa QUALE buffer ha preso lo slot
POST eager per ogni slot letto: un crash non porta via il dato
XHR sync, immune a 10/10 feature JSC-risky, syntax OK
backup: pg_tests.json.pre-reclaim.bak
```

**Perché il marker è un double e non un byte:** la finestra alias si legge
solo attraverso accessors float64. Un marker byte non sarebbe osservabile;
`0x4141414141414141` è un double valido e distintivo che attraversa il
canale float64 restando riconoscibile bit per bit.

## 6. Stato

```
pg_tests.json -> 152 moduli, scrivibile
reclaim-identity-1400: 7398 B, timeout_ms 45000
candidato 1 (canvas)   : CHIUSO - canale byte non aliased, 64 B di zero
candidato 2 (leak slot): QUESTO
candidato 3 (stack JS) : per ultimo, circolare
spill / ntfusion-obj   : ancora in coda
```

## 7. Se esce `NO-RECLAIM-NO-POINTER`

Non è "non abbiamo ancora cercato". È: **non esiste un punto di ancoraggio
in memoria leggibile con la primitiva attuale.** In quel caso la domanda
cambia natura e diventa: *la primitiva Canvas alias è strutturalmente troppo
stretta per qualsiasi leak, e serve un'altra classe di primitiva* — non un
altro offset, non un altro canale.

## 8. File

- `gen_reclaim.py` / `reclaim_module.json` — sonda installata
- `return-address-classifier-14.00.md` — la classificazione già pronta per i candidati
- `xotext-and-delta-method-14.00.md` — il metodo a delta da replicare dopo il leak
