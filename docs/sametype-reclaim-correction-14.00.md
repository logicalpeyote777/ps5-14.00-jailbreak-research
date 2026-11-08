# Il reclaim ArrayBuffer ammazza il processo, la mia sonda aveva il difetto che loro hanno già diagnosticato (PS5 14.00)

Engagement `ps5-1400-kernel`. 2026-11-07. Solo 14.00.

**Nota di reperimento:** il doc `FONTFACE_SECOND_RECLAIM_RECONCILIATION_2026-11-06.md`
**non è in `1nk1/PS5-Prolapse`** (che ha solo `docs/PROJECT_HANDOFF.md`).
È in **`ZigZagBoi1/PS5-14.10-Research`**, repo con 8 815 blob. Tutti i
riferimenti che seguono sono da lì.

## 1. Le tre affermazioni del lead, verificate

**a) Novità kind-swap: confermata.** Nessun doc upstream nomina
`sysctl`/`oid_kind`/`PRIV_SYSCTL`/`CTLFLAG` come bypass.

**b) La distinzione di forma FontFace: confermata, riga 77-78 del doc:**

| Pagina | Meccanismo stage-2 | Reclaim |
|---|---|---|
| p565 / p577 / p580 field-forge | secondo `document.fonts.load()` **sulle stesse facce** | **no** (`S2-b` = 0) |
| p599 v4f/v4i GC-destructor | **`FontFace` fresco + regola fresca per fase, GC completo tra le fasi** | **sì** (`P2:HIT` ×3, `TWO_UAF=YES`) |

> *"false as a general statement about second reclaims on 14.10"*

**c) Il blocker comune, riga 100-103:**
> *"The hard blocker named by both eras is unchanged: **no address of
> JS-owned memory** … 'buffer absolute VA unknown (**can't self-reference**)'
> … 'the two-phase UAF gives a heap leak but **not R/W or code exec**'."*

## 2. La scoperta che conta: il difetto era nella MIA sonda

**`p568_arraybuffer_768_reclaim.js` è lo stesso esperimento della mia
`reclaim-identity-1400`.** Loro sono alla versione **v12** e la testata
intestata documenta il fallimento:

```
v11 confirmed: ALL C++ methods crash on zeroed ArrayBuffer spray.
beginPath, createLinearGradient, getContextAttributes - all crash.
Only webkitBackingStorePixelRatio survives (constant return 1).

ROOT CAUSE: zeroed spray -> null vtable, null m_canvas, null m_stateStack.
Every C++ code path accesses at least one of these -> null deref -> crash.
```

**La mia v1 spruzzava ArrayBuffer e poi chiamava `alias.getTransform()`, che è un metodo C++.**

## 3. L'evidenza del crash, non l'ipotesi

`results/phase13_webkit/v704_ab768_direct_reclaim_20261028.txt`, PS5 14.10,
500 ArrayBuffer con marker `7777.77`:

```
[21:34:49] BOOT: abspray=500,marker=7777.77
[21:34:49] PRE-UAF: triggering
[21:34:49] POST-UAF: ctx=OK
[21:34:49] PRE-SPRAY: n=500
[21:34:49] POST-SPRAY: done
[21:34:49] PRE-READ: attempting-lineWidth
        <-- NESSUN POST-READ. Il log finisce qui.
```

**Il processo muore alla prima chiamata C++ dopo lo spray ArrayBuffer.**
6 beacon totali, tutti nello stesso secondo.

## 4. Il loro fix, copiato

```
NEW APPROACH: Don't spray with ArrayBuffers. Instead, immediately after the
UAF, create a SECOND CanvasRenderingContext2D on a new canvas. bmalloc
should reclaim the just-freed 768B slot. Now inner aliases the new live
context: its vtable, m_canvas, m_stateStack are all VALID. Methods should WORK.

Verification: set globalAlpha on the second context, read through inner.
If they match -> confirmed aliasing -> we have working methods on freed memory.
```

**Reclaim con lo STESSO TIPO: la vtable è valida, i metodi funzionano.**
Coerente con quanto già sapevamo dal Prolapse doc: *"reclaim only by
same-type Canvas2D contexts"*.

## 5. La sonda ricostruita prima che spari

**`reclaim-identity-1400` (v1) rimossa. `reclaim-sametype-1400` installata.**
**Motivo: se fosse sparata nella forma v1 avrebbe bruciato tempo console per
un crash già documentato da altri.**

```
FASE A  trigger UAF                        (pattern provato)
FASE B  alias locale via transform spray   (pattern provato)
FASE C  RECLAIM STESSO TIPO: ctx2 = canvas2.getContext("2d")
        verifica: ctx2.globalAlpha = 0.777 -> leggi inner.globalAlpha
FASE D  se aliased: sopravvivenza metodi C++
        beginPath / moveTo / lineTo / lineWidth set+get / globalAlpha set
FASE E  censimento puntatori attraverso l'oggetto vivo
FASE F  ArrayBuffer spray, MA dopo NON si chiama nessun metodo C++
```

**L'ArrayBuffer non è eliminato: è spostato in fase finale e dopo di esso
nessun metodo C++.** Così la v1 non muore più per ipotesi, viene testata
per quello che è, e se muore lo sappiamo dall'ultimo `STEP` registrato.

### Disciplina anti-crash

**Ogni chiamata C++ passa da `probeMethod()` che POSTa `M-PRE` prima di
eseguirla.** 5 chiamate, 1 sito di POST centralizzato. Se il processo muore,
l'ultimo `M-PRE` senza il suo `M-OK`/`M-CRASH` dice **esattamente quale
metodo ha ucciso**, non "è morto da qualche parte".

### Verdetti

| Verdetto | Significato |
|---|---|
| `SAME-TYPE-RECLAIM-ALIASED-METHODS-ALIVE` | **reclaim funziona, metodi vivi** → regione controllata |
| `SAME-TYPE-ALIASED-METHODS-LIMITED` | aliased ma i metodi muoiono → alias parziale |
| `SAME-TYPE-NO-ALIAS` | il secondo contesto non ha preso lo slot |

## 6. Cosa cambia nella lettura del blocker

**Il loro blocker, *"no address of JS-owned memory"*, resta.** Ma la
forma same-type cambia la natura di cosa si ottiene:

| | ArrayBuffer reclaim | Same-type reclaim |
|---|---|---|
| Vtable dell'oggetto nella slot | **null → crash** | **valida** |
| Metodi C++ usabili | no | **sì** |
| Regione controllata | nessuna | **sì, noi scriviamo ctx2, inner legge** |

**Se `inner.globalAlpha` legge `0.777` scritto su `ctx2`, abbiamo una
regione di memoria condivisa e controllata da entrambe le parti.** Non è
ancora un indirizzo assoluto, ma è il primo punto in cui **sappiamo cosa
c'è dentro** e **possiamo scriverci attraverso due oggetti diversi**.

## 7. Caveat firmware, stessa lezione dei deltas

**Loro sono su 14.10, noi su 14.00.** Il reclaim same-type è un meccanismo,
non un offset, ma **va verificato da noi, non eredarlo.** La forma
`fresh-face-per-phase` che loro dimostrano su 14.10 non è dimostrata su 14.00.

## 8. Stato

```
pg_tests.json -> 152 moduli
reclaim-identity-1400 : RIMOSSA (forma che sarebbe crashata)
reclaim-sametype-1400 : INSTALLATA, 7171 B, 45000 ms
backup: pg_tests.json.pre-sametype.bak
Pagina: morta, riarmo necessario
```

## 9. File

- `zz_p568_arraybuffer_768_reclaim.js`, il loro esperimento, v12 con la diagnosi
- `v704.txt`, l'evidenza del crash (6 beacon, morte a `PRE-READ`)
- `zz_FONTFACE_SECOND_RECLAIM_RECONCILIATION_2026-11-06.md`, la distinzione di forma
- `gen_sametype.py` / `sametype_module.json`, la sonda ricostruita
