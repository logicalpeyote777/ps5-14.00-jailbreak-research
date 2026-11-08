# Runner a due tempi — da 1 a N+1 sonde per reopen (PS5 14.00)

Engagement `ps5-1400-kernel`. 2026-11-07. Solo 14.00.

## 1. Il dato, verificato

```
righe log totali      : 4443
pg_begin (avviati)    : 105
pg_end  (completati)  : 99
tasso completamento   : 94.3 %
non completanti       : 7  (6.7%)
```

**Confermato: la pagina muore DOPO la sonda, non DURANTE.**

I 7 non completanti sono **identificabili come le sonde che innescano la UAF
letale**:

```
CVE-2026-20665 · CVE-2026-28907 · CVE-2026-43660
fontface-fullchunk-1400 · p563-verbatim-1400
pixel-readback-leak-1400 · transform-spill-1400
```

**98 moduli hanno dimostrato di completare.** Sono il budget di sonde
non letali concatenabili.

## 2. La regola di struttura, non negoziabile

**FASE 1 non deve creare la UAF.** Niente getter trick, niente oggetto
liberato, niente de-referenziazione. Solo letture su oggetti appena creati
e vivi.

**FASE 2 esegue PER ULTIMA**, quando ogni dato della fase 1 è già a casa.

**Ogni POST è eager**: un crash in fase 2 non porta via la fase 1.

## 3. Il runner installato — `batch-harvest-1400`

### FASE 1 — non letale, 4 censimenti

| | Cosa | Perché |
|---|---|---|
| **1A** | **censimento 25 API** nel WebProcess | la nostra superficie reale: canvas, offscreenCanvas, ImageData, webgl/2, wasm, worker, indexedDB, webcodecs, DOMMatrix, structuredClone, FontFace… |
| **1B** | **caccia al globale-numero** | **l'equivalente nostro di `__ps5NativeCtor`** — loro prendono la base WebKit da un globale JS che contiene un indirizzo. Scansione di tutte le proprietà di `window` per numeri che sembrano indirizzi |
| **1C** | **forma degli oggetti DOM** | prerequisito del `leakval` di Prolapse (`read8(leakval(textArea)+0x18)`): own-property di textarea/div/canvas/img/input |
| **1D** | **baseline contesto VIVO** | cosa restituisce un contesto appena creato, prima di ogni UAF — il termine di confronto per ogni lettura post-reclaim |

### FASE 2 — letale, per ultima

UAF trigger → alias → **reclaim stesso tipo** (`ctx2`) → verifica
`globalAlpha` → sopravvivenza metodi C++.

## 4. Verifiche strutturali fatte sul modulo

```
SYNTAX OK
immune a tutte e 10 feature JSC-risky
phase2() CHIAMATA dopo PHASE1-DONE : True
defineProperty solo dentro phase2   : True   <- la fase 1 NON crea UAF
M-PRE eager sui metodi C++          : True
XHR sync                            : True
25 API censite                      : True
```

**Il controllo decisivo è il terzo:** `defineProperty` — il getter che crea
la UAF — **esiste solo dentro `phase2`**. La fase 1 non può innescare la
morte per costruzione, non per attenzione.

## 5. Nota sul processo: due errori presi e verificati

**a) `node --check` fallito e io quasi non me ne accorgevo.** Il mio script
di verifica interno ha stampato "immune a tutte e 10" **su un file con
errore di sintassi**, perché i controlli sono string-based e girano comunque.
**Un check che passa su codice rotto è peggio di un check assente.**
Ora il `node --check` è a monte e blocca.

**b) Il bug era `}` invece di `});`** sulla chiusura di
`addEventListener` — classe di errore che i controlli per substring non
vedono mai.

**c) La mia prima verifica d'ordine era sbagliata:** `indexOf("phase2()")`
trovava la **definizione** (riga 141) prima della chiamata (riga 210) e
rispondeva `false` su codice corretto. Rifatta cercando la chiamata reale
(`r.lethal = phase2()`) → `true`.

## 6. Il guadagno

| | Prima | Ora |
|---|---|---|
| Sonde per reopen | 1 | **4 non letali + 1 letale = 5** |
| Informazione per reopen | 1 verdetto | 4 censimenti + 1 verdetto |
| Rischio | — | **invariato**: la letale è comunque l'ultima cosa che gira |

**Il rischio non aumenta**: la fase letale occupa la stessa posizione che
occupava prima — l'ultima. Tutto ciò che la precede è dimostrato non
in grado di uccidere.

## 7. Stato

```
pg_tests.json -> 153 moduli
batch-harvest-1400 : INSTALLATO, 10 764 B, timeout 60 000 ms
reclaim-sametype-1400 : ancora presente (la fase 2 e' la stessa logica)
backup: pg_tests.json.pre-harvest.bak
Pagina: morta, riarmo necessario
```

## 8. File

- `gen_harvest.py` / `harvest_module.json` — il runner
- `sametype-reclaim-correction-14.00.md` — la logica della fase 2
- `xotext-scope-webkit-base-derivation-14.00.md` — il contesto di 1B
