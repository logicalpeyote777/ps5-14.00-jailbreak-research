# xotext: solo libkernel, e LORO non leggono mai testo WebKit (PS5 14.00)

Engagement `ps5-1400-kernel`. 2026-11-07. Solo 14.00.

**Domanda del lead:** il nostro `xotext-and-delta-method-14.00.md` generalizza
a *"mai leggere codice con la R/W"*, ma la fonte parla di `libkernel`.
Anche il testo WebKit è xotext?

**Risposta corta: la fonte parla solo di libkernel. Ma la risposta utile è
che il metodo funzionante non legge mai testo WebKit, né codice di alcun
modulo, quindi la domanda non si pone.**

## 1. Le uniche due occorrenze di `xotext`, entrambe su libkernel

```
riga 381: "Signature-scanning libkernel text is impossible (the libraries
           are xotext; reading code through the R/W primitive faults
           and kills the process)."
riga 853: "Do not try to read libkernel *text* to signature-scan.
           The libraries are xotext; ... Read the *stack*."
```

**Nessuna menzione di WebKit insieme a xotext.** Il nostro doc ha
generalizzato oltre la fonte. **Correzione: il divieto dichiarato è per
libkernel.**

## 2. Come loro derivano la base WebKit, `main.js:158-212`

```js
let textArea = document.createElement("textarea");
let textAreaVtPtr = p.read8(p.leakval(textArea).add32(0x18));
let textAreaVtable = p.read8(textAreaVtPtr);
```

### Percorso attivo su 9.00+, zero lettura di codice

```js
const ctor = globalThis.__ps5NativeCtor;
for (const hc of OFFSET_wk_host_constructor_candidates) {
    const wb = ctor - hc;
    if (wb >= 0x800000000 && wb < 0x900000000 && wb % 0x4000 === 0) {
        libSceNKWebKitBase = new int64(wb % 0x100000000,
                                      Math.floor(wb / 0x100000000));
        break;
    }
}
```

**Un globale JS che contiene un indirizzo di codice, meno un candidato, con
validazione.** Nessun byte di testo toccato. `core.js:950` scrive
`globalThis.__ps5NativeCtor = nativeConstructorAddress`.

### Percorso legacy pre-9.00, legge la VTABLE, non il testo

```js
libSceNKWebKitBase = p.read8(textAreaVtable)
                     .sub32(OFFSET_wk_vtable_first_element);
```

**La vtable vive in `.data.rel.ro`: è dati, non testo execute-only.** E il
handoff registra che **questo ramo ha fired 0 volte in 81 run registrati.**

## 3. La risposta

**Non hanno mai letto un byte di codice WebKit.** Quindi:

- **non c'è evidenza che il testo WebKit sia leggibile;**
- **non c'è bisogno che lo sia**, il metodo non lo tocca mai.

**Il loro metodo è interamente "leggere l'INDIRIZZO del codice dai dati",
mai "leggere il codice":**

```
DOM element → leakval → +0x18 → read8 → vtable (DATA) → indirizzo di codice
```

**È il reframe già posto, con la catena concreta.**

## 4. Cosa possiamo e non possiamo affermare

| Proposizione | Stato |
|---|---|
| `libkernel_web` text è xotext | **affermato dalla fonte** |
| Testo WebKit è xotext | **non affermato; non testato da loro** |
| Il metodo funzionante richiede di leggere testo di codice | **falso, non lo legge mai** |

**Non possiamo affermare dal materiale che WebKit sia xotext. Possiamo
affermare una cosa più utile: non ci serve saperlo.**

## 5. Due cose da rubare, immediatamente riutilizzabili

### A. Validazione del base candidate

```js
wb >= 0x800000000 && wb < 0x900000000 && wb % 0x4000 === 0
```

*"so a wrong one is rejected rather than used"*, **banda moduli +
allineamento pagina.** Filtro diretto per i nostri candidati return-address;
si aggiunge alla libreria `classify.js`.

### B. La disciplina del rifiuto, parla direttamente al problema deltas

> *"subtracting 0 yields the raw first-vtable-entry pointer as if it were
> the module base. Every gadget and syscall is then derived from a wrong
> base and the page dies with no usable message. **Refuse instead: a loud
> failure here is worth far more than a plausible wrong number.**"*

**È esattamente il rischio dei deltas ereditati registrato ieri.** Loro si
rifiutano di produrre un numero plausibile e sbagliato. **Noi: se non
misuriamo il delta, rifiutiamo di applicarlo**, non lo ereditiamo con
aria convinta.

Nota di coerenza: `OFFSET_wk_vtable_first_element = 0  // needs a console`
è segnato come mancante anche per 13.60, **è il motivo per cui usano il
percorso host-constructor.** Un buco nella tabella offsets, gestito
cambiando metodo invece di tirare a indovinare.

## 6. Impatto sulla strategia

| | |
|---|---|
| Via "scan testo WebKit per gadget" | **non provata, ma non è la via di chi funziona.** Loro non l'hanno mai tentata |
| Via "indirizzo di codice dai dati" | **è LA via funzionante, con catena concreta** |
| `__ps5NativeCtor` | un globale JS che espone un indirizzo di codice, **da cercare il nostro equivalente** |

## 7. La prossima domanda concreta per la sonda

**Esiste un globale JS nella guida che espone un indirizzo di codice?**

Loro ce l'hanno perché `core.js` lo scrive. Noi non lo abbiamo, ma
possiamo cercare un analogo: **un oggetto JS il cui `+0x18` porta a una
vtable contenente indirizzi WebKit.** Quella vtable è dati leggibili, e il
primo entry è un puntatore di codice che non richiede di leggere codice.

**Quello è il nostro `leakval` senza worker.**

## 8. Correzione da applicare ai nostri file

In `xotext-and-delta-method-14.00.md`: sostituire *"mai leggere codice
con la R/W"* con **"mai leggere testo di codice con la R/W, e non serve:
si legge l'indirizzo del codice dai dati (vtable, globali, stack)."**

## 9. File

- `main.js` righe 158-212, la catena di derivazione
- `core.js:950`, dove scrivono `__ps5NativeCtor`
- `offsets_13.60.js:28`, `OFFSET_wk_vtable_first_element = 0 // needs a console`
- `classify.js`, dove aggiungere il filtro banda + allineamento
