# I deltas sono di famiglia, non di modulo — e la stabilità è più stretta del previsto (PS5 14.00)

Engagement `ps5-1400-kernel`. 2026-11-07. Solo 14.00.

**Ricalcolati dalla tabella `EXPECT` di `tools/lkfind.js`, non ricopiati.**

## 1. Delta = X − `slot_expect`, calcolati

```
FW       sw       sj       lj       tl        pop_rsp
10.00    0x14DC   0x3A68   0x3AC1   0x4B13D  0x1B2CF   (presente)
12.00    0x162C   0x3BB8   0x3C11   0x4AA1D  ABSENT
12.40    0x162C   0x3BB8   0x3C11   0x4E9FD  ABSENT
```

## 2. Confronto con i deltas dichiarati (+0x162C / +0x3BB8 / +0x3C11)

```
10.00   DIVERSI   sw:0x14DC!=0x162C  sj:0x3A68!=0x3BB8  lj:0x3AC1!=0x3C11
12.00   UGUALI    ok ok ok
12.40   UGUALI    ok ok ok
```

**I deltas sono esatti per la famiglia 12.xx. Su 10.00 sono diversi.** Non
sono una proprietà di `libkernel_web` in generale: **sono una proprietà di
quella famiglia di build.**

## 3. La scoperta in più: la stabilità è più stretta di così

**`thread_list` NON è stabile nemmeno dentro la famiglia 12.xx:**

```
12.00 -> 0x4AA1D
12.40 -> 0x4E9FD     diversi tra loro
```

**Quindi la proposizione "i deltas sono stabili" è vera solo per 3 dei 4
campi, e solo entro 12.xx.** `thread_list` cambia tra due build della stessa
famiglia. **Chi trattasse "i deltas" come blocco unico sbaglierebbe
`thread_list` anche restando in 12.xx.**

**Regola che ne esce: la stabilità va registrata campo per campo, non per
tabella.**

| Campo | Stabile in 12.xx | Stabile tra famiglie |
|---|---|---|
| `syscall_wrapper` | ✓ | ✗ |
| `setjmp` | ✓ | ✗ |
| `longjmp` | ✓ | ✗ |
| `thread_list` | **✗** | ✗ |

## 4. `pop_rsp` come controllo negativo — funziona

```
10.00: presente a 0x343AA
12.00: ABSENT
12.40: ABSENT
```

**L'assenza di `5c c3` distingue 10.00-era da 12.xx+.** È un negativo che
dice dove guardare: se sul 14.00 lo stato del `pop_rsp` è come 12.xx, è
un indizio di stessa famiglia; se è diverso, i deltas vanno riscritti.

## 5. Identificazione della famiglia dalla dimensione del modulo

```
12.00 group A: libkernel_web = 528 364 B
12.40 group B: libkernel_web = 544 860 B
```

**La dimensione identifica il gruppo.** Se determiniamo la dimensione di
`libkernel_web` sul 14.00, sappiamo se i deltas carryano o vanno
ridefiniti.

## 6. Come va registrato — la forma esatta

**NON:** *"i deltas sono +0x162C"*

**SÌ:** *"i deltas sono +0x162C / +0x3BB8 / +0x3C11 **per la famiglia
12.xx**; per il 14.00 sono **da derivare o confermare**. `thread_list` non
è stabile nemmeno dentro 12.xx e va misurato, non ereditato."*

**Applicarli al 14.00 senza verificarli = prendere indirizzi garbage con
sicurezza.** È l'errore che non si vede: ottieni un indirizzo, ci salti, e
non sai se era quello giusto.

## 7. La via robusta: misurare il delta sul device, non eredarlo

**Se leggiamo DUE return address distinti nello stesso dump — per esempio
`slot_expect` e `syscall_wrapper` entrambi presenti in dati leggibili — il
delta lo misuriamo NOI sul 14.00** invece di eredarlo da 12.xx.

**Perché è più robusto:**

| | Ereditare | Misurare |
|---|---|---|
| Richiede il `.sprx` | sì (e non ce l'abbiamo) | **no** |
| Richiede di indovinare la famiglia | sì | **no** |
| Fallimento silenzioso | possibile | il delta misurato è un dato, non un'assunzione |
| Copre `thread_list` | ✗ (non stabile) | **✓** |

**È anche l'unico modo di coprire `thread_list`**, che non è stabile
nemmeno entro la famiglia.

## 8. Impatto sulla sonda `reclaim-identity`

La sonda armed (plan 1170) **non deriva ancora nulla** — cerca il punto di
ancoraggio. Ma il suo successo va letto con questa regola:

- Se trova **un solo** return address → i deltas restano un'assunzione, e
  vanno marcati come non verificati per 14.00.
- Se trova **due** return address distinti → **il delta si misura**, e la
  famiglia si identifica senza il `.sprx`.

**Da registrare nel parser dei risultati: contare i return address distinti,
non fermarsi al primo.**

## 9. Stato

```
Pagina: morta, serve reopen
Plan armed: 1170 reclaim-identity-1400
Rischio registrato: deltas 12.xx != 10.00 -> non assumere 14.00 = 12.xx
Mitigazione: dimensione modulo + stato pop_rsp, oppure misura sul device
Scoperta aggiuntiva: thread_list instabile anche dentro 12.xx
```

## 10. File

- `tools_lkfind.js` — tabella `EXPECT` sorgente dei calcoli
- `xotext-and-delta-method-14.00.md` — il metodo a delta
- `reclaim-identity-probe-14.00.md` — la sonda armed
