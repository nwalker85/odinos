# Odin OS Phase B.3 — PMP Architecture & Boundary Verification Audit

**Author:** Principal Kernel Security Engineer & Independent Research Verification Lead  
**Scope:** RISC-V Privileged Architecture (PMP), TOR Mechanics, Boundary Crossing, Misalignment Disambiguation, and Hardware Context Integrity  
**Reference Specification:** RISC-V Instruction Set Manual, Volume II: Privileged Architecture, Version 20211203 (Section 3.7: Physical Memory Protection)  

---

## 1. PMP Configuration & Priority Resolution

In RISC-V, Physical Memory Protection (PMP) entries are evaluated in strict numerical priority order ($0 \rightarrow N-1$), where Entry 0 has the highest priority.

### 1.1 The Implemented 5-Active PMP Layout

```
PMP Entry   Address Register (`pmpaddrX`)           Mode   Privileges   Covered Physical Address Range
─────────────────────────────────────────────────────────────────────────────────────────────────────────────
Entry 0     pmpaddr0 = 0x80010000 >> 2              OFF    ---          Base delimiter for User Code TOR
Entry 1     pmpaddr1 = 0x80018000 >> 2              TOR    R - X (0x0D) 0x80010000 .. 0x80018000 (Agent Code)
Entry 2     pmpaddr2 = 0x80020000 >> 2              TOR    R W - (0x0B) 0x80018000 .. 0x80020000 (Agent Stack)
Entry 3     pmpaddr3 = lease_start >> 2             OFF    ---          Base delimiter for Dynamic Lease TOR
Entry 4     pmpaddr4 = lease_end >> 2               TOR    R W - (0x0B) lease_start .. lease_end (Active Lease)
Entry 5..7  pmpaddr5..7 = 0                         OFF    ---          Inactive
Unmatched   All other physical addresses            N/A    --- (0x00)   Hardware Default Deny (WE = 0)
```

### 1.2 Top-of-Range (TOR) Matching Invariant
For entry $i$ configured in TOR mode (`pmpcfg.A = 01`):
- The lower address bound is $L_i = \text{pmpaddr}_{i-1} \ll 2$ (or $0$ if $i = 0$).
- The upper address bound is $U_i = \text{pmpaddr}_i \ll 2$.
- An access to address range $[A, A + \text{width})$ matches entry $i$ if and only if:
  $$L_i \le A \quad \text{and} \quad A + \text{width} \le U_i$$
- If an access matches entry $i$, the permissions in $\text{pmpcfg}_i$ are enforced.
- If an access fails to match any entry, in U-Mode with $L=0$, the access is **denied by default**.

---

## 2. Disambiguation of Test 10: Multi-Byte Boundary Crossing vs Misalignment

### 2.1 The Critical Architectural Question
Phase B.2 reports that a 4-byte store (`sw`) at `0x8002005E` crosses the lease boundary (`0x80020060`) and triggers `mcause = 7` (Store Access Fault), leaving zero bytes committed.

Address `0x8002005E` is aligned to 2 bytes ($0x5E \equiv 2 \pmod 4$), but is **not** naturally aligned for a 4-byte word ($0x5E \not\equiv 0 \pmod 4$).

Is the observed trap caused by:
1. PMP boundary enforcement?
2. Misaligned-access trap (`mcause = 6`)?
3. QEMU-specific TCG emulation behavior?

### 2.2 Mathematical Proof of Natural Alignment Boundary Invariant
**Theorem:** *A naturally aligned memory access cannot straddle a naturally aligned boundary.*
- Let boundary $B$ be aligned to width $W$, such that $B \equiv 0 \pmod W$.
- Let address $A$ be naturally aligned to width $W$, such that $A \equiv 0 \pmod W$.
- If $A < B$, then because both $A$ and $B$ are multiples of $W$:
  $$B - A \ge W \implies A + W \le B$$
- Therefore, the entire span $[A, A + W)$ lies strictly on or below boundary $B$. It cannot cross $B$.
- **Corollary:** Any memory access instruction that straddles an aligned boundary $B$ **must necessarily be an unaligned access**.

### 2.3 Empirical Isolation in QEMU `virt`
To isolate the exact cause of `mcause = 7` in Test 10:
1. **Misaligned Store Inside Lease (`0x80020052`):**
   - Address `0x80020052` is misaligned to 4 bytes ($0x52 \equiv 2 \pmod 4$), but the 4-byte span $[0x52, 0x56)$ lies entirely inside the lease $[0x40, 0x60)$.
   - In QEMU `virt` (and physical cores supporting hardware misaligned access), storing `0x12345678` at `0x80020052` **succeeds without fault**. No `mcause = 6` is raised.
2. **Straddling Store (`0x8002005E`):**
   - The hardware splits the 4-byte access into constituent byte or halfword transfers:
     - Transfer 1: `0x8002005E .. 0x80020060` (Within Entry 4, authorized).
     - Transfer 2: `0x80020060 .. 0x80020062` (Outside Entry 4, falls into Default Deny).
   - Transfer 2 evaluates against PMP and fails the matching inequality $A + \text{width} \le U_4$.
   - The CPU raises `mcause = 7` (Store Access Fault).
   - Because RISC-V exceptions on memory accesses are precise, the entire instruction aborts: **Transfer 1 is squashed before commit**, leaving bytes `0x5E` and `0x5F` completely unmodified (`0x00`).

**Conclusion:** The observed fault in Test 10 is **genuinely a PMP Store Access Fault (`mcause = 7`)**, not a misaligned access trap (`mcause = 6`).

---

## 3. Register & Hardware Context Integrity

### 3.1 Privileged `mscratch` Context Isolation
When switching between U-Mode and M-Mode:
- In U-Mode, `mscratch` holds the base pointer to the privileged kernel stack (`0x8000FFF8`).
- Upon `ecall` or hardware fault, `trap_entry` executes:
  ```assembly
  csrrw sp, mscratch, sp
  ```
- This atomically swaps the untrusted user stack pointer (`sp`) with the privileged kernel stack pointer.
- `trap_entry` preserves all 32 integer registers onto the kernel stack frame.
- While in M-Mode, `mscratch` is cleared to `0`. If an unexpected nested trap occurs, `bnez sp, 1f` detects `sp == 0` and avoids corrupting the user stack pointer.
- On `mret`, all registers are restored, and `csrrw sp, mscratch, sp` restores the user stack pointer.

### 3.2 W^X Instruction Fetch Recovery (`mcause = 1`)
If user mode attempts to execute from the non-executable user stack (`0x80018100`), PMP raises `mcause = 1`.
If the kernel merely increments `mepc` by 4, `mepc` remains within the non-executable stack (`0x80018104`), causing an infinite trap cascade.
Odin OS solves this by inspecting `mepc`:
```rust
if mcause == 1 && mepc >= USER_STACK_START as u64 && mepc < USER_STACK_END as u64 {
    unsafe { core::arch::asm!("csrw mepc, {0}", in(reg) frame.ra); }
    return;
}
```
Execution is safely returned to the caller's return address in `.user_text`, maintaining full system availability and strict W^X enforcement.
