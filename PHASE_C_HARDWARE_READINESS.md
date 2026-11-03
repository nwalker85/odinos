# Odin OS — Phase C Physical-Hardware Readiness Assessment

**Author:** Principal Security Engineer & Verification Lead  
**Scope:** Feasibility analysis, silicon constraints, and migration plan from QEMU emulation to physical RISC-V silicon and FPGA hardware in Phase C.  
**Target Silicon Platforms:**  
1. **SiFive FU540 / FU740** (HiFive Unleashed / HiFive Unmatched)
2. **StarFive JH7110** (VisionFive 2)
3. **Kendryte K210** (Dual RV64GC with 8-entry PMP)
4. **Xilinx Artix-7 / UltraScale+** (Custom RocketChip / CVA6 soft core)

---

## 1. Physical Hardware Gap Analysis

While QEMU provides an ideal deterministic platform for developing privileged software architectures, physical silicon introduces fundamental physical and architectural differences that must be addressed prior to Phase C deployment.

```
Feature                  QEMU virt Platform (Phase B.2)   Physical Silicon (Phase C Target)
─────────────────────────────────────────────────────────────────────────────────────────────
PMP Region Granularity   Byte-exact TOR resolution        $G \ge 2$ or $G \ge 4$ (Grain size $\ge 4$ or 16 bytes)
PMP Entry Count          16 configurable entries          8 to 16 entries (e.g. Kendryte K210 has 8 entries)
PMP Execution Trap       Instant trap, 0-cycle flush      Pipeline flush, store buffer drain required
Interrupt Controller     Emulated PLIC / CLINT            Physical PLIC / ACLINT with wire-level latencies
UART Interface           16550A emulated MMIO at 0x10000000 Platform-specific (e.g. 0x10010000, 0x12000000, 0x38000000)
Boot Flow                Direct -kernel boot at 0x80000000 OpenSBI / Zero-Stage Bootloader (ZSBL) / M-Mode handoff
Cache Coherency & Fences Relaxed / No writeback delays    Hardware L1/L2 caches; mandates `fence` & `fence.i`
```

---

## 2. Key Silicon Constraints & Engineering Mitigations

### 2.1 PMP Granularity & Alignment ($G$)
- **Constraint:** In the RISC-V Privileged Specification, PMP entries in Top-of-Range (TOR) mode have an implementation-defined minimum granularity $G$. If $G > 0$, the low $G$ bits of `pmpaddr` are ignored or hardwired to zero. For example, if $G = 4$, regions must be aligned to 16-byte boundaries.
- **Mitigation:** In Phase C, the `TransitionDeed` allocator must enforce:
  $$\text{TargetOffset} \equiv 0 \pmod{2^{G+2}}, \quad \text{TargetLength} \equiv 0 \pmod{2^{G+2}}$$
  For 16-byte grain ($G=2$), capability allocations must be padded to 16-byte cache-line boundaries.

### 2.2 Cache Coherency and Store Buffers
- **Constraint:** In physical cores with out-of-order execution or store buffers, a store from U-Mode might reside in a store buffer when PMP registers are reprogrammed in M-Mode, causing delayed faults or unauthorized writes after lease expiration.
- **Mitigation:** The M-Mode `setup_pmp()` routine and `handle_trap` must issue explicit memory fences:
  ```rust
  core::arch::asm!("fence rw, rw");
  core::arch::asm!("fence.i");
  ```
  This guarantees that all in-flight store buffer entries are committed or drained before PMP configuration registers take effect.

### 2.3 Bootloader & M-Mode Execution Context
- **Constraint:** On commercial RISC-V boards (e.g. StarFive VisionFive 2), the system boots via OpenSBI in Supervisor Mode (S-Mode) by default, while Odin OS requires M-Mode to program PMP registers and handle trap vectors directly.
- **Mitigation:** Phase C will either:
  1. Boot as a bare-metal payload replacing OpenSBI directly in M-Mode via U-Boot SPL / ZSBL.
  2. Implement an OpenSBI extension (SBI SBI call) that delegates PMP programming to M-Mode firmware while running Odin OS microkernel in S-Mode. The direct M-Mode bare-metal approach is strongly preferred for sovereign security assurance.

---

## 3. Physical DRAM Wordline Gating (The Silicon Roadmap)

Phase B.2 proves that capability constraints can be enforced by CPU core PMP logic before a memory transaction leaves the core. However, the ultimate vision of Odin OS is **wordline-gated physical silicon**:

### The Phase C Hardware Target
In custom FPGA / ASIC implementations (e.g. modified RocketChip or CVA6 with custom memory controller):
1. **Wordline Gating Register:** Memory controller decodes deed leases directly from an on-chip hardware register.
2. **Physical Row-Select Suppression:** If a memory request's physical address does not match an active deed lease in the memory controller's capability table, the DRAM Row Access Strobe (RAS) / Column Access Strobe (CAS) enable line is grounded, physically preventing voltage from reaching the bitline capacitors.
3. **Hardware Vector 0x8F:** The memory controller signals a bus error directly to the CPU core, instantiating `VECTOR_TRAP_AST_BOUNDARY` (`0x8F`).

---

## 4. Phase C Hardware Milestones

1. **Milestone C.1: Commercial Board Bare-Metal Port**
   - Port `odin-kernel` to StarFive VisionFive 2 (JH7110) or SiFive HiFive Unmatched.
   - Adapt UART driver to platform MMIO address.
   - Verify 17-test matrix on physical silicon.
2. **Milestone C.2: OpenSBI-Free Direct M-Mode Boot**
   - Provide custom board support package (BSP) for flash-resident direct boot.
3. **Milestone C.3: FPGA Wordline Interlock Prototype**
   - Implement custom AXI memory interlock peripheral on Xilinx Artix-7 running soft RISC-V core.
   - Demonstrate hardware bus fault when DMA or agent attempts out-of-bounds access.
