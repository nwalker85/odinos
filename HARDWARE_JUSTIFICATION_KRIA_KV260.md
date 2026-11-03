# Odin OS: Architecture Summary & Hardware Justification
## Bridging Software Capability Verification to Physical Silicon Gating with the AMD Kria KV260

**Author:** Nathan Walker (@nwalker85)  
**Platform:** Odin OS / Ravenhelm Research  
**Document Purpose:** Architectural synthesis of current achievements and engineering justification for acquiring the AMD Kria KV260 FPGA/MPSoC platform.  
**Target Architecture:** 64-bit RISC-V (`RV64GC`) + AXI Memory Interlock + Zynq UltraScale+ MPSoC  

---

## 1. Executive Summary: What Has Been Built

Over Phases B.1 through B.3, **Odin OS** was built and verified from the ground up as a bare-metal, zero-allocation (`#![no_std]`) 64-bit RISC-V microkernel. It establishes a new computing paradigm for autonomous AI agents governed by a single axiom:

> **"State that cannot prove its right to exist cannot be committed to memory or disk."**

Rather than relying on natural language prompts, heuristic guardrails, or user-space software sandboxes—all of which are vulnerable to prompt injection, semantic jailbreaks, and memory-state corruption—Odin OS pins the agent's authority directly into CPU memory protection hardware.

```
┌────────────────────────────────────────────────────────────────────────┐
│                       WHAT IS PROVEN TODAY (PHASE B.3)                 │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Cryptographic Authority Verification: Pure #![no_std] RFC 8032      │
│    Ed25519 signature checks (zero heap allocations) against a pinned   │
│    root public key in M-Mode ROM.                                      │
│                                                                        │
│ 2. Spatial Capability Leases: 256-byte cache-line aligned binary       │
│    TransitionDeeds that open temporary Top-of-Range (TOR) PMP windows   │
│    for authorized Abstract Syntax Tree (AST) mutation slices.          │
│                                                                        │
│ 3. Bi-Directional W^X Enforcement: Agent executable code is strictly   │
│    R-X (store attempts fault with mcause = 7); agent stack is strictly │
│    RW- (shellcode fetch attempts fault with mcause = 1 and redirect).  │
│                                                                        │
│ 4. Deterministic Adversarial Matrix: 17 empirical invariant tests     │
│    passing bare-metal in QEMU with 100% hardware enforcement.          │
│                                                                        │
│ 5. Machine-Checked Formal SMT Verification: Z3 (v5.3.1) proofs         │
│    mathematically confirming integer overflow immunity, privileged     │
│    memory disjointness, and anti-replay sequence monotonicity.         │
│                                                                        │
│ 6. End-to-End Neural Coupling: Live local inference with Gemma 4,      │
│    demonstrating single-cycle authorized commits alongside instant     │
│    hardware halts on out-of-bounds prompt injections (0 bits flipped). │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. The Architectural Unification: The Supergraph Across Space & Time

As formalized in **ADR-SPACESHIP** (*The Supergraph Across Space and Time*), Odin OS is not merely an isolated memory manager; it is the **atomic physical-leaf reference monitor for a causal, partitioned graph-of-graphs**.

In distributed or disconnected environments (a cislunar spacecraft, a lunar rover, or a partitioned edge vehicle like Sleipner):
1. **Causal Horizon Constraint:** A node can only act on evidence and authority present within its local causal past: $\text{Evidence}(d) \subseteq \text{Reach}_i(t)$.
2. **"Promise-to-log later" is NOT authority now:** If a required central authority (Vór) is unreachable and no bounded offline mandate exists, the transition must fail closed.
3. **Graph Traversal as Memory Access:** A state mutation is a directed edge in an AST / causal DAG. 

In Odin OS, a `TransitionDeed` bridges the graph to the CPU:
- **`prev_deed_hash` & `anchor_id`**: Specify the exact causal parent and target node in the global graph.
- **`target_offset` & `target_length`**: Project that graph node onto physical DRAM addresses.
- **CPU Comparators**: Ensure the agent can write **only** to the active node in the traversal. If the agent hallucinates or attempts an unauthorized hop, the bus cycle is physically aborted.

---

## 3. The Ceiling of Emulation & Fixed-Silicon Single Board Computers

To advance Odin OS to physical silicon reality, we reach the limits of what software simulation and commodity Single Board Computers (SBCs) can provide.

### The Limitation of QEMU
QEMU is an instruction-level emulator running in software on host CPUs:
- It abstracts away memory bus timing, electrical signaling, and physical memory controllers.
- It models idealized PMP behavior with byte-exact granularity ($G=0$).
- It cannot prove that physical electrical charge was withheld from DRAM capacitors.

### The Limitation of Commodity RISC-V SBCs (e.g. StarFive VisionFive 2)
A standard RISC-V chip is a fixed Application-Specific Integrated Circuit (ASIC):
- **Fixed Silicon Logic:** You are locked into whatever fixed comparator circuits were etched into the die at the factory.
- **Inaccessible Memory Bus:** The interconnect between the CPU core and the DDR controller is buried inside the silicon die. You cannot intercept bus transactions, modify bus signals, or add custom hardware logic.
- **No Custom Vector 0x8F:** You cannot implement physical wordline gating or hardware causal trap controllers.
- **Resource Contention:** Running an autonomous agent (LLM / Python bridge) and a bare-metal microkernel simultaneously on four weak cores creates severe contention and compromises determinism.

---

## 4. Why the AMD Kria KV260 Is the Single Best Hardware Platform

The **AMD Kria KV260 Vision AI Starter Kit** (~$249) features the **Xilinx Zynq UltraScale+ MPSoC**. It is the only platform that provides an open, customizable physical memory bus alongside hardened enterprise compute.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ AMD KRIA KV260 ARCHITECTURE FOR ODIN OS & THE SUPERGRAPH                               │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│  ┌────────────────────────────────────────┐    ┌────────────────────────────────────┐  │
│  │ PROCESSING SYSTEM (PS)                 │    │ PROGRAMMABLE LOGIC (PL / FPGA)     │  │
│  │ Hardened Quad-Core ARM Cortex-A53      │    │ 256K UltraScale+ Logic Cells       │  │
│  │                                        │    │                                    │  │
│  │ - Runs Host Agent Environment & Bridge │    │ - Instantiates 64-bit RISC-V Core  │  │
│  │ - Runs Local Neural Models / Vision    │    │   (CVA6 or RocketChip) in M-Mode   │  │
│  │ - Evaluates Policy Decision Point (PDP)│    │ - Executes bare-metal Odin OS      │  │
│  │ - Emits Signed TransitionDeed Packets  │    │ - Holds Root Public Key in ROM     │  │
│  └───────────────────┬────────────────────┘    └─────────────────┬──────────────────┘  │
│                      │                                           │                     │
│                      │ High-Speed AXI Stream                     │ Instruction Memory  │
│                      ▼                                           ▼ Accesses            │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │ CUSTOM PHYSICAL AXI WORDLINE INTERLOCK PERIPHERAL                                │  │
│  │ (Implemented in FPGA Fabric)                                                     │  │
│  │                                                                                  │  │
│  │   [ AXI Address Write (AW) Channel Interception ]                                │  │
│  │                                                                                  │  │
│  │   • If awaddr is inside active TransitionDeed AST Mask:                          │  │
│  │       Assert AWVALID / WVALID to DDR4 Controller -> Commit in 1 Bus Cycle.       │  │
│  │                                                                                  │  │
│  │   • If awaddr is outside active TransitionDeed AST Mask:                         │  │
│  │       1. Pull Write Enable LOW (WE = 0) -> Zero Electrical Charge to DRAM.       │  │
│  │       2. Assert AXI Slave Error (SLVERR).                                        │  │
│  │       3. Pulse Physical Hardware Interrupt Line -> Vector 0x8F!                  │  │
│  │       4. Latch Bus Address & Cycle to Hardware CausalTrapFrame Register.         │  │
│  └────────────────────────────────────────┬─────────────────────────────────────────┘  │
│                                           │                                            │
│                                           ▼                                            │
│                       ┌──────────────────────────────────────┐                         │
│                       │ Physical 4GB 64-bit DDR4 SDRAM Array │                         │
│                       └──────────────────────────────────────┘                         │
│                                           ▲                                            │
│                                           │                                            │
│                   PMOD Hardware Header: Connect Logic Analyzer                         │
│                   to directly capture physical WE=0 suppression!                       │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### The 4 Definitive Advantages of the Kria KV260:

### 1. Direct Ownership of the Memory Bus (True Wordline Gating)
In the FPGA fabric, **we sit directly on the AXI bus between the RISC-V core and the physical DDR4 memory controller**. We write the AXI interlock state machine in Verilog/SpinalHDL. If an address is outside the active deed, the FPGA hardware suppresses `WVALID` and forces `WSTRB` to zero. **Write Enable is physically zero in hardware.**

### 2. Empirical Verification via Oscilloscope / Logic Analyzer
The KV260 exposes standard PMOD and Raspberry Pi GPIO headers tied directly to FPGA fabric pins. We can route:
- Pin 1: `AXI_WVALID`
- Pin 2: `AXI_WSTRB_SUPPRESSED`
- Pin 3: `IRQ_VECTOR_0x8F`
A $20 USB logic analyzer can capture the exact microsecond when an autonomous model tries an unauthorized store, proving to the scientific community that the electrical write strobe was killed on the wire.

### 3. Native Heterogeneous Co-Design (Agent Host + Silicon Microkernel)
The KV260 has both the ARM Processing System (running Linux, Python, PyNaCl, and edge neural inference) and the FPGA Programmable Logic on the **same piece of silicon**, communicating over multi-gigabit AXI interconnects. This allows an end-to-end demonstration where an autonomous agent on the ARM core proposes AST mutations, streams deeds across the on-chip AXI bus to the RISC-V microkernel in the FPGA, and is policed by physical hardware gating.

### 4. Aerospace & Space Heritage (ADR-SPACESHIP Validation)
The AMD Kria K26 SOM is built on the Xilinx Zynq UltraScale+ architecture—the direct commercial sibling of radiation-tolerant space-grade SoCs (XQRKU060 and Versal Adaptive SoCs) chosen for cislunar communications, lunar landers, and satellite payloads. Demonstrating capability-gated memory on this hardware validates the ADR-SPACESHIP thesis in the exact hardware family destined for space flight.

---

## 5. Bill of Materials & Procurement List

To bring up the complete physical hardware demonstration:

| Item | Description | Approximate Cost | Source |
|:---|:---|:---:|:---|
| **AMD Kria KV260** | Vision AI Starter Kit (Zynq UltraScale+ MPSoC) | ~$249.00 | DigiKey, Mouser, Avnet, AMD |
| **Power Supply** | 12V / 3A DC Barrel Jack Adapter (5.5mm OD x 2.1mm ID, Center-Positive) | ~$15.00 | Amazon, DigiKey |
| **MicroSD Card** | 32GB or 64GB High-Endurance / Extreme Card | ~$12.00 | Amazon |
| **Debug Cable** | Micro-USB to USB-A cable (onboard JTAG & dual UART) | ~$5.00 | Standard lab stock |
| **Logic Analyzer** | 8-Channel 24MHz USB Logic Analyzer (24M Saleae clone) | ~$15.00 | Amazon |
| **Total Investment** | **Complete Physical Silicon & Bus Instrumentation Lab** | **~$296.00** | |

---

## 6. Conclusion

Software simulation (Phase B.1–B.3) mathematically proved the logic, the cryptography, and the formal invariant bounds of Odin OS. 

The **AMD Kria KV260** is the hardware that turns that mathematical proof into **indisputable physical reality**: taking capability-gated memory out of software emulation and proving it on the physical memory bus wires of an aerospace-grade processor.
