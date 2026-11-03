; ==============================================================================
; Odin OS Phase B.3 — Formal SMT Invariant Verification (SMT-LIB2 / Z3)
; Component: TransitionDeed Range Validation & Integer Overflow Immunity
; Tool: Z3 version 5.3.1
; ==============================================================================

(set-logic QF_BV)

; Declare 32-bit bitvector inputs matching TransitionDeed fields
(declare-const target_offset (_ BitVec 32))
(declare-const target_length (_ BitVec 32))
(declare-const max_bound (_ BitVec 32))

; Define 64-bit zero-extended equivalents
(define-fun offset_64 () (_ BitVec 64) ((_ zero_extend 32) target_offset))
(define-fun length_64 () (_ BitVec 64) ((_ zero_extend 32) target_length))
(define-fun max_bound_64 () (_ BitVec 64) ((_ zero_extend 32) max_bound))

; Rust checked_add logic:
; checked_add overflows iff (target_offset + target_length) < target_offset in 32-bit unsigned math
; Equivalently, in 64-bit arithmetic: (offset_64 + length_64) > 0xFFFFFFFF
(define-fun add_overflows () Bool
  (bvugt (bvadd offset_64 length_64) (_ bv4294967295 64)))

; Result of checked_add when valid
(define-fun end_offset () (_ BitVec 32)
  (bvadd target_offset target_length))

; Microkernel Deed Acceptance Predicate:
; 1. target_length > 0
; 2. checked_add succeeds (no overflow)
; 3. end_offset <= max_bound
(define-fun deed_valid () Bool
  (and
    (bvugt target_length (_ bv0 32))
    (not add_overflows)
    (bvule end_offset max_bound)))

; Architectural Buffer Constraints in Odin OS:
; AST_BUFFER_BASE = 0x80020000
; AST_BUFFER_END  = 0x80030000
; max_bound       = (AST_BUFFER_END - AST_BUFFER_BASE) = 0x10000 (65536 bytes)
(assert (= max_bound (_ bv65536 32)))

; Physical Memory Layout Constants:
(define-fun ast_buffer_base () (_ BitVec 64) (_ bv2147614720 64)) ; 0x80020000
(define-fun kernel_base () (_ BitVec 64)     (_ bv2147483648 64)) ; 0x80000000
(define-fun kernel_end () (_ BitVec 64)      (_ bv2147549184 64)) ; 0x80010000
(define-fun user_text_base () (_ BitVec 64)  (_ bv2147549184 64)) ; 0x80010000
(define-fun user_text_end () (_ BitVec 64)   (_ bv2147581952 64)) ; 0x80018000
(define-fun user_stack_base () (_ BitVec 64) (_ bv2147581952 64)) ; 0x80018000
(define-fun user_stack_end () (_ BitVec 64)  (_ bv2147614720 64)) ; 0x80020000
(define-fun uart_base () (_ BitVec 64)       (_ bv268435456 64))  ; 0x10000000
(define-fun uart_end () (_ BitVec 64)        (_ bv268439552 64))  ; 0x10001000

; Computed Physical Lease Range:
(define-fun physical_lease_start () (_ BitVec 64)
  (bvadd ast_buffer_base offset_64))

(define-fun physical_lease_end () (_ BitVec 64)
  (bvadd physical_lease_start length_64))

; ------------------------------------------------------------------------------
; GOAL 1: FORMAL THEOREM — OVERFLOW IMMUNITY
; Assert that deed is accepted, but an overflow occurred (wrap-around).
; Expected: UNSAT (Proves that NO accepted deed can wrap around in 32-bit math).
; ------------------------------------------------------------------------------
(push 1)
(assert deed_valid)
(assert (bvuge target_offset end_offset))
(check-sat) ; Must return unsat
(pop 1)

; ------------------------------------------------------------------------------
; GOAL 2: FORMAL THEOREM — MEMORY ISOLATION & NON-OVERLAP
; Assert that deed is accepted, but the physical lease overlaps ANY privileged region:
; - Kernel RAM (0x80000000..0x80010000)
; - User Text  (0x80010000..0x80018000)
; - User Stack (0x80018000..0x80020000)
; - UART MMIO  (0x10000000..0x10001000)
; Expected: UNSAT (Proves that NO accepted deed can ever touch privileged memory).
; ------------------------------------------------------------------------------
(push 1)
(assert deed_valid)
(define-fun overlaps_kernel () Bool
  (and (bvult physical_lease_start kernel_end) (bvugt physical_lease_end kernel_base)))
(define-fun overlaps_user_text () Bool
  (and (bvult physical_lease_start user_text_end) (bvugt physical_lease_end user_text_base)))
(define-fun overlaps_user_stack () Bool
  (and (bvult physical_lease_start user_stack_end) (bvugt physical_lease_end user_stack_base)))
(define-fun overlaps_uart () Bool
  (and (bvult physical_lease_start uart_end) (bvugt physical_lease_end uart_base)))

(assert (or overlaps_kernel overlaps_user_text overlaps_user_stack overlaps_uart))
(check-sat) ; Must return unsat
(pop 1)

; ------------------------------------------------------------------------------
; GOAL 3: FORMAL THEOREM — STRICT BUFFER CONTAINMENT
; Assert that deed is accepted, but lease exceeds AST_BUFFER_END (0x80030000).
; Expected: UNSAT (Proves that all accepted leases remain strictly in AST buffer).
; ------------------------------------------------------------------------------
(push 1)
(assert deed_valid)
(define-fun ast_buffer_end () (_ BitVec 64) (_ bv2147680256 64)) ; 0x80030000
(assert (bvugt physical_lease_end ast_buffer_end))
(check-sat) ; Must return unsat
(pop 1)
