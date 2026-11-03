; ==============================================================================
; Odin OS Phase B.3 — Formal SMT Verification: Anti-Replay Monotonicity
; Tool: Z3 version 5.3.1
; ==============================================================================

(set-logic QF_BV)

; Model state variables across two consecutive transactions:
; last_seq_0: Initial consumed sequence
; seq_1:      Sequence proposed in deed 1
; last_seq_1: Consumed sequence after deed 1
; seq_2:      Sequence proposed in deed 2

(declare-const last_seq_0 (_ BitVec 32))
(declare-const seq_1 (_ BitVec 32))
(declare-const last_seq_1 (_ BitVec 32))
(declare-const seq_2 (_ BitVec 32))

; Transaction 1 Acceptance Rule:
; seq_1 > last_seq_0
(define-fun accept_1 () Bool
  (bvugt seq_1 last_seq_0))

; State Update Rule:
; If accepted, last_seq_1 = seq_1
(assert (=> accept_1 (= last_seq_1 seq_1)))

; Transaction 2 Acceptance Rule:
; seq_2 > last_seq_1
(define-fun accept_2 () Bool
  (bvugt seq_2 last_seq_1))

; ------------------------------------------------------------------------------
; THEOREM 1: IDENTICAL REPLAY ATTACK IMPOSSIBILITY
; An attacker resubmits deed 1 as deed 2 (seq_2 = seq_1).
; Prove that if deed 1 was accepted, deed 2 CANNOT be accepted.
; Formally: (accept_1 and (= seq_2 seq_1) and accept_2) is UNSAT.
; ------------------------------------------------------------------------------
(push 1)
(assert accept_1)
(assert (= seq_2 seq_1))
(assert accept_2)
(check-sat) ; Must return unsat
(pop 1)

; ------------------------------------------------------------------------------
; THEOREM 2: STALE SEQUENCE REPLAY IMPOSSIBILITY
; An attacker submits seq_2 <= seq_1 after deed 1 was accepted.
; Formally: (accept_1 and (bvule seq_2 seq_1) and accept_2) is UNSAT.
; ------------------------------------------------------------------------------
(push 1)
(assert accept_1)
(assert (bvule seq_2 seq_1))
(assert accept_2)
(check-sat) ; Must return unsat
(pop 1)
