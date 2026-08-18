// Fixture: relevant excerpt of the assembly emitted by
// crypto/aes/asm/aes-sha1-armv8.pl from openssl-4.0.1
// (generator sha256: f538afdbf4b2984c79d0c53a989c71ba58f1b8cc0fa75f241c8d9088bc158e3b).
// Flavour: linux64 (AArch64 GAS). Generated 2026-08-17 via
// core.sandbox.run_untrusted (strict profile, network deny) - the
// core/inventory/perlasm.py pipeline. Emitted assembly is untrusted
// target-derived data; this excerpt preserves only the regions
// load-bearing for core/audit/asm_zero_len_loop.py (elisions marked;
// line numbers do NOT match the full 5149-line generated file).
//
// VULNERABLE shape (external-harness finding #9, crypto/aes/asm/aes-sha1-armv8.pl:1551): x10 = len>>4 with no
// zero guard; cmp x10,12 / b.lt routes 0 to .Lenc_short_cases;
// .Lenc_short_loop stores one block (st1) before the first
// cbz x10 - a zero length wraps the counter to 2**64-1.

.globl	asm_aescbc_sha1_hmac
.type	asm_aescbc_sha1_hmac,%function

.section	.rodata
.align	4
.Lrcon:
.word	0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999
.word	0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1
.word	0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc
.word	0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6
.text

asm_aescbc_sha1_hmac:
	AARCH64_VALID_CALL_TARGET

	stp	d8,d9,[sp,#-64]!

	ldr	x7, [x6, #HMAC_IKEYPAD]

	ldr	q24, [x7]
	eor	v25.16b, v25.16b, v25.16b
	ldr	s25, [x7, #16]

	ldr	x7, [x6, #HMAC_OKEYPAD]

	stp	d10,d11,[sp,#16]

	prfm	PLDL1KEEP,[x0,0]
	prfm	PLDL1KEEP,[x1,0]
	lsr	x10,x2,4

	stp	d12,d13,[sp,#32]
	stp	d14,d15,[sp,#48]

	ldr	x9, [x6, #CIPHER_KEY]
	ldr	x16, [x6, #CIPHER_KEY_ROUNDS]
	ldr	x6, [x6, #CIPHER_IV]
	add	x17, x9, #160

	/*
	*	init sha state, prefetch, check for small cases.
	*	Note that the output is prefetched as a load, for the in-place case
	*/
	cmp	x10,12
	b.lt	.Lenc_short_cases


	ld1	{v3.16b},[x6]

// [elided: lines 126-1668 of the generated file]
.Lenc_short_cases:
	ldp	q8,q9,[x9],32
	adrp	x8,.Lrcon
	add	x8,x8,#:lo12:.Lrcon
	mov	w15,0x80
	ldp	q10,q11,[x9],32
	lsl	x11,x10,4
	eor	v26.16b,v26.16b,v26.16b
	ldp	q12,q13,[x9],32
	eor	v27.16b,v27.16b,v27.16b
	eor	v28.16b,v28.16b,v28.16b
	ldp	q14,q15,[x9],32
	eor	v29.16b,v29.16b,v29.16b
	ldp	q4,q5,[x8],32
	ldp	q16,q17,[x9],32
	ld1	{v3.16b},[x6]
	ldp	q6,q7,[x8]

	sub	x8,x5,x2
	/*
	*	the idea in the short loop (at least 1) is to break out with the padding
	*	already in place excepting the final word.
	*/
.Lenc_short_loop:

	ld1	{v0.16b},[x0],16
	eor	v0.16b,v0.16b,v3.16b


	aese	v0.16b,v8.16b
	aesmc	v0.16b,v0.16b
	aese	v0.16b,v9.16b
// [elided: lines 1701-1737 of the generated file]
	eor	v0.16b,v0.16b,v30.16b
	sub	x17, x17, #64
	b	1f
.Laes128_enc_short_0:
	ld1	{v18.16b},[x9]
	aese	v0.16b,v17.16b
	eor	v0.16b,v0.16b,v18.16b
1:

	st1	{v0.16b},[x1],16

	ld1	{v26.16b},[x3],16

	sub	x5,x5,16
	sub	x10,x10,1

	rev32	v26.16b,v26.16b
	cbz	x10,.Lpost_short_Q1

	ld1	{v1.16b},[x0],16
	eor	v1.16b,v1.16b,v0.16b


// [elided: lines 1761-2059 of the generated file]
	eor	v27.16b,v27.16b,v27.16b
	eor	v28.16b,v28.16b,v28.16b
	eor	v29.16b,v29.16b,v29.16b

	sub	x10,x10,1
	cbnz	x10,.Lenc_short_loop

.Lpost_short_Q0:
// [elided: remainder of the generated file]
