// Fixture: relevant excerpt of the assembly emitted by
// crypto/aes/asm/aes-sha256-armv8.pl from openssl-4.0.1
// (generator sha256: b113d2a9c6360df813c580ca91678c62388ef4736012a5d100ae7edd8f633e16).
// Flavour: linux64 (AArch64 GAS). Generated 2026-08-17 via
// core.sandbox.run_untrusted (strict profile, network deny) - the
// core/inventory/perlasm.py pipeline. Emitted assembly is untrusted
// target-derived data; this excerpt preserves only the regions
// load-bearing for core/audit/asm_zero_len_loop.py (elisions marked;
// line numbers do NOT match the full 5485-line generated file).
//
// VULNERABLE shape (external-harness finding #10, crypto/aes/asm/aes-sha256-armv8.pl:1653): structural twin of
// the sha1 kernel - same dispatch / short-loop / late-cbz shape.

.globl	asm_aescbc_sha256_hmac
.type	asm_aescbc_sha256_hmac,%function

.section	.rodata
.align	4
.Lrcon:
.word	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
.word	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
.word	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
.word	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
.word	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
.word	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
.word	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
.word	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
.word	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
.word	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
.word	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
.word	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
.word	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
.word	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
.word	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
.word	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

.Linit_sha_state:
.word	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
.word	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
.text

asm_aescbc_sha256_hmac:
	AARCH64_VALID_CALL_TARGET

	stp	d8,d9,[sp,#-64]!

	ldr	x7, [x6, #HMAC_IKEYPAD]

	ldp	q24,q25,[x7]

	ldr	x7, [x6, #HMAC_OKEYPAD]

	stp	d10,d11,[sp,#16]


	adrp	x12,.Linit_sha_state
	add	x12,x12,#:lo12:.Linit_sha_state
	prfm	PLDL1KEEP,[x1,0]
	lsr	x10,x2,4

	stp	d12,d13,[sp,#32]
	stp	d14,d15,[sp,#48]

	ldr	x9, [x6, #CIPHER_KEY]
	ldr	x16, [x6, #CIPHER_KEY_ROUNDS]
	ldr	x6, [x6, #CIPHER_IV]
	add	x17, x9, #160

	/*
	*	Init sha state, prefetch, check for small cases.
	*	Note that the output is prefetched as a load, for the in-place case
	*/
	prfm	PLDL1KEEP,[x0,0]
	cmp	x10,12
	b.lt	.Lenc_short_cases


	ld1	{v3.16b},[x6]
// [elided: lines 141-1772 of the generated file]
.Lenc_short_cases:
	ld1	{v3.16b},[x6]
	ldp	q8,q9,[x9],32
	eor	v26.16b,v26.16b,v26.16b
	ldp	q10,q11,[x9],32
	eor	v27.16b,v27.16b,v27.16b
	ldp	q12,q13,[x9],32
	eor	v28.16b,v28.16b,v28.16b
	ldp	q14,q15,[x9],32
	eor	v29.16b,v29.16b,v29.16b
	ldp	q16,q17,[x9],32
	mov	w15,0x80
	lsl	x11,x10,4
	ld1	{v18.16b},[x9]


	sub	x12,x5,x2
	/*
	*	the idea in the short loop (at least 1) is to break out with the padding
	*	already in place excepting the final word.
	*/
.Lenc_short_loop:
	adrp	x8,.Lrcon
	add	x8,x8,#:lo12:.Lrcon

	ld1	{v0.16b},[x0],16
	eor	v0.16b,v0.16b,v3.16b

// [elided: lines 1801-1844 of the generated file]
.Laes128_enc_short_0:
	ld1	{v18.16b},[x9]
	aese	v0.16b,v17.16b
	eor	v0.16b,v0.16b,v18.16b
1:

	st1	{v0.16b},[x1],16

	ld1	{v26.16b},[x3],16

	sub	x5,x5,16
	rev32	v26.16b,v26.16b
	sub	x10,x10,1
	cbz	x10,.Lpost_short_Q1

	ld1	{v1.16b},[x0],16
	eor	v1.16b,v1.16b,v0.16b

// [elided: lines 1863-2177 of the generated file]
	eor	v28.16b,v28.16b,v28.16b
	sub	x10,x10,1
	eor	v29.16b,v29.16b,v29.16b

	cbnz	x10,.Lenc_short_loop

.Lpost_short_Q0:

// [elided: remainder of the generated file]
