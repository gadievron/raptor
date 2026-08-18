// Fixture: relevant excerpt of the assembly emitted by
// crypto/aes/asm/aes-sha512-armv8.pl from openssl-4.0.1
// (generator sha256: 3431c9c228029094d45045e6e9a624f4c0b83621c6a69711a5826da9039c142a).
// Flavour: linux64 (AArch64 GAS). Generated 2026-08-17 via
// core.sandbox.run_untrusted (strict profile, network deny) - the
// core/inventory/perlasm.py pipeline. Emitted assembly is untrusted
// target-derived data; this excerpt preserves only the regions
// load-bearing for core/audit/asm_zero_len_loop.py (elisions marked;
// line numbers do NOT match the full 10306-line generated file).
//
// CONFORMING sibling shape: lsr x11, x2, #4 followed
// immediately by cbz x11, .Lret - the leading zero guard the
// two vulnerable kernels lack. The detector must return zero
// findings on this excerpt.

.globl	asm_aescbc_sha512_hmac
.type	asm_aescbc_sha512_hmac,%function

.section	.rodata
// [elided: lines 43-88 of the generated file]
asm_aescbc_sha512_hmac:
	AARCH64_VALID_CALL_TARGET

	stp	d8, d9, [sp,#-64]!
	stp	d10, d11, [sp,#16]
	stp	d12, d13, [sp,#32]
	stp	d14, d15, [sp,#48]


	ldr	x7, [x6, #HMAC_IKEYPAD]
	ld1	{v24.2d, v25.2d, v26.2d, v27.2d}, [x7]

	ldr	x7, [x6, #CIPHER_KEY]
	ldr	x8, [x6, #CIPHER_IV]
	ldr	x9, [x6, #CIPHER_KEY_ROUNDS]
	mov	x12, x7

	adrp	x10, .LK512
	add	x10, x10, #:lo12:.LK512

	lsr	x11, x2, #4
	cbz	x11, .Lret

	cmp	x11, #16
	b.lt	.Lenc_short_case

	ld1	{v0.16b}, [x0], #16
// [elided: lines 116-3579 of the generated file]
	add	v24.2d, v24.2d, v20.2d
	add	v25.2d, v25.2d, v21.2d
	add	v26.2d, v26.2d, v22.2d
	add	v27.2d, v27.2d, v23.2d
	ldr	x7, [x6, #CIPHER_KEY]
	ldp	q8, q9, [x7]
	add	x7, x7, #160
	cbz	x11, .Lenc_short_no_more_aes_block
	ld1	{v0.16b}, [x0], #16
	ldr	q1, [x1, -16]
	eor	v0.16b, v0.16b, v1.16b
.Lenc_less_than_8_block:
	cbz	x11, .Lenc_short_no_more_aes_block

	aese	v0.16b, v8.16b
	aesmc	v0.16b, v0.16b
	aese	v0.16b, v9.16b
	aesmc	v0.16b, v0.16b
	aese	v0.16b, v10.16b
	aesmc	v0.16b, v0.16b
	aese	v0.16b, v11.16b
	aesmc	v0.16b, v0.16b
	aese	v0.16b, v12.16b
	aesmc	v0.16b, v0.16b
	aese	v0.16b, v13.16b
	aesmc	v0.16b, v0.16b
	aese	v0.16b, v14.16b
	aesmc	v0.16b, v0.16b
	aese	v0.16b, v15.16b
	aesmc	v0.16b, v0.16b
	aese	v0.16b, v16.16b
	aesmc	v0.16b, v0.16b
	cmp	x9, #12
	b.lt	.Laes128_enc_short_partial_0
.Laes192_enc_short_partial_0:
	ldp	q18,q19,[x7],32
	aese	v0.16b,v17.16b
	aesmc	v0.16b,v0.16b
	aese	v0.16b,v18.16b
	aesmc	v0.16b,v0.16b
	b.gt	.Laes256_enc_short_partial_0
	ld1	{v18.16b},[x7]
	aese	v0.16b,v19.16b
	eor	v0.16b,v0.16b,v18.16b
	sub	x7, x7, #32
	b	1f
.Laes256_enc_short_partial_0:
	aese	v0.16b,v19.16b
	aesmc	v0.16b,v0.16b
	ldp	q18,q19,[x7],32
	aese	v0.16b,v18.16b
	aesmc	v0.16b,v0.16b
	ld1	{v18.16b},[x7]
	aese	v0.16b,v19.16b
	eor	v0.16b,v0.16b,v18.16b
	sub	x7, x7, #64
	b	1f
.Laes128_enc_short_partial_0:
	aese	v0.16b,v17.16b
	eor	v0.16b,v0.16b,v18.16b
1:
	str	q0, [x1], #16
	sub	x11, x11, #1
	cbz	x11, .Lenc_short_post_Q0

	ld1	{v1.16b}, [x0], #16

	eor	v1.16b, v1.16b, v0.16b

	aese	v1.16b, v8.16b
	aesmc	v1.16b, v1.16b
// [elided: remainder of the generated file]
