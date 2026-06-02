/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * RFC-0006 IntentObservation encoder in x86-64 assembly (System V AMD64 ABI).
 * void axonos_rfc0006_encode_asm(const axonos_enc_args *in /%rdi/, uint8_t *out /%rsi/)
 * Emits the 32-byte little-endian layout. The x86-64 host is little-endian, so
 * 64/16-bit stores need no byte swap. When kind_tag == 3 (Quality) the quality
 * field is forced to 0xFFFF via a conditional move.
 * struct axonos_enc_args offsets: timestamp_us=0, session_id=8, kind_tag=16,
 *                                 quality_raw=18, discriminant=20, attestation=21 */
	.text
	.globl	axonos_rfc0006_encode_asm
	.type	axonos_rfc0006_encode_asm, @function
axonos_rfc0006_encode_asm:
	movq	0(%rdi), %rax        /* timestamp_us            */
	movq	%rax, 0(%rsi)        /* out[0..8)               */
	movzwl	16(%rdi), %eax       /* kind_tag (u16)          */
	movw	%ax, 8(%rsi)         /* out[8..10)              */
	movzwl	18(%rdi), %edx       /* quality_raw (u16)       */
	cmpw	$3, %ax              /* kind_tag == Quality?    */
	movl	$0xFFFF, %ecx
	cmove	%ecx, %edx           /* if Quality, force 0xFFFF*/
	movw	%dx, 10(%rsi)        /* out[10..12)             */
	movzbl	20(%rdi), %eax       /* discriminant            */
	movb	%al, 12(%rsi)        /* out[12]                 */
	xorl	%eax, %eax
	movb	%al, 13(%rsi)        /* out[13..16) = 0         */
	movb	%al, 14(%rsi)
	movb	%al, 15(%rsi)
	movq	8(%rdi), %rax        /* session_id              */
	movq	%rax, 16(%rsi)       /* out[16..24)             */
	movq	21(%rdi), %rax       /* attestation[8] (unaligned load) */
	movq	%rax, 24(%rsi)       /* out[24..32)             */
	ret
	.size	axonos_rfc0006_encode_asm, .-axonos_rfc0006_encode_asm
	.section	.note.GNU-stack,"",@progbits
