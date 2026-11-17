/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * Cryptography for WPA/WPA2-Personal: key derivation, EAPOL-Key helpers,
 * CCMP (AES) and TKIP frame protection. The primitives (AES, SHA-1, MD5,
 * PBKDF2) come from Apple's CommonCrypto.
 */
#ifndef XG_CRYPTO_H
#define XG_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

void xg_random(void *buf, size_t len);

/* PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32) */
int wpa_passphrase_to_pmk(const char *passphrase, const uint8_t *ssid,
			  size_t ssid_len, uint8_t pmk[32]);

void hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *data,
	       size_t len, uint8_t mac[20]);
void hmac_md5(const uint8_t *key, size_t key_len, const uint8_t *data,
	      size_t len, uint8_t mac[16]);

/* IEEE 802.11i PRF (HMAC-SHA1 based) */
void wpa_prf(const uint8_t *key, size_t key_len, const char *label,
	     const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len);

/* RFC 3394 AES key unwrap; n = number of 8-byte blocks of plaintext.
 * cipher holds (n + 1) * 8 bytes. Returns 0 if the integrity check passes. */
int aes_unwrap(const uint8_t kek[16], int n, const uint8_t *cipher,
	       uint8_t *plain);

void rc4_skip(const uint8_t *key, size_t key_len, size_t skip, uint8_t *data,
	      size_t len);

/* Generic CCM with a 13-byte nonce and an 8-byte tag (what CCMP uses).
 * Exposed for the self-tests. */
struct aes_ctx;
struct aes_ctx *aes_ctx_new(const uint8_t key[16]);
void aes_ctx_free(struct aes_ctx *c);
int ccm_encrypt(struct aes_ctx *c, const uint8_t nonce[13], const uint8_t *aad,
		size_t aad_len, const uint8_t *plain, size_t len, uint8_t *out,
		uint8_t tag[8]);
int ccm_decrypt(struct aes_ctx *c, const uint8_t nonce[13], const uint8_t *aad,
		size_t aad_len, const uint8_t *cipher, size_t len, uint8_t *out,
		const uint8_t tag[8]);

/* --- per-frame protection ------------------------------------------------ */

enum xg_cipher {
	XG_CIPHER_NONE = 0,
	XG_CIPHER_TKIP,
	XG_CIPHER_CCMP,
};

#define CCMP_HDR_LEN 8
#define CCMP_MIC_LEN 8
#define TKIP_HDR_LEN 8
#define TKIP_MIC_LEN 8
#define TKIP_ICV_LEN 4
/* worst-case growth of a frame body when it gets protected */
#define XG_CRYPT_OVERHEAD (TKIP_HDR_LEN + TKIP_MIC_LEN + TKIP_ICV_LEN)

struct xg_key {
	enum xg_cipher cipher;
	int key_idx;
	struct aes_ctx *aes;		/* CCMP */
	uint8_t tk[16];			/* TKIP temporal key */
	uint8_t mic_tx[8], mic_rx[8];	/* TKIP Michael keys */
	uint64_t tx_pn;			/* last packet number used */
	uint64_t rx_pn[17];		/* last accepted, per TID (+1: non-QoS) */
	/* TKIP phase 1 cache for reception */
	int rx_p1k_valid;
	uint32_t rx_p1k_iv32;
	uint16_t rx_p1k[5];
};

/*
 * key material layout:
 *  CCMP: 16 bytes
 *  TKIP: 32 bytes = TK(16) | authenticator-tx Michael key(8) |
 *                   supplicant-tx Michael key(8)
 * rsc: initial receive packet number (may be NULL).
 */
int xg_key_set(struct xg_key *k, enum xg_cipher cipher, int key_idx,
	       const uint8_t *material, size_t len, const uint8_t *rsc);
void xg_key_clear(struct xg_key *k);

/*
 * Protects a frame. hdr is the 802.11 header (hdr_len bytes, Protected bit
 * already set), body the cleartext frame body. out receives the protected
 * body (cipher header + ciphertext + MIC/ICV). Returns its length or -1.
 */
int xg_encrypt(struct xg_key *k, const uint8_t *hdr, size_t hdr_len,
	       const uint8_t *body, size_t len, uint8_t *out);

/*
 * Reverse operation. Returns the cleartext length, or a negative value:
 * -1 malformed, -2 integrity failure, -3 replay.
 */
int xg_decrypt(struct xg_key *k, const uint8_t *hdr, size_t hdr_len,
	       const uint8_t *body, size_t len, uint8_t *out);

/* key index carried by a protected frame body, or -1 */
int xg_frame_key_idx(const uint8_t *body, size_t len);

/* exposed for the self-tests */
void tkip_phase1(uint16_t p1k[5], const uint8_t tk[16], const uint8_t ta[6],
		 uint32_t iv32);
void tkip_phase2(uint8_t rc4key[16], const uint8_t tk[16],
		 const uint16_t p1k[5], uint16_t iv16);
void michael_mic(const uint8_t key[8], const uint8_t *hdr16,
		 const uint8_t *data, size_t len, uint8_t mic[8]);

#endif /* XG_CRYPTO_H */
