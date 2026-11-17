/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * Cryptography for WPA/WPA2-Personal on top of Apple's CommonCrypto.
 *
 * CCMP follows IEEE 802.11-2012 11.4.3 (CCM from RFC 3610), TKIP follows
 * 11.4.2. Both are checked against the published test vectors by
 * tests/crypto_test.c.
 */
#include "crypto.h"

#include <CommonCrypto/CommonCrypto.h>
#include <stdlib.h>
#include <string.h>

#include "ieee80211.h"

#define MAX_BODY 2400

void xg_random(void *buf, size_t len)
{
	arc4random_buf(buf, len);
}

int wpa_passphrase_to_pmk(const char *passphrase, const uint8_t *ssid,
			  size_t ssid_len, uint8_t pmk[32])
{
	size_t n = strlen(passphrase);

	if (n < 8 || n > 63)
		return -1;
	return CCKeyDerivationPBKDF(kCCPBKDF2, passphrase, n, ssid, ssid_len,
				    kCCPRFHmacAlgSHA1, 4096, pmk, 32) ==
		       kCCSuccess ? 0 : -1;
}

void hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *data,
	       size_t len, uint8_t mac[20])
{
	CCHmac(kCCHmacAlgSHA1, key, key_len, data, len, mac);
}

void hmac_md5(const uint8_t *key, size_t key_len, const uint8_t *data,
	      size_t len, uint8_t mac[16])
{
	CCHmac(kCCHmacAlgMD5, key, key_len, data, len, mac);
}

void wpa_prf(const uint8_t *key, size_t key_len, const char *label,
	     const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len)
{
	size_t label_len = strlen(label) + 1; /* includes the NUL */
	uint8_t counter = 0;
	uint8_t hash[20];
	size_t pos = 0;

	while (pos < out_len) {
		CCHmacContext ctx;
		size_t n = out_len - pos < sizeof(hash) ? out_len - pos :
							  sizeof(hash);

		CCHmacInit(&ctx, kCCHmacAlgSHA1, key, key_len);
		CCHmacUpdate(&ctx, label, label_len);
		CCHmacUpdate(&ctx, data, data_len);
		CCHmacUpdate(&ctx, &counter, 1);
		CCHmacFinal(&ctx, hash);
		memcpy(out + pos, hash, n);
		pos += n;
		counter++;
	}
	memset(hash, 0, sizeof(hash));
}

int aes_unwrap(const uint8_t kek[16], int n, const uint8_t *cipher,
	       uint8_t *plain)
{
	uint8_t a[8], b[16];
	uint8_t *r;
	size_t moved;

	if (n < 1)
		return -1;
	memcpy(a, cipher, 8);
	memcpy(plain, cipher + 8, 8 * (size_t)n);

	for (int j = 5; j >= 0; j--) {
		r = plain + (n - 1) * 8;
		for (int i = n; i >= 1; i--) {
			uint64_t t = (uint64_t)n * (uint64_t)j + (uint64_t)i;

			memcpy(b, a, 8);
			for (int k = 0; k < 8; k++)
				b[7 - k] ^= (uint8_t)(t >> (8 * k));
			memcpy(b + 8, r, 8);
			if (CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionECBMode,
				    kek, 16, NULL, b, 16, b, 16, &moved) !=
			    kCCSuccess)
				return -1;
			memcpy(a, b, 8);
			memcpy(r, b + 8, 8);
			r -= 8;
		}
	}
	for (int i = 0; i < 8; i++)
		if (a[i] != 0xa6)
			return -1;
	return 0;
}

void rc4_skip(const uint8_t *key, size_t key_len, size_t skip, uint8_t *data,
	      size_t len)
{
	uint8_t s[256], t;
	unsigned int i, j = 0;

	for (i = 0; i < 256; i++)
		s[i] = (uint8_t)i;
	for (i = 0; i < 256; i++) {
		j = (j + s[i] + key[i % key_len]) & 0xff;
		t = s[i];
		s[i] = s[j];
		s[j] = t;
	}
	i = j = 0;
	for (size_t k = 0; k < skip + len; k++) {
		i = (i + 1) & 0xff;
		j = (j + s[i]) & 0xff;
		t = s[i];
		s[i] = s[j];
		s[j] = t;
		if (k >= skip)
			data[k - skip] ^= s[(s[i] + s[j]) & 0xff];
	}
}

/* --- AES-CCM (13-byte nonce, 8-byte tag) -------------------------------- */

struct aes_ctx {
	CCCryptorRef ecb;
	CCCryptorRef cbc;
};

static const uint8_t zero_iv[16];

struct aes_ctx *aes_ctx_new(const uint8_t key[16])
{
	struct aes_ctx *c = calloc(1, sizeof(*c));

	if (!c)
		return NULL;
	if (CCCryptorCreate(kCCEncrypt, kCCAlgorithmAES, kCCOptionECBMode, key,
			    16, NULL, &c->ecb) != kCCSuccess ||
	    CCCryptorCreate(kCCEncrypt, kCCAlgorithmAES, 0, key, 16, zero_iv,
			    &c->cbc) != kCCSuccess) {
		aes_ctx_free(c);
		return NULL;
	}
	return c;
}

void aes_ctx_free(struct aes_ctx *c)
{
	if (!c)
		return;
	if (c->ecb)
		CCCryptorRelease(c->ecb);
	if (c->cbc)
		CCCryptorRelease(c->cbc);
	free(c);
}

/* CBC-MAC over B0 | AAD | data; returns the full 16-byte value */
static int ccm_cbc_mac(struct aes_ctx *c, const uint8_t nonce[13],
		       const uint8_t *aad, size_t aad_len, const uint8_t *data,
		       size_t len, uint8_t t[16])
{
	uint8_t buf[16 + 64 + MAX_BODY + 16];
	uint8_t out[sizeof(buf)];
	size_t n, moved;

	if (aad_len > 60 || len > MAX_BODY)
		return -1;
	buf[0] = (uint8_t)((aad_len ? 0x40 : 0) | (((8 - 2) / 2) << 3) | (2 - 1));
	memcpy(buf + 1, nonce, 13);
	buf[14] = (uint8_t)(len >> 8);
	buf[15] = (uint8_t)len;
	n = 16;
	if (aad_len) {
		buf[n++] = (uint8_t)(aad_len >> 8);
		buf[n++] = (uint8_t)aad_len;
		memcpy(buf + n, aad, aad_len);
		n += aad_len;
		while (n % 16)
			buf[n++] = 0;
	}
	memcpy(buf + n, data, len);
	n += len;
	while (n % 16)
		buf[n++] = 0;

	if (CCCryptorReset(c->cbc, zero_iv) != kCCSuccess ||
	    CCCryptorUpdate(c->cbc, buf, n, out, n, &moved) != kCCSuccess ||
	    moved != n)
		return -1;
	memcpy(t, out + n - 16, 16);
	return 0;
}

/* keystream blocks S_0 .. S_nblocks */
static int ccm_keystream(struct aes_ctx *c, const uint8_t nonce[13],
			 size_t nblocks, uint8_t *ks)
{
	size_t moved, n = (nblocks + 1) * 16;

	for (size_t i = 0; i <= nblocks; i++) {
		uint8_t *a = ks + 16 * i;

		a[0] = 2 - 1;
		memcpy(a + 1, nonce, 13);
		a[14] = (uint8_t)(i >> 8);
		a[15] = (uint8_t)i;
	}
	if (CCCryptorUpdate(c->ecb, ks, n, ks, n, &moved) != kCCSuccess ||
	    moved != n)
		return -1;
	return 0;
}

int ccm_encrypt(struct aes_ctx *c, const uint8_t nonce[13], const uint8_t *aad,
		size_t aad_len, const uint8_t *plain, size_t len, uint8_t *out,
		uint8_t tag[8])
{
	uint8_t ks[MAX_BODY + 32];
	uint8_t t[16];

	if (len > MAX_BODY)
		return -1;
	if (ccm_cbc_mac(c, nonce, aad, aad_len, plain, len, t) ||
	    ccm_keystream(c, nonce, (len + 15) / 16, ks))
		return -1;
	for (size_t i = 0; i < len; i++)
		out[i] = plain[i] ^ ks[16 + i];
	for (int i = 0; i < 8; i++)
		tag[i] = t[i] ^ ks[i];
	return 0;
}

int ccm_decrypt(struct aes_ctx *c, const uint8_t nonce[13], const uint8_t *aad,
		size_t aad_len, const uint8_t *cipher, size_t len, uint8_t *out,
		const uint8_t tag[8])
{
	uint8_t ks[MAX_BODY + 32];
	uint8_t t[16];
	uint8_t diff = 0;

	if (len > MAX_BODY)
		return -1;
	if (ccm_keystream(c, nonce, (len + 15) / 16, ks))
		return -1;
	for (size_t i = 0; i < len; i++)
		out[i] = cipher[i] ^ ks[16 + i];
	if (ccm_cbc_mac(c, nonce, aad, aad_len, out, len, t))
		return -1;
	for (int i = 0; i < 8; i++)
		diff |= (uint8_t)(tag[i] ^ t[i] ^ ks[i]);
	return diff ? -2 : 0;
}

/* --- 802.11 header helpers ---------------------------------------------- */

struct hdr_info {
	uint16_t fc;
	const uint8_t *a2;
	const uint8_t *da, *sa;
	int has_a4;
	int qos;
	uint8_t tid;
};

static int parse_hdr(const uint8_t *hdr, size_t hdr_len, struct hdr_info *h)
{
	size_t need = 24;

	if (hdr_len < 24)
		return -1;
	h->fc = get_le16(hdr);
	h->a2 = hdr + 10;
	h->has_a4 = (h->fc & (FC_TODS | FC_FROMDS)) == (FC_TODS | FC_FROMDS);
	h->qos = (h->fc & FC_TYPE_MASK) == FC_TYPE_DATA &&
		 (h->fc & FC_STYPE_DATA_QOS);
	if (h->has_a4)
		need += 6;
	if (h->qos)
		need += 2;
	if (hdr_len < need)
		return -1;
	h->tid = h->qos ? (hdr[need - 2] & 0x0f) : 0;

	switch (h->fc & (FC_TODS | FC_FROMDS)) {
	case 0:
		h->da = hdr + 4;
		h->sa = hdr + 10;
		break;
	case FC_TODS:
		h->da = hdr + 16;
		h->sa = hdr + 10;
		break;
	case FC_FROMDS:
		h->da = hdr + 4;
		h->sa = hdr + 16;
		break;
	default:
		h->da = hdr + 16;
		h->sa = hdr + 24;
		break;
	}
	return 0;
}

/* --- CCMP --------------------------------------------------------------- */

static size_t ccmp_aad(const uint8_t *hdr, const struct hdr_info *h,
		       uint8_t *aad)
{
	uint16_t fc = h->fc;
	size_t n;

	if ((fc & FC_TYPE_MASK) == FC_TYPE_DATA)
		fc &= (uint16_t)~0x0070;
	fc &= (uint16_t)~(FC_RETRY | FC_PWRMGT | FC_MOREDATA);
	fc |= FC_PROTECTED;
	if (h->qos)
		fc &= (uint16_t)~FC_ORDER;
	put_le16(aad, fc);
	memcpy(aad + 2, hdr + 4, 18);	/* A1 A2 A3 */
	aad[20] = hdr[22] & 0x0f;	/* fragment number only */
	aad[21] = 0;
	n = 22;
	if (h->has_a4) {
		memcpy(aad + n, hdr + 24, 6);
		n += 6;
	}
	if (h->qos) {
		aad[n++] = h->tid;
		aad[n++] = 0;
	}
	return n;
}

static void ccmp_nonce(const struct hdr_info *h, uint64_t pn, uint8_t nonce[13])
{
	nonce[0] = h->tid;
	memcpy(nonce + 1, h->a2, 6);
	for (int i = 0; i < 6; i++)
		nonce[7 + i] = (uint8_t)(pn >> (8 * (5 - i)));
}

static int ccmp_encrypt(struct xg_key *k, const uint8_t *hdr, size_t hdr_len,
			const uint8_t *body, size_t len, uint8_t *out)
{
	struct hdr_info h;
	uint8_t aad[32], nonce[13];
	size_t aad_len;
	uint64_t pn;

	if (parse_hdr(hdr, hdr_len, &h))
		return -1;
	pn = ++k->tx_pn;
	out[0] = (uint8_t)pn;
	out[1] = (uint8_t)(pn >> 8);
	out[2] = 0;
	out[3] = (uint8_t)(0x20 | (k->key_idx << 6));
	out[4] = (uint8_t)(pn >> 16);
	out[5] = (uint8_t)(pn >> 24);
	out[6] = (uint8_t)(pn >> 32);
	out[7] = (uint8_t)(pn >> 40);

	aad_len = ccmp_aad(hdr, &h, aad);
	ccmp_nonce(&h, pn, nonce);
	if (ccm_encrypt(k->aes, nonce, aad, aad_len, body, len,
			out + CCMP_HDR_LEN, out + CCMP_HDR_LEN + len))
		return -1;
	return (int)(len + CCMP_HDR_LEN + CCMP_MIC_LEN);
}

static int ccmp_decrypt(struct xg_key *k, const uint8_t *hdr, size_t hdr_len,
			const uint8_t *body, size_t len, uint8_t *out)
{
	struct hdr_info h;
	uint8_t aad[32], nonce[13];
	size_t aad_len, plen;
	uint64_t pn;
	int tid_idx, r;

	if (parse_hdr(hdr, hdr_len, &h) || len < CCMP_HDR_LEN + CCMP_MIC_LEN)
		return -1;
	if (!(body[3] & 0x20))
		return -1; /* no extended IV: not CCMP */
	pn = (uint64_t)body[0] | ((uint64_t)body[1] << 8) |
	     ((uint64_t)body[4] << 16) | ((uint64_t)body[5] << 24) |
	     ((uint64_t)body[6] << 32) | ((uint64_t)body[7] << 40);
	tid_idx = h.qos ? h.tid : 16;
	if (pn <= k->rx_pn[tid_idx])
		return -3;

	plen = len - CCMP_HDR_LEN - CCMP_MIC_LEN;
	aad_len = ccmp_aad(hdr, &h, aad);
	ccmp_nonce(&h, pn, nonce);
	r = ccm_decrypt(k->aes, nonce, aad, aad_len, body + CCMP_HDR_LEN, plen,
			out, body + CCMP_HDR_LEN + plen);
	if (r)
		return r;
	k->rx_pn[tid_idx] = pn;
	return (int)plen;
}

/* --- TKIP --------------------------------------------------------------- */

static uint16_t tkip_sbox[256];
static int tkip_sbox_ready;

/* The TKIP S-box is derived from the AES one: (2*s << 8) | (3*s). */
static void tkip_sbox_init(void)
{
	uint8_t aes_sbox[256];
	uint8_t p = 1, q = 1;

	do {
		uint8_t x;

		/* multiply p by 3, divide q by 3 in GF(2^8) */
		p = (uint8_t)(p ^ (uint8_t)(p << 1) ^ ((p & 0x80) ? 0x1b : 0));
		q ^= (uint8_t)(q << 1);
		q ^= (uint8_t)(q << 2);
		q ^= (uint8_t)(q << 4);
		if (q & 0x80)
			q ^= 0x09;
		x = (uint8_t)(q ^ (uint8_t)((q << 1) | (q >> 7)) ^
			      (uint8_t)((q << 2) | (q >> 6)) ^
			      (uint8_t)((q << 3) | (q >> 5)) ^
			      (uint8_t)((q << 4) | (q >> 4)));
		aes_sbox[p] = x ^ 0x63;
	} while (p != 1);
	aes_sbox[0] = 0x63;

	for (int i = 0; i < 256; i++) {
		uint8_t s = aes_sbox[i];
		uint8_t s2 = (uint8_t)((s << 1) ^ ((s & 0x80) ? 0x1b : 0));

		tkip_sbox[i] = (uint16_t)((s2 << 8) | (s2 ^ s));
	}
	tkip_sbox_ready = 1;
}

static inline uint16_t tkip_s(uint16_t v)
{
	uint16_t hi = tkip_sbox[v >> 8];

	return (uint16_t)(tkip_sbox[v & 0xff] ^ (uint16_t)((hi << 8) | (hi >> 8)));
}

static inline uint16_t ror16(uint16_t v)
{
	return (uint16_t)((v >> 1) | (v << 15));
}

void tkip_phase1(uint16_t p1k[5], const uint8_t tk[16], const uint8_t ta[6],
		 uint32_t iv32)
{
	if (!tkip_sbox_ready)
		tkip_sbox_init();
	p1k[0] = (uint16_t)iv32;
	p1k[1] = (uint16_t)(iv32 >> 16);
	p1k[2] = get_le16(ta + 0);
	p1k[3] = get_le16(ta + 2);
	p1k[4] = get_le16(ta + 4);

	for (int i = 0; i < 8; i++) {
		int j = 2 * (i & 1);

		p1k[0] += tkip_s(p1k[4] ^ get_le16(tk + 0 + j));
		p1k[1] += tkip_s(p1k[0] ^ get_le16(tk + 4 + j));
		p1k[2] += tkip_s(p1k[1] ^ get_le16(tk + 8 + j));
		p1k[3] += tkip_s(p1k[2] ^ get_le16(tk + 12 + j));
		p1k[4] += (uint16_t)(tkip_s(p1k[3] ^ get_le16(tk + 0 + j)) + i);
	}
}

void tkip_phase2(uint8_t rc4key[16], const uint8_t tk[16],
		 const uint16_t p1k[5], uint16_t iv16)
{
	uint16_t ppk[6];

	if (!tkip_sbox_ready)
		tkip_sbox_init();
	memcpy(ppk, p1k, 5 * sizeof(uint16_t));
	ppk[5] = (uint16_t)(p1k[4] + iv16);

	ppk[0] += tkip_s(ppk[5] ^ get_le16(tk + 0));
	ppk[1] += tkip_s(ppk[0] ^ get_le16(tk + 2));
	ppk[2] += tkip_s(ppk[1] ^ get_le16(tk + 4));
	ppk[3] += tkip_s(ppk[2] ^ get_le16(tk + 6));
	ppk[4] += tkip_s(ppk[3] ^ get_le16(tk + 8));
	ppk[5] += tkip_s(ppk[4] ^ get_le16(tk + 10));
	ppk[0] += ror16(ppk[5] ^ get_le16(tk + 12));
	ppk[1] += ror16(ppk[0] ^ get_le16(tk + 14));
	ppk[2] += ror16(ppk[1]);
	ppk[3] += ror16(ppk[2]);
	ppk[4] += ror16(ppk[3]);
	ppk[5] += ror16(ppk[4]);

	rc4key[0] = (uint8_t)(iv16 >> 8);
	rc4key[1] = (uint8_t)(((iv16 >> 8) | 0x20) & 0x7f);
	rc4key[2] = (uint8_t)iv16;
	rc4key[3] = (uint8_t)((ppk[5] ^ get_le16(tk)) >> 1);
	for (int i = 0; i < 6; i++) {
		rc4key[4 + 2 * i] = (uint8_t)ppk[i];
		rc4key[5 + 2 * i] = (uint8_t)(ppk[i] >> 8);
	}
}

static inline uint32_t rol32(uint32_t v, int n)
{
	return (v << n) | (v >> (32 - n));
}

static inline uint32_t get_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static inline void put_le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static void michael_block(uint32_t *l, uint32_t *r)
{
	*r ^= rol32(*l, 17);
	*l += *r;
	*r ^= ((*l & 0xff00ff00) >> 8) | ((*l & 0x00ff00ff) << 8);
	*l += *r;
	*r ^= rol32(*l, 3);
	*l += *r;
	*r ^= rol32(*l, 30); /* rotate right by 2 */
	*l += *r;
}

void michael_mic(const uint8_t key[8], const uint8_t *hdr16,
		 const uint8_t *data, size_t len, uint8_t mic[8])
{
	uint32_t l = get_le32(key), r = get_le32(key + 4), val;
	size_t blocks = len / 4, left = len % 4;

	if (hdr16) {
		for (int i = 0; i < 4; i++) {
			l ^= get_le32(hdr16 + 4 * i);
			michael_block(&l, &r);
		}
	}
	for (size_t i = 0; i < blocks; i++) {
		l ^= get_le32(data + 4 * i);
		michael_block(&l, &r);
	}
	/* padding: 0x5a, then 4 to 7 zero bytes */
	val = 0x5a;
	while (left > 0) {
		val <<= 8;
		left--;
		val |= data[blocks * 4 + left];
	}
	l ^= val;
	michael_block(&l, &r);
	/* last block is zero, so l ^ 0 = l */
	michael_block(&l, &r);

	put_le32(mic, l);
	put_le32(mic + 4, r);
}

static uint32_t crc32_ieee(const uint8_t *data, size_t len)
{
	static uint32_t table[256];
	static int ready;
	uint32_t crc = 0xffffffff;

	if (!ready) {
		for (uint32_t i = 0; i < 256; i++) {
			uint32_t c = i;

			for (int k = 0; k < 8; k++)
				c = (c & 1) ? 0xedb88320 ^ (c >> 1) : c >> 1;
			table[i] = c;
		}
		ready = 1;
	}
	for (size_t i = 0; i < len; i++)
		crc = table[(crc ^ data[i]) & 0xff] ^ (crc >> 8);
	return ~crc;
}

static void michael_hdr(const struct hdr_info *h, uint8_t mh[16])
{
	memcpy(mh, h->da, 6);
	memcpy(mh + 6, h->sa, 6);
	mh[12] = h->tid;
	mh[13] = mh[14] = mh[15] = 0;
}

static int tkip_encrypt(struct xg_key *k, const uint8_t *hdr, size_t hdr_len,
			const uint8_t *body, size_t len, uint8_t *out)
{
	struct hdr_info h;
	uint8_t mh[16], rc4key[16];
	uint16_t p1k[5], iv16;
	uint32_t iv32, icv;
	uint64_t tsc;
	uint8_t *p = out + TKIP_HDR_LEN;

	if (parse_hdr(hdr, hdr_len, &h))
		return -1;
	tsc = ++k->tx_pn;
	iv16 = (uint16_t)tsc;
	iv32 = (uint32_t)(tsc >> 16);

	out[0] = (uint8_t)(iv16 >> 8);
	out[1] = (uint8_t)(((iv16 >> 8) | 0x20) & 0x7f);
	out[2] = (uint8_t)iv16;
	out[3] = (uint8_t)(0x20 | (k->key_idx << 6));
	put_le32(out + 4, iv32);

	memcpy(p, body, len);
	michael_hdr(&h, mh);
	michael_mic(k->mic_tx, mh, body, len, p + len);
	icv = crc32_ieee(p, len + TKIP_MIC_LEN);
	put_le32(p + len + TKIP_MIC_LEN, icv);

	tkip_phase1(p1k, k->tk, h.a2, iv32);
	tkip_phase2(rc4key, k->tk, p1k, iv16);
	rc4_skip(rc4key, 16, 0, p, len + TKIP_MIC_LEN + TKIP_ICV_LEN);
	return (int)(len + TKIP_HDR_LEN + TKIP_MIC_LEN + TKIP_ICV_LEN);
}

static int tkip_decrypt(struct xg_key *k, const uint8_t *hdr, size_t hdr_len,
			const uint8_t *body, size_t len, uint8_t *out)
{
	struct hdr_info h;
	uint8_t buf[MAX_BODY + 16];
	uint8_t mh[16], mic[8], rc4key[16];
	uint16_t iv16;
	uint32_t iv32;
	uint64_t tsc;
	size_t clen, plen;
	int tid_idx;

	if (parse_hdr(hdr, hdr_len, &h) ||
	    len < TKIP_HDR_LEN + TKIP_MIC_LEN + TKIP_ICV_LEN ||
	    len > MAX_BODY)
		return -1;
	if (!(body[3] & 0x20))
		return -1;
	iv16 = (uint16_t)((body[0] << 8) | body[2]);
	iv32 = get_le32(body + 4);
	tsc = ((uint64_t)iv32 << 16) | iv16;
	tid_idx = h.qos ? h.tid : 16;
	if (tsc <= k->rx_pn[tid_idx])
		return -3;

	if (!k->rx_p1k_valid || k->rx_p1k_iv32 != iv32) {
		tkip_phase1(k->rx_p1k, k->tk, h.a2, iv32);
		k->rx_p1k_iv32 = iv32;
		k->rx_p1k_valid = 1;
	}
	tkip_phase2(rc4key, k->tk, k->rx_p1k, iv16);

	clen = len - TKIP_HDR_LEN;
	memcpy(buf, body + TKIP_HDR_LEN, clen);
	rc4_skip(rc4key, 16, 0, buf, clen);
	plen = clen - TKIP_MIC_LEN - TKIP_ICV_LEN;
	if (crc32_ieee(buf, clen - TKIP_ICV_LEN) !=
	    get_le32(buf + clen - TKIP_ICV_LEN))
		return -2;
	michael_hdr(&h, mh);
	michael_mic(k->mic_rx, mh, buf, plen, mic);
	if (memcmp(mic, buf + plen, TKIP_MIC_LEN) != 0)
		return -2;

	memcpy(out, buf, plen);
	k->rx_pn[tid_idx] = tsc;
	return (int)plen;
}

/* --- key handling ------------------------------------------------------- */

int xg_key_set(struct xg_key *k, enum xg_cipher cipher, int key_idx,
	       const uint8_t *material, size_t len, const uint8_t *rsc)
{
	uint64_t pn = 0;

	xg_key_clear(k);
	if (rsc)
		for (int i = 5; i >= 0; i--)
			pn = (pn << 8) | rsc[i];

	switch (cipher) {
	case XG_CIPHER_CCMP:
		if (len != 16)
			return -1;
		k->aes = aes_ctx_new(material);
		if (!k->aes)
			return -1;
		break;
	case XG_CIPHER_TKIP:
		if (len != 32)
			return -1;
		memcpy(k->tk, material, 16);
		/* we are the supplicant: we receive with the authenticator's
		 * Michael key and send with our own */
		memcpy(k->mic_rx, material + 16, 8);
		memcpy(k->mic_tx, material + 24, 8);
		break;
	default:
		return -1;
	}
	k->cipher = cipher;
	k->key_idx = key_idx;
	for (int i = 0; i < 17; i++)
		k->rx_pn[i] = pn;
	return 0;
}

void xg_key_clear(struct xg_key *k)
{
	aes_ctx_free(k->aes);
	memset(k, 0, sizeof(*k));
}

int xg_encrypt(struct xg_key *k, const uint8_t *hdr, size_t hdr_len,
	       const uint8_t *body, size_t len, uint8_t *out)
{
	if (len > MAX_BODY - 32)
		return -1;
	switch (k->cipher) {
	case XG_CIPHER_CCMP:
		return ccmp_encrypt(k, hdr, hdr_len, body, len, out);
	case XG_CIPHER_TKIP:
		return tkip_encrypt(k, hdr, hdr_len, body, len, out);
	default:
		return -1;
	}
}

int xg_decrypt(struct xg_key *k, const uint8_t *hdr, size_t hdr_len,
	       const uint8_t *body, size_t len, uint8_t *out)
{
	if (len > MAX_BODY)
		return -1;
	switch (k->cipher) {
	case XG_CIPHER_CCMP:
		return ccmp_decrypt(k, hdr, hdr_len, body, len, out);
	case XG_CIPHER_TKIP:
		return tkip_decrypt(k, hdr, hdr_len, body, len, out);
	default:
		return -1;
	}
}

int xg_frame_key_idx(const uint8_t *body, size_t len)
{
	if (len < 4)
		return -1;
	return body[3] >> 6;
}
