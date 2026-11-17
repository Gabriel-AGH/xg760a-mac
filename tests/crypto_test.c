/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/* Known-answer tests for src/crypto.c (published IEEE / RFC vectors). */
#include <stdio.h>
#include <string.h>

#include "crypto.h"

static int failures;

static void check(const char *name, const uint8_t *got, const uint8_t *want,
		  size_t len)
{
	if (memcmp(got, want, len) == 0) {
		printf("ok    %s\n", name);
		return;
	}
	failures++;
	printf("ÉCHEC %s\n  obtenu :", name);
	for (size_t i = 0; i < len; i++)
		printf(" %02x", got[i]);
	printf("\n  attendu:");
	for (size_t i = 0; i < len; i++)
		printf(" %02x", want[i]);
	printf("\n");
}

static void test_pbkdf2(void)
{
	/* IEEE 802.11i H.4.3, test 1 */
	static const uint8_t want[32] = {
		0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef, 0x9e, 0xbb, 0x4b,
		0x90, 0xb3, 0x8a, 0x5f, 0x90, 0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a,
		0x70, 0xe2, 0x3a, 0xed, 0x76, 0x2e, 0x97, 0x10, 0xa1, 0x2e,
	};
	uint8_t pmk[32];

	wpa_passphrase_to_pmk("password", (const uint8_t *)"IEEE", 4, pmk);
	check("PBKDF2 (phrase -> PMK)", pmk, want, 32);
}

static void test_prf(void)
{
	/* IEEE 802.11i H.3, PRF test case 1 */
	static const uint8_t want[24] = {
		0xbc, 0xd4, 0xc6, 0x50, 0xb3, 0x0b, 0x96, 0x84,
		0x95, 0x18, 0x29, 0xe0, 0xd7, 0x5f, 0x9d, 0x54,
		0xb8, 0x62, 0x17, 0x5e, 0xd9, 0xf0, 0x06, 0x06,
	};
	uint8_t key[20], out[24];

	memset(key, 0x0b, sizeof(key));
	wpa_prf(key, sizeof(key), "prefix", (const uint8_t *)"Hi There", 8, out,
		sizeof(out));
	check("PRF-192", out, want, sizeof(want));
}

static void test_unwrap(void)
{
	/* RFC 3394 4.1 */
	static const uint8_t kek[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
					 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
					 0x0c, 0x0d, 0x0e, 0x0f };
	static const uint8_t cipher[24] = {
		0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47,
		0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a, 0x7b, 0x82,
		0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5,
	};
	static const uint8_t want[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
					  0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
					  0xcc, 0xdd, 0xee, 0xff };
	uint8_t plain[16] = { 0 };
	uint8_t bad[24];
	int r = aes_unwrap(kek, 2, cipher, plain);

	if (r)
		memset(plain, 0xee, sizeof(plain));
	check("AES key unwrap", plain, want, 16);
	memcpy(bad, cipher, sizeof(bad));
	bad[20] ^= 1;
	if (aes_unwrap(kek, 2, bad, plain) == 0) {
		failures++;
		printf("ÉCHEC AES key unwrap: altération non détectée\n");
	} else {
		printf("ok    AES key unwrap: altération détectée\n");
	}
}

static void test_ccm(void)
{
	/* RFC 3610, packet vector #1 */
	static const uint8_t key[16] = { 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5,
					 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
					 0xcc, 0xcd, 0xce, 0xcf };
	static const uint8_t nonce[13] = { 0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00,
					   0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	static const uint8_t want[31] = {
		0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2, 0xf0, 0x66, 0xd0,
		0xc2, 0xc0, 0xf9, 0x89, 0x80, 0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3,
		0x84, 0x17, 0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0,
	};
	uint8_t packet[31], out[31], back[23];
	struct aes_ctx *c = aes_ctx_new(key);

	for (int i = 0; i < 31; i++)
		packet[i] = (uint8_t)i;
	ccm_encrypt(c, nonce, packet, 8, packet + 8, 23, out, out + 23);
	check("AES-CCM chiffrement (RFC 3610 #1)", out, want, 31);
	if (ccm_decrypt(c, nonce, packet, 8, out, 23, back, out + 23) != 0)
		memset(back, 0xee, sizeof(back));
	check("AES-CCM déchiffrement", back, packet + 8, 23);
	out[3] ^= 0x10;
	if (ccm_decrypt(c, nonce, packet, 8, out, 23, back, out + 23) == 0) {
		failures++;
		printf("ÉCHEC AES-CCM: altération non détectée\n");
	} else {
		printf("ok    AES-CCM: altération détectée\n");
	}
	aes_ctx_free(c);
}

static void test_ccmp(void)
{
	/* IEEE 802.11-2012 M.6.4 */
	static const uint8_t tk[16] = { 0xc9, 0x7c, 0x1f, 0x67, 0xce, 0x37,
					0x11, 0x85, 0x51, 0x4a, 0x8a, 0x19,
					0xf2, 0xbd, 0xd5, 0x2f };
	static const uint8_t hdr[24] = {
		0x08, 0x48, 0xc3, 0x2c, 0x0f, 0xd2, 0xe1, 0x28,
		0xa5, 0x7c, 0x50, 0x30, 0xf1, 0x84, 0x44, 0x08,
		0xab, 0xae, 0xa5, 0xb8, 0xfc, 0xba, 0x80, 0x33,
	};
	static const uint8_t plain[20] = {
		0xf8, 0xba, 0x1a, 0x55, 0xd0, 0x2f, 0x85, 0xae, 0x96, 0x7b,
		0xb6, 0x2f, 0xb6, 0xcd, 0xa8, 0xeb, 0x7e, 0x78, 0xa0, 0x50,
	};
	static const uint8_t want[36] = {
		0x0c, 0xe7, 0x00, 0x20, 0x76, 0x97, 0x03, 0xb5,
		0xf3, 0xd0, 0xa2, 0xfe, 0x9a, 0x3d, 0xbf, 0x23, 0x42, 0xa6,
		0x43, 0xe4, 0x32, 0x46, 0xe8, 0x0c, 0x3c, 0x04, 0xd0, 0x19,
		0x78, 0x45, 0xce, 0x0b, 0x16, 0xf9, 0x76, 0x23,
	};
	struct xg_key k, k2;
	uint8_t out[64], back[64];
	int n;

	memset(&k, 0, sizeof(k));
	memset(&k2, 0, sizeof(k2));
	xg_key_set(&k, XG_CIPHER_CCMP, 0, tk, 16, NULL);
	k.tx_pn = 0xb5039776e70cULL - 1;
	n = xg_encrypt(&k, hdr, sizeof(hdr), plain, sizeof(plain), out);
	if (n != 36)
		memset(out, 0xee, sizeof(out));
	check("CCMP chiffrement (IEEE 802.11 M.6.4)", out, want, 36);

	xg_key_set(&k2, XG_CIPHER_CCMP, 0, tk, 16, NULL);
	n = xg_decrypt(&k2, hdr, sizeof(hdr), want, 36, back);
	if (n != 20)
		memset(back, 0xee, sizeof(back));
	check("CCMP déchiffrement", back, plain, 20);
	if (xg_decrypt(&k2, hdr, sizeof(hdr), want, 36, back) != -3) {
		failures++;
		printf("ÉCHEC CCMP: rejeu non détecté\n");
	} else {
		printf("ok    CCMP: rejeu détecté\n");
	}
	xg_key_clear(&k);
	xg_key_clear(&k2);
}

static void test_tkip(void)
{
	/* IEEE 802.11i H.5.2, test vector 1 */
	static const uint8_t tk[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
					0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
					0x0c, 0x0d, 0x0e, 0x0f };
	static const uint8_t ta[6] = { 0x10, 0x22, 0x33, 0x44, 0x55, 0x66 };
	static const uint16_t want_p1k[5] = { 0x3dd2, 0x016e, 0x76f4, 0x8697,
					      0xb2e8 };
	static const uint8_t want_rc4[16] = { 0x00, 0x20, 0x00, 0x33, 0xea, 0x8d,
					      0x2f, 0x60, 0xca, 0x6d, 0x13, 0x74,
					      0x23, 0x4a, 0x66, 0x0b };
	static const uint8_t want_rc4_2[16] = { 0x00, 0x20, 0x01, 0x90, 0xff,
						0xdc, 0x31, 0x43, 0x89, 0xa9,
						0xd9, 0xd0, 0x74, 0xfd, 0x20,
						0xaa };
	uint16_t p1k[5];
	uint8_t rc4key[16];

	tkip_phase1(p1k, tk, ta, 0);
	check("TKIP phase 1", (const uint8_t *)p1k, (const uint8_t *)want_p1k,
	      sizeof(p1k));
	tkip_phase2(rc4key, tk, p1k, 0);
	check("TKIP phase 2 (IV16=0)", rc4key, want_rc4, 16);
	tkip_phase2(rc4key, tk, p1k, 1);
	check("TKIP phase 2 (IV16=1)", rc4key, want_rc4_2, 16);
}

static void test_michael(void)
{
	/* IEEE 802.11i H.6.1: each MIC is the key of the next test */
	static const char *const msg[] = { "", "M", "Mi", "Mic", "Mich",
					   "Michael" };
	static const uint8_t want[6][8] = {
		{ 0x82, 0x92, 0x5c, 0x1c, 0xa1, 0xd1, 0x30, 0xb8 },
		{ 0x43, 0x47, 0x21, 0xca, 0x40, 0x63, 0x9b, 0x3f },
		{ 0xe8, 0xf9, 0xbe, 0xca, 0xe9, 0x7e, 0x5d, 0x29 },
		{ 0x90, 0x03, 0x8f, 0xc6, 0xcf, 0x13, 0xc1, 0xdb },
		{ 0xd5, 0x5e, 0x10, 0x05, 0x10, 0x12, 0x89, 0x86 },
		{ 0x0a, 0x94, 0x2b, 0x12, 0x4e, 0xca, 0xa5, 0x46 },
	};
	uint8_t key[8] = { 0 }, mic[8];

	for (int i = 0; i < 6; i++) {
		char name[48];

		michael_mic(key, NULL, (const uint8_t *)msg[i], strlen(msg[i]),
			    mic);
		snprintf(name, sizeof(name), "Michael \"%s\"", msg[i]);
		check(name, mic, want[i], 8);
		memcpy(key, want[i], 8);
	}
}

static void test_tkip_roundtrip(void)
{
	static const uint8_t hdr_tx[24] = {
		0x08, 0x41, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x60, 0xb3, 0x01, 0x02, 0x03, 0x11, 0x22, 0x33, 0x44,
		0x55, 0x66, 0x10, 0x00,
	};
	uint8_t material[32], swapped[32];
	uint8_t plain[100], out[160], back[160];
	struct xg_key tx, rx;
	int n, m;

	for (int i = 0; i < 32; i++)
		material[i] = (uint8_t)(0x40 + i);
	for (int i = 0; i < 100; i++)
		plain[i] = (uint8_t)(3 * i + 1);
	/* the peer uses the two Michael keys the other way round */
	memcpy(swapped, material, 16);
	memcpy(swapped + 16, material + 24, 8);
	memcpy(swapped + 24, material + 16, 8);

	memset(&tx, 0, sizeof(tx));
	memset(&rx, 0, sizeof(rx));
	xg_key_set(&tx, XG_CIPHER_TKIP, 0, material, 32, NULL);
	xg_key_set(&rx, XG_CIPHER_TKIP, 0, swapped, 32, NULL);
	n = xg_encrypt(&tx, hdr_tx, 24, plain, 100, out);
	m = n > 0 ? xg_decrypt(&rx, hdr_tx, 24, out, (size_t)n, back) : -9;
	if (n != 120 || m != 100)
		memset(back, 0xee, sizeof(back));
	check("TKIP aller-retour", back, plain, 100);
	n = xg_encrypt(&tx, hdr_tx, 24, plain, 100, out);
	out[40] ^= 4;
	if (xg_decrypt(&rx, hdr_tx, 24, out, (size_t)n, back) != -2) {
		failures++;
		printf("ÉCHEC TKIP: altération non détectée\n");
	} else {
		printf("ok    TKIP: altération détectée\n");
	}
}

int main(void)
{
	test_pbkdf2();
	test_prf();
	test_unwrap();
	test_ccm();
	test_ccmp();
	test_tkip();
	test_michael();
	test_tkip_roundtrip();
	printf("%s\n", failures ? "DES TESTS ONT ECHOUE" : "tous les tests passent");
	return failures ? 1 : 0;
}
