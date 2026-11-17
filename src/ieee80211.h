/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/* The few IEEE 802.11 definitions this driver needs. */
#ifndef XG_IEEE80211_H
#define XG_IEEE80211_H

#include <stdint.h>
#include <string.h>

#define IEEE80211_ADDR_LEN 6
#define IEEE80211_HDR_LEN 24
#define IEEE80211_MAX_SSID_LEN 32
#define IEEE80211_MAX_FRAME_LEN 2352

/* frame control, as a little-endian 16-bit value */
#define FC_TYPE_MASK 0x000c
#define FC_TYPE_MGMT 0x0000
#define FC_TYPE_CTRL 0x0004
#define FC_TYPE_DATA 0x0008
#define FC_SUBTYPE_MASK 0x00f0
#define FC_TODS 0x0100
#define FC_FROMDS 0x0200
#define FC_MOREFRAG 0x0400
#define FC_RETRY 0x0800
#define FC_PWRMGT 0x1000
#define FC_MOREDATA 0x2000
#define FC_PROTECTED 0x4000
#define FC_ORDER 0x8000

/* type + subtype */
#define FC_ASSOC_REQ 0x0000
#define FC_ASSOC_RESP 0x0010
#define FC_REASSOC_RESP 0x0030
#define FC_PROBE_REQ 0x0040
#define FC_PROBE_RESP 0x0050
#define FC_BEACON 0x0080
#define FC_DISASSOC 0x00a0
#define FC_AUTH 0x00b0
#define FC_DEAUTH 0x00c0
#define FC_ACTION 0x00d0
#define FC_DATA 0x0008
#define FC_NULLFUNC 0x0048
#define FC_QOS_DATA 0x0088
/* data subtype bits */
#define FC_STYPE_DATA_NODATA 0x0040
#define FC_STYPE_DATA_QOS 0x0080

/* capability information */
#define CAP_ESS 0x0001
#define CAP_IBSS 0x0002
#define CAP_PRIVACY 0x0010
#define CAP_SHORT_PREAMBLE 0x0020
#define CAP_SHORT_SLOT 0x0400

/* information elements */
#define IE_SSID 0
#define IE_SUPP_RATES 1
#define IE_DS_PARAMS 3
#define IE_TIM 5
#define IE_COUNTRY 7
#define IE_ERP 42
#define IE_HT_CAP 45
#define IE_RSN 48
#define IE_EXT_SUPP_RATES 50
#define IE_VENDOR 221

#define ERP_NON_ERP_PRESENT 0x01
#define ERP_USE_PROTECTION 0x02
#define ERP_BARKER_PREAMBLE 0x04

/* reason / status codes worth naming */
#define REASON_UNSPECIFIED 1
#define REASON_PREV_AUTH_NOT_VALID 2
#define REASON_DEAUTH_LEAVING 3
#define REASON_MIC_FAILURE 14
#define REASON_4WAY_HANDSHAKE_TIMEOUT 15

#define ETHERTYPE_EAPOL 0x888e

struct ieee80211_hdr3 {
	uint8_t fc[2];
	uint8_t duration[2];
	uint8_t addr1[6];
	uint8_t addr2[6];
	uint8_t addr3[6];
	uint8_t seq_ctrl[2];
} __attribute__((packed));

static inline uint16_t get_le16(const uint8_t *p)
{
	return (uint16_t)(p[0] | (p[1] << 8));
}

static inline uint16_t get_be16(const uint8_t *p)
{
	return (uint16_t)((p[0] << 8) | p[1]);
}

static inline void put_le16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static inline void put_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static inline int addr_is_group(const uint8_t *a)
{
	return a[0] & 1;
}

static inline int addr_equal(const uint8_t *a, const uint8_t *b)
{
	return memcmp(a, b, 6) == 0;
}

#endif /* XG_IEEE80211_H */
