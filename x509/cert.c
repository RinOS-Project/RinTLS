/*
 * rinTLS - X.509証明書パーサー
 * RFC 5280準拠
 */

#include "cert.h"
#include "../crypto/sha256.h"
#include "../platform/rin_platform.h"

#if defined(RIN_USERSPACE)
#include "../../libc/time.h"
#elif !defined(RIN_FREESTANDING)
#include <time.h>
#endif

/* ═══════════════════════════════════════
 * OID定義
 * ═══════════════════════════════════════ */

/* 署名アルゴリズムOID */
static const u8 OID_RSA_SHA1[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05};
static const u8 OID_RSA_SHA256[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B};
static const u8 OID_RSA_SHA384[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C};
static const u8 OID_RSA_SHA512[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D};
static const u8 OID_ECDSA_SHA256[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02};
static const u8 OID_ECDSA_SHA384[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03};
static const u8 OID_ECDSA_SHA512[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04};

/* 公開鍵アルゴリズムOID */
static const u8 OID_RSA_ENCRYPTION[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
static const u8 OID_EC_PUBLIC_KEY[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
static const u8 OID_EC_P256[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
static const u8 OID_EC_P384[] = {0x2B, 0x81, 0x04, 0x00, 0x22};
static const u8 OID_EC_P521[] = {0x2B, 0x81, 0x04, 0x00, 0x23};

/* 名前属性OID */
static const u8 OID_CN[] = {0x55, 0x04, 0x03};  /* commonName */

/* 拡張OID */
static const u8 OID_BASIC_CONSTRAINTS[] = {0x55, 0x1D, 0x13};
static const u8 OID_SUBJECT_ALT_NAME[] = {0x55, 0x1D, 0x11};

/* ═══════════════════════════════════════
 * ASN.1パーサー
 * ═══════════════════════════════════════ */

int asn1_read_tag(const u8** p, const u8* end, u8* tag, rin_size_t* len)
{
    if (*p >= end) return -1;

    *tag = **p;
    (*p)++;

    if (*p >= end) return -1;

    u8 first = **p;
    (*p)++;

    if (first < 0x80) {
        *len = first;
    } else if (first == 0x81) {
        if (*p >= end) return -1;
        *len = **p;
        (*p)++;
    } else if (first == 0x82) {
        if (*p + 1 >= end) return -1;
        *len = ((rin_size_t)(*p)[0] << 8) | (*p)[1];
        *p += 2;
    } else if (first == 0x83) {
        if (*p + 2 >= end) return -1;
        *len = ((rin_size_t)(*p)[0] << 16) | ((rin_size_t)(*p)[1] << 8) | (*p)[2];
        *p += 3;
    } else {
        return -1;
    }

    if (*p + *len > end) return -1;

    return 0;
}

int asn1_read_integer(const u8** p, const u8* end, u8* out, rin_size_t* out_len, rin_size_t max_len)
{
    u8 tag;
    rin_size_t len;

    if (asn1_read_tag(p, end, &tag, &len) < 0) return -1;
    if (tag != ASN1_INTEGER) return -1;

    /* 先頭の0x00をスキップ */
    while (len > 0 && **p == 0x00) {
        (*p)++;
        len--;
    }

    if (len > max_len) return -1;

    rintls_memcpy(out, *p, len);
    *out_len = len;
    *p += len;

    return 0;
}

int asn1_read_oid(const u8** p, const u8* end, const u8* expected_oid, rin_size_t oid_len)
{
    u8 tag;
    rin_size_t len;

    if (asn1_read_tag(p, end, &tag, &len) < 0) return -1;
    if (tag != ASN1_OID) return -1;

    if (expected_oid) {
        if (len != oid_len) {
            *p += len;
            return -1;
        }
        if (rintls_memcmp(*p, expected_oid, oid_len) != 0) {
            *p += len;
            return -1;
        }
    }

    *p += len;
    return 0;
}

int asn1_read_time(const u8** p, const u8* end, x509_time_t* time)
{
    u8 tag;
    rin_size_t len;

    if (asn1_read_tag(p, end, &tag, &len) < 0) return -1;

    if (tag == ASN1_UTC_TIME && len >= 12) {
        /* YYMMDDHHMMSSZ */
        time->year = ((*p)[0] - '0') * 10 + ((*p)[1] - '0');
        time->year += (time->year < 50) ? 2000 : 1900;
        time->month = ((*p)[2] - '0') * 10 + ((*p)[3] - '0');
        time->day = ((*p)[4] - '0') * 10 + ((*p)[5] - '0');
        time->hour = ((*p)[6] - '0') * 10 + ((*p)[7] - '0');
        time->minute = ((*p)[8] - '0') * 10 + ((*p)[9] - '0');
        time->second = ((*p)[10] - '0') * 10 + ((*p)[11] - '0');
    } else if (tag == ASN1_GENERALIZED_TIME && len >= 14) {
        /* YYYYMMDDHHMMSSZ */
        time->year = ((*p)[0] - '0') * 1000 + ((*p)[1] - '0') * 100 +
                     ((*p)[2] - '0') * 10 + ((*p)[3] - '0');
        time->month = ((*p)[4] - '0') * 10 + ((*p)[5] - '0');
        time->day = ((*p)[6] - '0') * 10 + ((*p)[7] - '0');
        time->hour = ((*p)[8] - '0') * 10 + ((*p)[9] - '0');
        time->minute = ((*p)[10] - '0') * 10 + ((*p)[11] - '0');
        time->second = ((*p)[12] - '0') * 10 + ((*p)[13] - '0');
    } else {
        *p += len;
        return -1;
    }

    *p += len;
    return 0;
}

/* ═══════════════════════════════════════
 * 署名アルゴリズムをパース
 * ═══════════════════════════════════════ */

static int parse_sig_alg(const u8** p, const u8* end)
{
    u8 tag;
    rin_size_t len;

    if (asn1_read_tag(p, end, &tag, &len) < 0) return -1;
    if (tag != ASN1_SEQUENCE) return -1;

    const u8* seq_end = *p + len;

    /* OIDを読み取り */
    if (asn1_read_tag(p, seq_end, &tag, &len) < 0) return -1;
    if (tag != ASN1_OID) return -1;

    int alg = -1;
    if (len == sizeof(OID_RSA_SHA1) && rintls_memcmp(*p, OID_RSA_SHA1, len) == 0) {
        alg = X509_SIG_RSA_SHA1;
    } else if (len == sizeof(OID_RSA_SHA256) && rintls_memcmp(*p, OID_RSA_SHA256, len) == 0) {
        alg = X509_SIG_RSA_SHA256;
    } else if (len == sizeof(OID_RSA_SHA384) && rintls_memcmp(*p, OID_RSA_SHA384, len) == 0) {
        alg = X509_SIG_RSA_SHA384;
    } else if (len == sizeof(OID_RSA_SHA512) && rintls_memcmp(*p, OID_RSA_SHA512, len) == 0) {
        alg = X509_SIG_RSA_SHA512;
    } else if (len == sizeof(OID_ECDSA_SHA256) && rintls_memcmp(*p, OID_ECDSA_SHA256, len) == 0) {
        alg = X509_SIG_ECDSA_SHA256;
    } else if (len == sizeof(OID_ECDSA_SHA384) && rintls_memcmp(*p, OID_ECDSA_SHA384, len) == 0) {
        alg = X509_SIG_ECDSA_SHA384;
    } else if (len == sizeof(OID_ECDSA_SHA512) && rintls_memcmp(*p, OID_ECDSA_SHA512, len) == 0) {
        alg = X509_SIG_ECDSA_SHA512;
    }

    *p = seq_end;
    return alg;
}

/* ═══════════════════════════════════════
 * 名前(DN)から共通名(CN)を抽出
 * ═══════════════════════════════════════ */

static int parse_name_cn(const u8** p, const u8* end, char* cn, rin_size_t max_len)
{
    u8 tag;
    rin_size_t len;

    /* Name ::= SEQUENCE OF RelativeDistinguishedName */
    if (asn1_read_tag(p, end, &tag, &len) < 0) return -1;
    if (tag != ASN1_SEQUENCE) return -1;

    const u8* name_end = *p + len;

    while (*p < name_end) {
        /* RelativeDistinguishedName ::= SET OF AttributeTypeAndValue */
        if (asn1_read_tag(p, name_end, &tag, &len) < 0) break;
        if (tag != ASN1_SET) continue;

        const u8* set_end = *p + len;

        /* AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY } */
        if (asn1_read_tag(p, set_end, &tag, &len) < 0) continue;
        if (tag != ASN1_SEQUENCE) {
            *p = set_end;
            continue;
        }

        const u8* atv_end = *p + len;

        /* type (OID) */
        if (asn1_read_tag(p, atv_end, &tag, &len) < 0) {
            *p = set_end;
            continue;
        }
        if (tag != ASN1_OID) {
            *p = set_end;
            continue;
        }

        int is_cn = (len == sizeof(OID_CN) && rintls_memcmp(*p, OID_CN, len) == 0);
        *p += len;

        /* value */
        if (asn1_read_tag(p, atv_end, &tag, &len) < 0) {
            *p = set_end;
            continue;
        }

        if (is_cn && len < max_len) {
            rintls_memcpy(cn, *p, len);
            cn[len] = '\0';
        }

        *p = set_end;
    }

    return 0;
}

/* ═══════════════════════════════════════
 * 公開鍵をパース
 * ═══════════════════════════════════════ */

static int parse_public_key(x509_cert_t* cert, const u8** p, const u8* end)
{
    u8 tag;
    rin_size_t len;

    /* SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey } */
    if (asn1_read_tag(p, end, &tag, &len) < 0) return -1;
    if (tag != ASN1_SEQUENCE) return -1;

    const u8* spki_end = *p + len;

    /* AlgorithmIdentifier */
    if (asn1_read_tag(p, spki_end, &tag, &len) < 0) return -1;
    if (tag != ASN1_SEQUENCE) return -1;

    const u8* alg_end = *p + len;

    /* OIDを読み取り */
    if (asn1_read_tag(p, alg_end, &tag, &len) < 0) return -1;
    if (tag != ASN1_OID) return -1;

    if (len == sizeof(OID_RSA_ENCRYPTION) &&
        rintls_memcmp(*p, OID_RSA_ENCRYPTION, len) == 0) {
        cert->key_type = X509_KEY_RSA;
    } else if (len == sizeof(OID_EC_PUBLIC_KEY) &&
               rintls_memcmp(*p, OID_EC_PUBLIC_KEY, len) == 0) {
        cert->key_type = X509_KEY_ECDSA;
    } else {
        return X509_ERR_UNSUPPORTED;
    }
    *p += len;
    if (cert->key_type == X509_KEY_ECDSA) {
        if (asn1_read_tag(p, alg_end, &tag, &len) < 0 || tag != ASN1_OID)
            return X509_ERR_UNSUPPORTED;
        if (len == sizeof(OID_EC_P256) && rintls_memcmp(*p, OID_EC_P256, len) == 0)
            cert->pubkey.ecdsa.curve = ECDSA_CURVE_P256;
        else if (len == sizeof(OID_EC_P384) && rintls_memcmp(*p, OID_EC_P384, len) == 0)
            cert->pubkey.ecdsa.curve = ECDSA_CURVE_P384;
        else if (len == sizeof(OID_EC_P521) && rintls_memcmp(*p, OID_EC_P521, len) == 0)
            cert->pubkey.ecdsa.curve = ECDSA_CURVE_P521;
        else
            return X509_ERR_UNSUPPORTED;
        *p += len;
    }
    *p = alg_end;

    /* subjectPublicKey (BIT STRING) */
    if (asn1_read_tag(p, spki_end, &tag, &len) < 0) return -1;
    if (tag != ASN1_BIT_STRING) return -1;

    /* 最初のバイトは未使用ビット数 */
    if (len < 1) return -1;
    u8 unused_bits = **p;
    (*p)++;
    len--;
    if (unused_bits != 0) return X509_ERR_PARSE;

    if (cert->key_type == X509_KEY_RSA) {
        /* RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER } */
        if (asn1_read_tag(p, spki_end, &tag, &len) < 0) return -1;
        if (tag != ASN1_SEQUENCE) return -1;

        const u8* rsa_end = *p + len;

        /* modulus */
        u8 n[512];
        rin_size_t n_len;
        if (asn1_read_integer(p, rsa_end, n, &n_len, sizeof(n)) < 0) return -1;

        /* publicExponent */
        u8 e[8];
        rin_size_t e_len;
        if (asn1_read_integer(p, rsa_end, e, &e_len, sizeof(e)) < 0) return -1;

        if (rsa_pubkey_set(&cert->pubkey.rsa, n, n_len, e, e_len) != RSA_OK)
            return X509_ERR_PARSE;

    } else if (cert->key_type == X509_KEY_ECDSA) {
        /* ECポイント (非圧縮形式: 0x04 || x || y) */
        rin_size_t expected = cert->pubkey.ecdsa.curve == ECDSA_CURVE_P256 ? 65 :
                              cert->pubkey.ecdsa.curve == ECDSA_CURVE_P384 ? 97 : 133;
        if (len != expected || len > sizeof(cert->pubkey.ecdsa.point) || **p != 0x04)
            return X509_ERR_PARSE;
        rintls_memcpy(cert->pubkey.ecdsa.point, *p, len);
        cert->pubkey.ecdsa.point_len = len;
        *p += len;
    }

    *p = spki_end;
    return X509_OK;
}

/* ═══════════════════════════════════════
 * 拡張をパース
 * ═══════════════════════════════════════ */

static int parse_extensions(x509_cert_t* cert, const u8** p, const u8* end)
{
    u8 tag;
    rin_size_t len;

    /* Extensions ::= SEQUENCE OF Extension */
    if (asn1_read_tag(p, end, &tag, &len) < 0) return -1;
    if (tag != ASN1_SEQUENCE) return -1;

    const u8* ext_end = *p + len;

    while (*p < ext_end) {
        /* Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING } */
        if (asn1_read_tag(p, ext_end, &tag, &len) < 0) break;
        if (tag != ASN1_SEQUENCE) continue;

        const u8* single_ext_end = *p + len;

        /* extnID (OID) */
        if (asn1_read_tag(p, single_ext_end, &tag, &len) < 0) {
            *p = single_ext_end;
            continue;
        }
        if (tag != ASN1_OID) {
            *p = single_ext_end;
            continue;
        }

        int is_basic_constraints = (len == sizeof(OID_BASIC_CONSTRAINTS) &&
                                    rintls_memcmp(*p, OID_BASIC_CONSTRAINTS, len) == 0);
        int is_san = (len == sizeof(OID_SUBJECT_ALT_NAME) &&
                      rintls_memcmp(*p, OID_SUBJECT_ALT_NAME, len) == 0);
        *p += len;

        /* critical (optional) */
        if (*p < single_ext_end) {
            if (asn1_read_tag(p, single_ext_end, &tag, &len) < 0) {
                *p = single_ext_end;
                continue;
            }
            if (tag == ASN1_BOOLEAN) {
                *p += len;
                /* extnValue */
                if (asn1_read_tag(p, single_ext_end, &tag, &len) < 0) {
                    *p = single_ext_end;
                    continue;
                }
            }
            if (tag != ASN1_OCTET_STRING) {
                *p = single_ext_end;
                continue;
            }
        }

        const u8* value_data = *p;
        rin_size_t value_len = len;

        if (is_basic_constraints) {
            /* BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL } */
            const u8* bc_p = value_data;
            if (asn1_read_tag(&bc_p, value_data + value_len, &tag, &len) == 0 && tag == ASN1_SEQUENCE) {
                const u8* bc_end = bc_p + len;
                if (bc_p < bc_end && asn1_read_tag(&bc_p, bc_end, &tag, &len) == 0) {
                    if (tag == ASN1_BOOLEAN && len == 1) {
                        cert->is_ca = (*bc_p != 0);
                    }
                }
            }
        } else if (is_san) {
            /* SubjectAltName ::= GeneralNames */
            const u8* san_p = value_data;
            if (asn1_read_tag(&san_p, value_data + value_len, &tag, &len) == 0 && tag == ASN1_SEQUENCE) {
                const u8* san_end = san_p + len;
                cert->san_names_data = san_p;
                cert->san_names_len = len;
                while (san_p < san_end) {
                    if (asn1_read_tag(&san_p, san_end, &tag, &len) < 0) break;
                    /* dNSName [2] */
                    if (tag == 0x82 && len < X509_MAX_SAN_SIZE - 1) {
                        rintls_memcpy(cert->san, san_p, len);
                        cert->san[len] = '\0';
                        break;
                    }
                    san_p += len;
                }
            }
        }

        *p = single_ext_end;
    }

    return X509_OK;
}

/* ═══════════════════════════════════════
 * 証明書パース
 * ═══════════════════════════════════════ */

int x509_parse_cert(x509_cert_t* cert, const u8* der, rin_size_t len)
{
    rintls_memset(cert, 0, sizeof(x509_cert_t));
    cert->raw_data = der;
    cert->raw_len = len;

    const u8* p = der;
    const u8* end = der + len;
    u8 tag;
    rin_size_t slen;

    /* Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature } */
    if (asn1_read_tag(&p, end, &tag, &slen) < 0) return X509_ERR_PARSE;
    if (tag != ASN1_SEQUENCE) return X509_ERR_PARSE;

    const u8* cert_end = p + slen;

    /* TBSCertificate */
    cert->tbs_data = p;
    if (asn1_read_tag(&p, cert_end, &tag, &slen) < 0) return X509_ERR_PARSE;
    if (tag != ASN1_SEQUENCE) return X509_ERR_PARSE;
    cert->tbs_len = (p - cert->tbs_data) + slen;

    const u8* tbs_end = p + slen;

    /* version [0] EXPLICIT INTEGER DEFAULT v1 */
    if (*p == ASN1_CONTEXT_0) {
        const u8* version_end;
        if (asn1_read_tag(&p, tbs_end, &tag, &slen) < 0 ||
            tag != ASN1_CONTEXT_0 || slen == 0) {
            return X509_ERR_PARSE;
        }
        version_end = p + slen;
        if (version_end > tbs_end ||
            asn1_read_tag(&p, version_end, &tag, &slen) < 0 ||
            tag != ASN1_INTEGER || slen != 1 || p + slen != version_end) {
            return X509_ERR_PARSE;
        }
        cert->version = *p + 1;
        p = version_end;
    } else {
        cert->version = 1;
    }

    /* serialNumber */
    if (asn1_read_integer(&p, tbs_end, cert->serial, &cert->serial_len, sizeof(cert->serial)) < 0) {
        return X509_ERR_PARSE;
    }

    /* signature (algorithm) */
    cert->sig_alg = parse_sig_alg(&p, tbs_end);
    if (cert->sig_alg < 0) return X509_ERR_UNSUPPORTED;

    /* issuer */
    cert->issuer_name = p;
    if (parse_name_cn(&p, tbs_end, cert->issuer_cn, sizeof(cert->issuer_cn)) < 0) {
        return X509_ERR_PARSE;
    }
    cert->issuer_name_len = (rin_size_t)(p - cert->issuer_name);

    /* validity */
    if (asn1_read_tag(&p, tbs_end, &tag, &slen) < 0) return X509_ERR_PARSE;
    if (tag != ASN1_SEQUENCE) return X509_ERR_PARSE;
    const u8* validity_end = p + slen;
    if (asn1_read_time(&p, validity_end, &cert->not_before) < 0) return X509_ERR_PARSE;
    if (asn1_read_time(&p, validity_end, &cert->not_after) < 0) return X509_ERR_PARSE;

    /* subject */
    cert->subject_name = p;
    if (parse_name_cn(&p, tbs_end, cert->subject_cn, sizeof(cert->subject_cn)) < 0) {
        return X509_ERR_PARSE;
    }
    cert->subject_name_len = (rin_size_t)(p - cert->subject_name);

    /* subjectPublicKeyInfo */
    if (parse_public_key(cert, &p, tbs_end) != X509_OK) {
        return X509_ERR_PARSE;
    }

    /* extensions [3] EXPLICIT Extensions OPTIONAL */
    if (p < tbs_end && *p == ASN1_CONTEXT_3) {
        const u8* extensions_end;
        if (asn1_read_tag(&p, tbs_end, &tag, &slen) < 0 ||
            tag != ASN1_CONTEXT_3) {
            return X509_ERR_PARSE;
        }
        extensions_end = p + slen;
        if (extensions_end > tbs_end ||
            parse_extensions(cert, &p, extensions_end) != X509_OK ||
            p != extensions_end) {
            return X509_ERR_PARSE;
        }
    }

    p = tbs_end;

    /* signatureAlgorithm must repeat the TBSCertificate algorithm exactly. */
    if (parse_sig_alg(&p, cert_end) != cert->sig_alg) return X509_ERR_PARSE;

    /* signature (BIT STRING) */
    if (asn1_read_tag(&p, cert_end, &tag, &slen) < 0) return X509_ERR_PARSE;
    if (tag != ASN1_BIT_STRING) return X509_ERR_PARSE;
    if (slen < 1) return X509_ERR_PARSE;
    p++;  /* unused bits */
    slen--;
    if (slen > sizeof(cert->signature)) return X509_ERR_PARSE;
    rintls_memcpy(cert->signature, p, slen);
    cert->signature_len = slen;

    return X509_OK;
}

void x509_cert_clear(x509_cert_t* cert)
{
    if (cert->key_type == X509_KEY_RSA) {
        rsa_pubkey_clear(&cert->pubkey.rsa);
    }
    rintls_memset(cert, 0, sizeof(x509_cert_t));
}

/* ═══════════════════════════════════════
 * 証明書検証
 * ═══════════════════════════════════════ */

int x509_verify_signature(const x509_cert_t* cert, const x509_cert_t* issuer)
{
    u8 hash[64];
    rin_size_t hash_len;

    /* TBSCertificateをハッシュ */
    switch (cert->sig_alg) {
    case X509_SIG_RSA_SHA256:
    case X509_SIG_ECDSA_SHA256:
        sha256(cert->tbs_data, cert->tbs_len, hash);
        hash_len = 32;
        break;
    case X509_SIG_RSA_SHA384:
    case X509_SIG_ECDSA_SHA384:
        sha384(cert->tbs_data, cert->tbs_len, hash);
        hash_len = 48;
        break;
    case X509_SIG_RSA_SHA512:
    case X509_SIG_ECDSA_SHA512:
        sha512(cert->tbs_data, cert->tbs_len, hash);
        hash_len = 64;
        break;
    case X509_SIG_RSA_SHA1:
        /* SHA-1 is recognized so legacy self-signed trust anchors can be
         * provisioned, but no peer-chain edge may validate with it. */
        return X509_ERR_UNSUPPORTED;
    default:
        return X509_ERR_UNSUPPORTED;
    }

    /* 署名を検証 */
    if (issuer->key_type == X509_KEY_RSA) {
        if (cert->sig_alg != X509_SIG_RSA_SHA256 &&
            cert->sig_alg != X509_SIG_RSA_SHA384 &&
            cert->sig_alg != X509_SIG_RSA_SHA512) return X509_ERR_UNSUPPORTED;
        int hash_alg = (cert->sig_alg == X509_SIG_RSA_SHA256) ? RSA_HASH_SHA256 :
                       (cert->sig_alg == X509_SIG_RSA_SHA384) ? RSA_HASH_SHA384 : RSA_HASH_SHA512;

        if (rsa_pkcs1_verify(cert->signature, cert->signature_len,
                             hash, hash_len, hash_alg,
                             &issuer->pubkey.rsa) != RSA_OK) {
            return X509_ERR_SIGNATURE;
        }
    } else if (issuer->key_type == X509_KEY_ECDSA) {
        if (cert->sig_alg != X509_SIG_ECDSA_SHA256 &&
            cert->sig_alg != X509_SIG_ECDSA_SHA384 &&
            cert->sig_alg != X509_SIG_ECDSA_SHA512) return X509_ERR_UNSUPPORTED;
        if (ecdsa_nist_verify(issuer->pubkey.ecdsa.curve,
                              cert->signature, cert->signature_len,
                              hash, hash_len, issuer->pubkey.ecdsa.point,
                              issuer->pubkey.ecdsa.point_len) != ECDH_OK) {
            return X509_ERR_SIGNATURE;
        }
    } else {
        return X509_ERR_UNSUPPORTED;
    }

    return X509_OK;
}

int x509_is_self_signed(const x509_cert_t* cert)
{
    return cert && cert->issuer_name && cert->subject_name &&
           cert->issuer_name_len != 0 &&
           cert->issuer_name_len == cert->subject_name_len &&
           rintls_memcmp(cert->issuer_name, cert->subject_name,
                         cert->issuer_name_len) == 0;
}

int x509_time_cmp(const x509_time_t* a, const x509_time_t* b)
{
    if (a->year != b->year) return (a->year < b->year) ? -1 : 1;
    if (a->month != b->month) return (a->month < b->month) ? -1 : 1;
    if (a->day != b->day) return (a->day < b->day) ? -1 : 1;
    if (a->hour != b->hour) return (a->hour < b->hour) ? -1 : 1;
    if (a->minute != b->minute) return (a->minute < b->minute) ? -1 : 1;
    if (a->second != b->second) return (a->second < b->second) ? -1 : 1;
    return 0;
}

void x509_get_current_time(x509_time_t* time)
{
    if (!time) return;

#if defined(RIN_USERSPACE) || !defined(RIN_FREESTANDING)
    struct timeval now;
    struct tm utc;

    if (gettimeofday(&now, NULL) != 0 || now.tv_sec < 0 ||
        !gmtime_r(&now.tv_sec, &utc)) {
        rintls_memset(time, 0, sizeof(*time));
        return;
    }

    time->year = utc.tm_year + 1900;
    time->month = utc.tm_mon + 1;
    time->day = utc.tm_mday;
    time->hour = utc.tm_hour;
    time->minute = utc.tm_min;
    time->second = utc.tm_sec;
#else
    /* Kernel TLS has no trusted realtime source configured yet. */
    rintls_memset(time, 0, sizeof(*time));
#endif
}

int x509_check_validity(const x509_cert_t* cert)
{
    x509_time_t now;
    x509_get_current_time(&now);

    if (now.year == 0) {
        /* Certificate validity cannot be established without trusted wall
         * clock input.  Security-sensitive callers must fail closed. */
        return X509_ERR_EXPIRED;
    }

    if (x509_time_cmp(&now, &cert->not_before) < 0) {
        return X509_ERR_EXPIRED;  /* まだ有効でない */
    }
    if (x509_time_cmp(&now, &cert->not_after) > 0) {
        return X509_ERR_EXPIRED;  /* 期限切れ */
    }

    return X509_OK;
}

static int x509_is_leap_year(u32 year)
{
    return (year % 4u == 0u && year % 100u != 0u) ||
           year % 400u == 0u;
}

static u32 x509_days_in_month(u32 year, u32 month)
{
    static const u8 days[] = {
        31u, 28u, 31u, 30u, 31u, 30u,
        31u, 31u, 30u, 31u, 30u, 31u
    };
    if (month == 0u || month > 12u) return 0u;
    if (month == 2u && x509_is_leap_year(year)) return 29u;
    return days[month - 1u];
}

static int x509_time_from_unix(u64 unix_time, x509_time_t* time)
{
    u64 days;
    u64 seconds;
    u32 year = 1970u;
    u32 month = 1u;
    if (!time || unix_time > 253402300799ULL) return 0;
    days = unix_time / 86400ULL;
    seconds = unix_time % 86400ULL;
    while (year <= 9999u) {
        u32 year_days = x509_is_leap_year(year) ? 366u : 365u;
        if (days < year_days) break;
        days -= year_days;
        ++year;
    }
    if (year > 9999u) return 0;
    while (month <= 12u) {
        u32 month_days = x509_days_in_month(year, month);
        if (days < month_days) break;
        days -= month_days;
        ++month;
    }
    if (month > 12u) return 0;
    time->year = (int)year;
    time->month = (int)month;
    time->day = (int)days + 1;
    time->hour = (int)(seconds / 3600ULL);
    seconds %= 3600ULL;
    time->minute = (int)(seconds / 60ULL);
    time->second = (int)(seconds % 60ULL);
    return 1;
}

int x509_check_validity_at(const x509_cert_t* cert, u64 unix_time)
{
    x509_time_t now;
    if (!cert || !x509_time_from_unix(unix_time, &now))
        return X509_ERR_EXPIRED;
    if (x509_time_cmp(&now, &cert->not_before) < 0 ||
        x509_time_cmp(&now, &cert->not_after) > 0)
        return X509_ERR_EXPIRED;
    return X509_OK;
}

static char x509_ascii_lower(char c)
{
    if (c >= 'A' && c <= 'Z') return (char)(c + ('a' - 'A'));
    return c;
}

static int x509_dns_name_matches(const u8* pattern, rin_size_t pattern_len,
                                 const char* hostname)
{
    rin_size_t host_len = 0;
    rin_size_t pattern_offset = 0;
    rin_size_t host_offset = 0;

    if (!pattern || !hostname || pattern_len == 0) return 0;
    while (hostname[host_len]) host_len++;
    if (host_len == 0) return 0;

    /* RFC 6125 wildcard form: a complete left-most label only. It must match
     * exactly one non-empty hostname label, never the bare suffix or multiple
     * labels. */
    if (pattern_len >= 3 && pattern[0] == '*' && pattern[1] == '.') {
        while (host_offset < host_len && hostname[host_offset] != '.')
            host_offset++;
        if (host_offset == 0 || host_offset >= host_len)
            return 0;
        host_offset++;
        pattern_offset = 2;
    }

    if (pattern_len - pattern_offset != host_len - host_offset)
        return 0;

    while (pattern_offset < pattern_len) {
        char expected = (char)pattern[pattern_offset++];
        char actual = hostname[host_offset++];
        if (expected == '\0' || expected == '*' ||
            x509_ascii_lower(expected) != x509_ascii_lower(actual)) {
            return 0;
        }
    }
    return 1;
}

int x509_check_hostname(const x509_cert_t* cert, const char* hostname)
{
    int saw_dns_san = 0;

    /* A SAN extension can contain many names. Keep the DER-backed GeneralNames
     * sequence and inspect all dNSName entries; modern public certificates
     * commonly place the requested host after unrelated names. */
    if (cert->san_names_data && cert->san_names_len > 0) {
        const u8* san_p = cert->san_names_data;
        const u8* san_end = san_p + cert->san_names_len;
        while (san_p < san_end) {
            u8 tag;
            rin_size_t len;
            if (asn1_read_tag(&san_p, san_end, &tag, &len) < 0)
                return X509_ERR_NAME;
            if (tag == 0x82) {
                saw_dns_san = 1;
                if (x509_dns_name_matches(san_p, len, hostname))
                    return X509_OK;
            }
            san_p += len;
        }
        if (saw_dns_san)
            return X509_ERR_NAME;
    } else if (cert->san[0]) {
        /* Compatibility for callers that construct x509_cert_t manually. */
        rin_size_t san_len = 0;
        while (cert->san[san_len]) san_len++;
        if (x509_dns_name_matches((const u8*)cert->san, san_len, hostname))
            return X509_OK;
        return X509_ERR_NAME;
    }

    /* CN fallback is permitted only when no dNSName SAN exists. */
    if (cert->subject_cn[0]) {
        rin_size_t cn_len = 0;
        while (cert->subject_cn[cn_len]) cn_len++;
        if (x509_dns_name_matches((const u8*)cert->subject_cn, cn_len, hostname))
            return X509_OK;
    }

    return X509_ERR_NAME;
}

int x509_trust_identity_matches(const x509_cert_t* candidate,
                                const x509_cert_t* trusted)
{
    if (!candidate || !trusted || !candidate->is_ca || !trusted->is_ca ||
        !candidate->subject_name || !trusted->subject_name ||
        candidate->subject_name_len == 0 ||
        candidate->subject_name_len != trusted->subject_name_len ||
        rintls_memcmp(candidate->subject_name, trusted->subject_name,
                      candidate->subject_name_len) != 0 ||
        candidate->key_type != trusted->key_type) {
        return 0;
    }

    if (candidate->key_type == X509_KEY_RSA) {
        return candidate->pubkey.rsa.bits == trusted->pubkey.rsa.bits &&
               bn_cmp(&candidate->pubkey.rsa.n, &trusted->pubkey.rsa.n) == 0 &&
               bn_cmp(&candidate->pubkey.rsa.e, &trusted->pubkey.rsa.e) == 0;
    }

    if (candidate->key_type == X509_KEY_ECDSA) {
        return candidate->pubkey.ecdsa.curve == trusted->pubkey.ecdsa.curve &&
               candidate->pubkey.ecdsa.point_len == trusted->pubkey.ecdsa.point_len &&
               candidate->pubkey.ecdsa.point_len != 0 &&
               rintls_memcmp(candidate->pubkey.ecdsa.point,
                             trusted->pubkey.ecdsa.point,
                             candidate->pubkey.ecdsa.point_len) == 0;
    }

    return 0;
}

int x509_verify_chain(x509_cert_t* certs, int cert_count, const char* hostname)
{
    if (cert_count < 1) return X509_ERR_CHAIN;

    /* リーフ証明書のホスト名をチェック */
    int ret = x509_check_hostname(&certs[0], hostname);
    if (ret != X509_OK) return ret;

    /* 各証明書の有効期間をチェック */
    for (int i = 0; i < cert_count; i++) {
        ret = x509_check_validity(&certs[i]);
        if (ret != X509_OK) return ret;
    }

    /* チェーンの署名を検証 */
    for (int i = 0; i < cert_count - 1; i++) {
        ret = x509_verify_signature(&certs[i], &certs[i + 1]);
        if (ret != X509_OK) return ret;

        /* 発行者がCA証明書であることを確認 */
        if (!certs[i + 1].is_ca && !x509_is_self_signed(&certs[i + 1])) {
            return X509_ERR_CA;
        }
    }

    /* 最後の証明書（ルート）は自己署名または既知のCAであるべき */
    x509_cert_t* root = &certs[cert_count - 1];
    if (x509_is_self_signed(root)) {
        ret = x509_verify_signature(root, root);
        if (ret != X509_OK) return ret;
    }

    return X509_OK;
}
