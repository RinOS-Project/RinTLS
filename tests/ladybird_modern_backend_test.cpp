/*
 * Copyright (c) 2026, RinOS Contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibCrypto/Curves/EdwardsCurve.h>
#include <LibCrypto/Curves/SECPxxxr1.h>
#include <LibCrypto/PK/MLDSA.h>
#include <LibCrypto/PK/MLKEM.h>
#include <LibCrypto/PK/RSA.h>

#include <string.h>

static constexpr u8 message[] {
    0x52, 0x69, 0x6e, 0x4f, 0x53, 0x20, 0x72, 0x69,
    0x6e, 0x74, 0x6c, 0x73, 0x20, 0x62, 0x61, 0x63,
    0x6b, 0x65, 0x6e, 0x64,
};

static ErrorOr<ByteBuffer> deterministic_seed(u8 domain, size_t size)
{
    auto seed = TRY(ByteBuffer::create_uninitialized(size));
    for (size_t index = 0; index < seed.size(); ++index)
        seed[index] = static_cast<u8>(domain + index);
    return seed;
}

template<typename Curve>
static bool test_nist_curve()
{
    Curve curve;
    Crypto::UnsignedBigInteger alice_private_key { 1 };
    Crypto::UnsignedBigInteger bob_private_key { 2 };
    u8 digest[64] {};
    for (size_t index = 0; index < sizeof(digest); ++index)
        digest[index] = static_cast<u8>(0x80 + index);

    auto alice_public_key = curve.generate_public_key(alice_private_key);
    if (alice_public_key.is_error())
        return false;
    auto bob_public_key = curve.generate_public_key(bob_private_key);
    if (bob_public_key.is_error())
        return false;

    auto alice_shared = curve.compute_coordinate(alice_private_key, bob_public_key.value());
    if (alice_shared.is_error())
        return false;
    auto bob_shared = curve.compute_coordinate(bob_private_key, alice_public_key.value());
    if (bob_shared.is_error() || alice_shared.value().x != bob_shared.value().x)
        return false;

    auto signature = curve.sign({ digest, sizeof(digest) }, alice_private_key);
    if (signature.is_error())
        return false;
    auto verified = curve.verify({ digest, sizeof(digest) }, alice_public_key.value(), signature.value());
    if (verified.is_error() || !verified.value())
        return false;

    auto invalid_signature = signature.release_value();
    invalid_signature.r = Crypto::UnsignedBigInteger { 0 };
    auto rejected = curve.verify({ digest, sizeof(digest) }, alice_public_key.release_value(), invalid_signature);
    return !rejected.is_error() && !rejected.value();
}

template<typename Curve>
static bool test_edwards_signature(ReadonlyBytes context = {})
{
    Curve curve;
    auto private_key = curve.generate_private_key();
    if (private_key.is_error())
        return false;
    auto public_key = curve.generate_public_key(private_key.value());
    if (public_key.is_error())
        return false;
    auto signature = curve.sign(private_key.value(), message, context);
    if (signature.is_error())
        return false;
    auto verified = curve.verify(public_key.value(), signature.value(), message, context);
    if (verified.is_error() || !verified.value())
        return false;

    auto invalid_signature = signature.release_value();
    invalid_signature[0] ^= 0x80;
    auto rejected = curve.verify(public_key.value(), invalid_signature, message, context);
    return !rejected.is_error() && !rejected.value();
}

static bool test_x448()
{
    Crypto::Curves::X448 curve;
    auto alice_private_key = curve.generate_private_key();
    if (alice_private_key.is_error())
        return false;
    auto bob_private_key = curve.generate_private_key();
    if (bob_private_key.is_error())
        return false;
    auto alice_public_key = curve.generate_public_key(alice_private_key.value());
    if (alice_public_key.is_error())
        return false;
    auto bob_public_key = curve.generate_public_key(bob_private_key.value());
    if (bob_public_key.is_error())
        return false;
    auto alice_shared = curve.compute_coordinate(alice_private_key.value(), bob_public_key.value());
    if (alice_shared.is_error())
        return false;
    auto bob_shared = curve.compute_coordinate(bob_private_key.value(), alice_public_key.value());
    return !bob_shared.is_error() && alice_shared.value() == bob_shared.value();
}

static bool test_mldsa_key_pair(Crypto::PK::MLDSASize size, ByteBuffer seed)
{
    auto key_pair = Crypto::PK::MLDSA::generate_key_pair(size, move(seed));
    if (key_pair.is_error())
        return false;
    auto pair = key_pair.release_value();
    Crypto::PK::MLDSA signer { size, pair.private_key, {} };
    Crypto::PK::MLDSA verifier { size, pair.public_key, {} };
    auto signature = signer.sign(message);
    if (signature.is_error())
        return false;
    auto verified = verifier.verify(message, signature.value());
    if (verified.is_error() || !verified.value())
        return false;

    auto invalid_signature = signature.release_value();
    invalid_signature[0] ^= 0x01;
    auto rejected = verifier.verify(message, invalid_signature);
    return !rejected.is_error() && !rejected.value();
}

static bool test_mldsa(Crypto::PK::MLDSASize size, u8 domain)
{
    auto seed = deterministic_seed(domain, 32);
    if (seed.is_error())
        return false;
    if (!test_mldsa_key_pair(size, seed.release_value()))
        return false;

    // An empty seed is the public LibCrypto request for provider-owned
    // entropy. Exercise it separately from the deterministic import path.
    return test_mldsa_key_pair(size, {});
}

static bool test_mlkem_key_pair(Crypto::PK::MLKEMSize size, ByteBuffer seed)
{
    auto key_pair = Crypto::PK::MLKEM::generate_key_pair(size, move(seed));
    if (key_pair.is_error())
        return false;
    auto pair = key_pair.release_value();
    auto encapsulation = Crypto::PK::MLKEM::encapsulate(size, pair.public_key);
    if (encapsulation.is_error())
        return false;
    auto result = encapsulation.release_value();
    auto ciphertext = ByteBuffer::copy(result.ciphertext);
    auto tampered_ciphertext = ByteBuffer::copy(result.ciphertext);
    if (ciphertext.is_error() || tampered_ciphertext.is_error())
        return false;
    auto shared_key = Crypto::PK::MLKEM::decapsulate(size, pair.private_key, ciphertext.release_value());
    if (shared_key.is_error() || shared_key.value() != result.shared_key)
        return false;
    auto invalid_ciphertext = tampered_ciphertext.release_value();
    invalid_ciphertext[0] ^= 0x01;
    auto implicit_rejection_key = Crypto::PK::MLKEM::decapsulate(size, pair.private_key, move(invalid_ciphertext));
    return !implicit_rejection_key.is_error() && implicit_rejection_key.value() != result.shared_key;
}

static bool test_mlkem(Crypto::PK::MLKEMSize size, u8 domain)
{
    auto seed = deterministic_seed(domain, 64);
    if (seed.is_error())
        return false;
    if (!test_mlkem_key_pair(size, seed.release_value()))
        return false;

    // See test_mldsa(): key generation without a supplied seed must traverse
    // the only allowed RinTLS entropy boundary, not a provider-local PRNG.
    return test_mlkem_key_pair(size, {});
}

static bool test_rsa_webcrypto_algorithms()
{
    static constexpr u8 plaintext[] {
        0x52, 0x69, 0x6e, 0x4f, 0x53, 0x20, 0x72, 0x69,
        0x6e, 0x74, 0x6c, 0x73, 0x20, 0x52, 0x53, 0x41,
    };
    static constexpr u8 label[] { 0x72, 0x69, 0x6e, 0x2d, 0x6c, 0x61, 0x62, 0x65, 0x6c };

    auto key_pair = Crypto::PK::RSA::generate_key_pair(2048u);
    if (key_pair.is_error())
        return false;
    auto pair = key_pair.release_value();
    if (pair.public_key.length() != 256u || pair.private_key.length() != 256u)
        return false;
    auto public_valid = pair.public_key.is_valid();
    auto private_valid = pair.private_key.is_valid();
    if (public_valid.is_error() || private_valid.is_error() || !public_valid.value() || !private_valid.value())
        return false;

    Crypto::PK::RSA raw { pair };
    if (!raw.encrypt(plaintext).is_error() || !raw.sign(plaintext).is_error())
        return false;

    Crypto::PK::RSA_OAEP_EME oaep_encrypt { Crypto::Hash::HashKind::SHA256, pair.public_key };
    Crypto::PK::RSA_OAEP_EME oaep_decrypt { Crypto::Hash::HashKind::SHA256, pair.private_key };
    oaep_encrypt.set_label(label);
    oaep_decrypt.set_label(label);
    auto ciphertext = oaep_encrypt.encrypt(plaintext);
    if (ciphertext.is_error() || ciphertext.value().size() != pair.public_key.length())
        return false;
    auto recovered = oaep_decrypt.decrypt(ciphertext.value());
    if (recovered.is_error() || recovered.value().size() != sizeof(plaintext)
        || memcmp(recovered.value().data(), plaintext, sizeof(plaintext)) != 0)
        return false;

    Crypto::PK::RSA_PKCS1_EMSA pkcs1_signer { Crypto::Hash::HashKind::SHA256, pair.private_key };
    Crypto::PK::RSA_PKCS1_EMSA pkcs1_verifier { Crypto::Hash::HashKind::SHA256, pair.public_key };
    auto pkcs1_signature = pkcs1_signer.sign(plaintext);
    if (pkcs1_signature.is_error() || pkcs1_signature.value().size() != pair.public_key.length())
        return false;
    auto pkcs1_verified = pkcs1_verifier.verify(plaintext, pkcs1_signature.value());
    if (pkcs1_verified.is_error() || !pkcs1_verified.value())
        return false;
    auto tampered_pkcs1_signature = ByteBuffer::copy(pkcs1_signature.value());
    if (tampered_pkcs1_signature.is_error())
        return false;
    tampered_pkcs1_signature.value()[0] ^= 0x80;
    auto pkcs1_rejected = pkcs1_verifier.verify(plaintext, tampered_pkcs1_signature.value());
    if (pkcs1_rejected.is_error() || pkcs1_rejected.value())
        return false;

    Crypto::PK::RSA_PSS_EMSA pss_signer { Crypto::Hash::HashKind::SHA256, pair.private_key };
    Crypto::PK::RSA_PSS_EMSA pss_verifier { Crypto::Hash::HashKind::SHA256, pair.public_key };
    pss_signer.set_salt_length(32);
    pss_verifier.set_salt_length(32);
    auto pss_signature = pss_signer.sign(plaintext);
    if (pss_signature.is_error() || pss_signature.value().size() != pair.public_key.length())
        return false;
    auto pss_verified = pss_verifier.verify(plaintext, pss_signature.value());
    if (pss_verified.is_error() || !pss_verified.value())
        return false;
    auto tampered_pss_signature = ByteBuffer::copy(pss_signature.value());
    if (tampered_pss_signature.is_error())
        return false;
    tampered_pss_signature.value()[0] ^= 0x80;
    auto pss_rejected = pss_verifier.verify(plaintext, tampered_pss_signature.value());
    return !pss_rejected.is_error() && !pss_rejected.value();
}

int main()
{
    static constexpr u8 ed448_context[] { 0x72, 0x69, 0x6e };

    if (!test_nist_curve<Crypto::Curves::SECP384r1>())
        return 1;
    if (!test_nist_curve<Crypto::Curves::SECP521r1>())
        return 2;
    if (!test_edwards_signature<Crypto::Curves::Ed25519>())
        return 3;
    if (!test_edwards_signature<Crypto::Curves::Ed448>(ed448_context))
        return 4;
    if (!test_x448())
        return 5;

    if (!test_mldsa(Crypto::PK::MLDSA44, 0x10))
        return 6;
    if (!test_mldsa(Crypto::PK::MLDSA65, 0x20))
        return 7;
    if (!test_mldsa(Crypto::PK::MLDSA87, 0x30))
        return 8;

    if (!test_mlkem(Crypto::PK::MLKEMSize::MLKEM512, 0x40))
        return 9;
    if (!test_mlkem(Crypto::PK::MLKEMSize::MLKEM768, 0x50))
        return 10;
    if (!test_mlkem(Crypto::PK::MLKEMSize::MLKEM1024, 0x60))
        return 11;

    if (!test_rsa_webcrypto_algorithms())
        return 12;

    return 0;
}
