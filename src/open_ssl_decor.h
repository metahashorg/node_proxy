#ifndef CRYPTO_TEMPLATES_HPP
#define CRYPTO_TEMPLATES_HPP


// Containers
#include <string_view>
#include <list>
#include <deque>
#include <vector>
#include <array>
#include <map>
#include <unordered_map>
#include <set>
#include <unordered_set>

// OpenSSL
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>

// XXHASH
#include "mh/xxhash/xxhash.h"


const uint8_t BYTED_2 = 0xfa;
const uint8_t BYTED_4 = 0xfb;
const uint8_t BYTED_8 = 0xfc;
const uint8_t BYTED_16 = 0xfd;
const uint8_t BYTED_32 = 0xfe;
const uint8_t BYTED_64 = 0xff;


typedef std::array<unsigned char, 32> sha256_2;

template<typename Message>
uint8_t read_varint(uint64_t &varint, Message & data) {
    if (data.size() < 1) return 0;

    uint8_t data_0 = static_cast<uint8_t>(data[0]);
    if (data_0 < BYTED_2) {
        varint = data_0;
        return 1;
    }
    switch (data_0) {
    case BYTED_2: {
        if (data.size() < 3) return 0;
        const uint16_t * p_int16 = reinterpret_cast<const uint16_t *>(&data[1]);
        varint = *p_int16;
        return 3;
    }
    case BYTED_4: {
        if (data.size() < 5) return 0;
        const uint32_t * p_int32 = reinterpret_cast<const uint32_t *>(&data[1]);
        varint = *p_int32;
        return 5;
    }
    default: {
        if (data.size() < 9) return 0;
        const uint64_t * p_int64 = reinterpret_cast<const uint64_t *>(&data[1]);
        varint = *p_int64;
        return 9;
    }
    }
}

std::vector<unsigned char> int_as_varint_array(uint64_t value);


template<typename Message>
uint64_t append_varint(Message & data, uint64_t value) {
    unsigned char * p_int = reinterpret_cast<unsigned char*>(&value);

    uint64_t writed = 0;

    std::vector<unsigned char> ret_data;
    if (value < 0xfa) {
        data.insert(data.end(), p_int, p_int + 1);
        writed = 1;
    } else if (value <= 0xffff) {
        data.insert(data.end(), &BYTED_2, &BYTED_2 + 1);
        data.insert(data.end(), p_int, p_int + 2);
        writed = 3;
    } else if (value <= 0xffffffff) {
        data.insert(data.end(), &BYTED_4, &BYTED_4 + 1);
        data.insert(data.end(), p_int, p_int + 4);
        writed = 5;
    } else {
        data.insert(data.end(), &BYTED_8, &BYTED_8 + 1);
        data.insert(data.end(), p_int, p_int + 8);
        writed = 9;
    }

    return writed;
}


template<typename Message>
sha256_2 get_sha256(Message & data) {
    sha256_2 hash1;
    sha256_2 hash2;

    const unsigned char * data_buff = reinterpret_cast<const unsigned char *>(data.data());
    // First pass
    SHA256(data_buff, data.size(), hash1.data());

    // Second pass
    SHA256(hash1.data(), hash1.size(), hash2.data());

    return hash2;
}


template<typename DataContainer>
bool CheckBufferSignature(EVP_PKEY* publicKey, DataContainer & data, ECDSA_SIG* signature) {
    size_t bufsize = data.size();
    const char * buff = data.data();

    EVP_MD_CTX *mdctx;
    static const EVP_MD *md = EVP_sha256();
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    md = EVP_sha256();
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, nullptr);
    EVP_DigestUpdate(mdctx, buff, bufsize);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_destroy(mdctx);


    EC_KEY * ec_key = EVP_PKEY_get1_EC_KEY(publicKey);
    if (ECDSA_do_verify(md_value, md_len, signature, ec_key) == 1) {
        EC_KEY_free(ec_key);
        return true;
    }
    EC_KEY_free(ec_key);
    return false;
}


template<typename SignContainer>
ECDSA_SIG* ReadSignature(SignContainer & binsign) {
    const unsigned char * data = reinterpret_cast<const unsigned char *>(binsign.data());

    ECDSA_SIG* signature = d2i_ECDSA_SIG(nullptr, &data, binsign.size());
    return signature;
}


template<typename PubKContainer>
EVP_PKEY* ReadPublicKey(PubKContainer & binpubk) {
    const unsigned char * data = reinterpret_cast<const unsigned char *>(binpubk.data());

    EVP_PKEY* key = d2i_PUBKEY(nullptr, &data, binpubk.size());
    return key;
}

template<typename PrivKContainer>
EVP_PKEY* ReadPrivateKey(PrivKContainer & binprivk) {
    const unsigned char * data = reinterpret_cast<const unsigned char *>(binprivk.data());

    EVP_PKEY* key = d2i_AutoPrivateKey(nullptr, &data, binprivk.size());
    return key;
}


template<typename DataContainer, typename SignContainer, typename PubKContainer>
bool check_sign(DataContainer & data, SignContainer & sign, PubKContainer & pubk) {
    EVP_PKEY* pubkey = ReadPublicKey(pubk);
    if (!pubkey) {
        return false;
    }
    ECDSA_SIG* signature = ReadSignature(sign);
    if (!signature) {
        EVP_PKEY_free(pubkey);
        return false;
    }

    if (CheckBufferSignature(pubkey, data, signature)) {
        EVP_PKEY_free(pubkey);
        ECDSA_SIG_free(signature);
        return true;
    } else {
        EVP_PKEY_free(pubkey);
        ECDSA_SIG_free(signature);
        return false;
    }
}


std::vector<unsigned char> hex2bin(const std::string & src);


template<typename Container>
std::string bin2hex(Container & bin_msg) {
    static const char HexLookup[513]= {
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f"
        "505152535455565758595a5b5c5d5e5f"
        "606162636465666768696a6b6c6d6e6f"
        "707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    };

    std::string res;
    res.reserve(bin_msg.size() * 2 + 1);

    for (uint i = 0; i < bin_msg.size(); i++) {
        const char * hex = HexLookup + 2 * (static_cast<unsigned char>(bin_msg[i]));
        res.insert(res.end(), hex, hex + 2);
    }

    return res;
}


template<typename PubKContainer>
std::array<char, 25> get_address(PubKContainer & bpubk) {
    std::vector<unsigned char> binary;
    binary.insert(binary.end(), bpubk.begin(), bpubk.end());

    unsigned char* data = binary.data();
    int datasize = binary.size();
    if (data && datasize >= 65) {
        data[datasize - 65] = 0x04;

        sha256_2 sha_1;
        std::array<unsigned char, RIPEMD160_DIGEST_LENGTH> r160;

        SHA256(data + (datasize - 65), 65, sha_1.data());
        RIPEMD160(sha_1.data(), SHA256_DIGEST_LENGTH, r160.data());

        std::array<unsigned char, RIPEMD160_DIGEST_LENGTH + 1> wide_h;
        wide_h[0] = 0;
        for (size_t i = 0; i < RIPEMD160_DIGEST_LENGTH; i++) {
            wide_h[i + 1] = r160[i];
        }

        sha256_2 hash1;
        SHA256(wide_h.data(), RIPEMD160_DIGEST_LENGTH + 1, hash1.data());

        sha256_2 hash2;
        SHA256(hash1.data(), SHA256_DIGEST_LENGTH, hash2.data());

        std::array<char, 25> address;
        uint j = 0;
        {
            for (uint i = 0; i < wide_h.size(); i++, j++) {
                address[j] = static_cast<char>(wide_h[i]);
            }

            for (size_t i = 0; i < 4; i++, j++) {
                address[j] = static_cast<char>(hash2[i]);
            }
        }

        return address;
    }

    return std::array<char, 25>{0};
}


template<typename PubKContainer, typename PrivKContainer>
bool generate_public_key(PubKContainer & pub_key, const PrivKContainer & private_key) {
    EVP_PKEY * pkey = ReadPrivateKey(private_key);
    if (!pkey) {
        return false;
    }

    unsigned char * public_key_temp_buff = nullptr;
    int public_key_temp_buff_size = i2d_PUBKEY(pkey, &public_key_temp_buff);

    if (public_key_temp_buff_size <= 0) {
        EVP_PKEY_free(pkey);
        return false;
    }

    pub_key.insert(pub_key.end(), public_key_temp_buff, public_key_temp_buff + public_key_temp_buff_size);
    free(public_key_temp_buff);
    EVP_PKEY_free(pkey);

    return true;
}


template<typename DataContainer, typename SignContainer, typename PrivKContainer>
bool sign_data(DataContainer & data, SignContainer & sign, PrivKContainer & private_key) {
    EVP_PKEY * pkey = ReadPrivateKey(private_key);
    if (!pkey) {
        return false;
    }

    EVP_MD_CTX * mdctx = EVP_MD_CTX_create();
    if (!mdctx) {
        return false;
    }

    if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) {
        return false;
    }

    if (EVP_DigestSignUpdate(mdctx, data.data(), data.size()) != 1) {
        return false;
    }

    size_t signature_size = 0;
    if (EVP_DigestSignFinal(mdctx, nullptr, &signature_size) != 1) {
        return false;
    }

    unsigned char * signature_temp_buff = new unsigned char[signature_size];

    if (EVP_DigestSignFinal(mdctx, signature_temp_buff, &signature_size) != 1) {
        return false;
    }

    sign.insert(sign.end(), signature_temp_buff, signature_temp_buff + signature_size);

    delete [] signature_temp_buff;
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_destroy(mdctx);

    return true;
}

#endif // CRYPTO_TEMPLATES_HPP

