#include "transaction.h"
#include "open_ssl_decor.h"

#include <iostream>

//#include "statics.hpp"

TX::TX() {}

TX::~TX() {
    if (json_rpc) {
        delete json_rpc;
    }
    if (delegate_list) {
        delete delegate_list;
    }
}

bool TX::parse(std::string_view raw_data, bool check_sign_flag)
{
    raw_tx.insert(raw_tx.end(), raw_data.begin(), raw_data.end());

    uint64_t index = 0;
    uint8_t varint_size;
    uint64_t sign_data_size = 0;

    {
        const uint8_t toadr_size = 25;
        if (index + toadr_size >= raw_tx.size()) {
            return false;
        }
        bin_to = std::string_view(&raw_tx[index], toadr_size);
        index += toadr_size;
    }

    {
        std::string_view varint_arr(&raw_tx[index], raw_tx.size() - index);
        varint_size = read_varint(value, varint_arr);
        if (varint_size < 1) {
            return false;
        }
        index += varint_size;
    }

    {
        std::string_view varint_arr(&raw_tx[index], raw_tx.size() - index);
        varint_size = read_varint(fee, varint_arr);
        if (varint_size < 1) {
            return false;
        }
        index += varint_size;
    }

    {
        std::string_view varint_arr(&raw_tx[index], raw_tx.size() - index);
        varint_size = read_varint(nonce, varint_arr);
        if (varint_size < 1) {
            return false;
        }
        index += varint_size;
    }

    {
        uint64_t data_size;
        std::string_view varint_arr(&raw_tx[index], raw_tx.size() - index);
        varint_size = read_varint(data_size, varint_arr);
        if (varint_size < 1) {
            return false;
        }
        index += varint_size;

        if (index + data_size >= raw_tx.size()) {
            return false;
        }
        data = std::string_view(&raw_tx[index], data_size);
        index += data_size;

        sign_data_size = index;
    }

    {
        uint64_t sign_size;
        std::string_view varint_arr(&raw_tx[index], raw_tx.size() - index);
        varint_size = read_varint(sign_size, varint_arr);
        if (varint_size < 1) {
            return false;
        }
        index += varint_size;

        if (index + sign_size >= raw_tx.size()) {
            return false;
        }
        sign = std::string_view(&raw_tx[index], sign_size);
        index += sign_size;
    }

    {
        uint64_t pubk_size;
        std::string_view varint_arr(&raw_tx[index], raw_tx.size() - index);
        varint_size = read_varint(pubk_size, varint_arr);
        if (varint_size < 1) {
            return false;
        }
        index += varint_size;

        if (pubk_size && (index + pubk_size > raw_tx.size())) {
            return false;
        }
        pub_key = std::string_view(&raw_tx[index], pubk_size);
        index += pubk_size;
    }

    {
        data_for_sign = std::string_view(&raw_tx[0], sign_data_size);
        hash = get_sha256(raw_tx);
    }

    if (check_sign_flag && !check_sign(data_for_sign, sign, pub_key)) {
        return false;
    }

    addr_to = "0x" + bin2hex(bin_to);
    if (check_sign_flag) {
        auto bin_from = get_address(pub_key);
        addr_from = "0x" + bin2hex(bin_from);
    }

    return true;
}

bool TX::fill_from_strings(
        std::string & param_to,
        std::string param_value,
        std::string param_fee,
        std::string param_nonce,
        std::string & param_data,
        std::string & param_sign,
        std::string & param_pub_key)
{
    unsigned long transaction_value = 0;
    unsigned long transaction_id = 0;
    unsigned long transaction_fee = 0;

    if (param_value.empty()) {
        param_value = "0";
    }
    try {
        transaction_value = std::stoul(param_value);
    } catch(...) {
        return false;
    }

    if (param_nonce.empty()) {
        param_nonce = "0";
    }
    try {
        transaction_id = std::stoul(param_nonce);
    } catch(...) {
        return false;
    }

    if (param_fee.empty()) {
        param_fee = "0";
    }
    try {
        transaction_fee = std::stoul(param_fee);
    } catch(...) {
        return false;
    }

    std::vector<unsigned char> bin_to = hex2bin(param_to);
    std::vector<unsigned char> bin_data = hex2bin(param_data);
    std::vector<unsigned char> bin_sign = hex2bin(param_sign);
    std::vector<unsigned char> bin_pub_key = hex2bin(param_pub_key);

    return fill_sign_n_raw(bin_to, transaction_value, transaction_fee, transaction_id, bin_data, bin_sign, bin_pub_key);
}


void TX::clear() {
    bin_to = std::string_view();
    value = 0;
    fee = 0;
    nonce = 0;
    data = std::string_view();
    sign = std::string_view();
    pub_key = std::string_view();

    data_for_sign = std::string_view();
    raw_tx.clear();
    hash = {0};

    addr_from.clear();
    addr_to.clear();
}

void TX::append_tx_varint(std::vector<char> & _raw_tx, uint64_t param)
{
    append_varint(_raw_tx, param);
}

bool TX::check_tx()
{
    if (check_sign(data_for_sign, sign, pub_key)) {
        hash = get_sha256(raw_tx);
        addr_to = "0x" + bin2hex(bin_to);
        auto bin_from = get_address(pub_key);
        addr_from = "0x" + bin2hex(bin_from);
        return true;
    } else {
        return false;
    }
}

