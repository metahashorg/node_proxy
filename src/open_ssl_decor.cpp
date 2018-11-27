#include "open_ssl_decor.h"

std::vector<unsigned char> int_as_varint_array(uint64_t value) {
    unsigned char * p_int = reinterpret_cast<unsigned char*>(&value);

    std::vector<unsigned char> ret_data;
    if (value < 0xfa) {
        ret_data.push_back(p_int[0]);
    } else if (value <= 0xffff) {
        ret_data.push_back(BYTED_2);
        ret_data.insert(ret_data.end(), p_int, p_int + 2);
    } else if (value <= 0xffffffff) {
        ret_data.push_back(BYTED_4);
        ret_data.insert(ret_data.end(), p_int, p_int + 4);
    } else {
        ret_data.push_back(BYTED_8);
        ret_data.insert(ret_data.end(), p_int, p_int + 8);
    }
    return ret_data;
}

std::vector<unsigned char> hex2bin(const std::string & src) {
    static const unsigned char DecLookup[256] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // gap before first hex digit
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,1,2,3,4,5,6,7,8,9,       // 0123456789
        0,0,0,0,0,0,0,             // :;<=>?@ (gap)
        10,11,12,13,14,15,         // ABCDEF
        0,0,0,0,0,0,0,0,0,0,0,0,0, // GHIJKLMNOPQRS (gap)
        0,0,0,0,0,0,0,0,0,0,0,0,0, // TUVWXYZ[/]^_` (gap)
        10,11,12,13,14,15,         // abcdef
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 // fill zeroes
    };

    uint i = 0;
    if (src.size() > 2 && src[0] == '0' && src[1] == 'x') {
        i = 2;
    }

    std::vector<unsigned char> dest;
    dest.reserve(src.length()/2);
    for (; i < src.length(); i += 2 ) {
        unsigned char d =  DecLookup[(unsigned char)src[i]] << 4;
        d |= DecLookup[(unsigned char)src[i + 1]];
        dest.push_back(d);
    }

    return dest;
}
