//
// Created by aokblast on 2023/1/6.
//

#ifndef HORMOMORPHICHASHCHECKER_COMMON_H
#define HORMOMORPHICHASHCHECKER_COMMON_H

#include <cstdint>
#include <vector>

template<typename T>
static std::vector<uint8_t> to_bigEndian(T num) {
    int len = sizeof(T);
    std::vector<uint8_t> res(len);

    for (int i = 0; i < len; ++i) {
        res[len - 1 - i] = num & 255ull;
        num >>= 8;
    }

    return res;
}

template<typename T>
static std::vector<uint8_t> to_littleEndian(T num) {
    int len = sizeof(T);
    std::vector<uint8_t> res(len);

    for (int i = 0; i < len; ++i) {
        res[i] = num & 255ull;
        num >>= 8;
    }

    return res;
}

template<typename T>
inline static T right_rotate(T num, size_t offset) {
    return (num >> offset) | (num << (sizeof(T) * 8 - offset));
}

template<typename T>
inline static T left_rotate(T num, size_t offset) {
    return (num << offset) | (num >> (sizeof(T) * 8 - offset));
}

#endif //HORMOMORPHICHASHCHECKER_COMMON_H
