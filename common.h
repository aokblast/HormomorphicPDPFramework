//
// Created by aokblast on 2022/9/13.
//

#ifndef MD5CHECKERINCPP_COMMON_H
#define MD5CHECKERINCPP_COMMON_H

#include <string>
#include <iomanip>
#include <sstream>
#include <time.h>
#include <iostream>

static inline std::string uint64_to_hex_string(uint64_t val) {
    std::stringstream ss;
    ss << std::setbase(16) << val << std::setbase(10);
    return ss.str();
}

static inline void print_time() {
    std::cout << "[" << std::time(nullptr) << "] ";
}

#endif //MD5CHECKERINCPP_COMMON_H
