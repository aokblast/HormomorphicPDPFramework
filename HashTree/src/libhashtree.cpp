#include "MD5.h"
#include "libtfhe_core.h"
#include "libhashtree.hpp"

std::vector<HashTree::hash_value_t> &&
HashTree::_hash_files(const std::vector<file_stream_t> &files, const TFHE::CloudKey &key) {
    std::vector<HashTree::hash_value_t> res;

    for(const auto &file : files)
        res.emplace_back(MD5::hash(file, key));
    return std::move(res);
}

HashTree::_Node
HashTree::_recursive_build_tree(const std::vector<hash_value_t> &hashs, int l, int r) {

}


HashTree::HashTree(const std::vector<file_stream_t> &files, const TFHE::CloudKey &key)
    : _root(_recursive_build_tree(_hash_files(files, key), 0, files.size() - 1)), _key(key) {
}

HashTree::hash_value_t &
HashTree::query() {
    return _root.hash_value;
}
