#include "libtfhe_core.h"
#include <memory>
#include <vector>
#include <array>

class HashTree {
public:
    using file_stream_t = std::vector<TFHE::CipherText<8>>;
    using hash_value_t = std::array<TFHE::CipherText<32>, 4>;
private:
    class _Node {
    public:
        hash_value_t hash_value;
        _Node *left, *right;

				explicit _Node(hash_value_t &&value);
    };

    _Node _root;
    const TFHE::CloudKey _key;

    static std::vector<hash_value_t>
		_hash_files(const std::vector<file_stream_t> &files, const TFHE::CloudKey &key);

    static _Node
		_build_tree(std::vector<hash_value_t> hashes, const TFHE::CloudKey &key);
public:
    HashTree(const std::vector<file_stream_t> &files, const TFHE::CloudKey &key);

    hash_value_t &
    query();
};
