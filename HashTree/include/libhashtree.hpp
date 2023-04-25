#include "libtfhe_core.h"
#include <memory>
#include <vector>

class HashTree {
public:
    using file_stream_t = std::vector<TFHE::CipherText<8>>;
    using hash_value_t = std::array<TFHE::CipherText<32>, 4>;
private:
    class _Node {
    public:
        hash_value_t hash_value;
        std::unique_ptr<_Node> left, right;
    };

    _Node _root;
    const TFHE::CloudKey _key;

    static std::vector<hash_value_t>
    &&_hash_files(const std::vector<file_stream_t> &files, const TFHE::CloudKey &key);

    static _Node
    _recursive_build_tree(const std::vector<hash_value_t> &hashs, int l, int r);
public:
    HashTree(const std::vector<file_stream_t> &files, const TFHE::CloudKey &key);

    hash_value_t &
    query();
};
