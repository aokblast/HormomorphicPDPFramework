#include "libtfhe_core.h"
#include "MD5.h"
#include "SHA256.h"
#include <memory>
#include <vector>
#include <array>


namespace HASHNS = SHA256;

class HashTree {
public:
    using file_stream_t = std::vector<TFHE::CipherText<8>>;
    using hash_value_t = HASHNS::hash_value_t;
		const static int NTHREADS = 8;
private:
    class _Node {
    public:
        hash_value_t hash_value;
        _Node *left{}, *right{};

				explicit _Node(hash_value_t &&value);
				_Node() = default;
				_Node(_Node &&) = default;
				~_Node();
    };

    _Node *_root;
    const TFHE::CloudKey _key;

    static _Node*
		_build_tree(std::vector<hash_value_t> hashes, const TFHE::CloudKey &key);
public:
    HashTree(std::vector<hash_value_t> files, const TFHE::CloudKey &key);
		~HashTree();

		static std::vector<hash_value_t>
		hash_files(const std::vector<file_stream_t> &files, const TFHE::CloudKey &key);

    hash_value_t &
    query();
};
