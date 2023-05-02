#include <queue>
#include <algorithm>
#include <future>
#include "MD5.h"
#include "SHA256.h"
#include "libhashtree.hpp"

HashTree::_Node::_Node(hash_value_t &&value): hash_value(std::forward<hash_value_t>(value))
, left(nullptr), right(nullptr) {

}

HashTree::_Node::~_Node() {
		delete left;
		delete right;
}

HashTree::~HashTree() {
		delete _root;
}

std::vector<HashTree::hash_value_t>
HashTree::hash_files(const std::vector<file_stream_t> &files, const TFHE::CloudKey &key) {
		std::vector<HashTree::hash_value_t> res;
		std::vector<std::future<hash_value_t>> promises;

		for (int i = 0; i < files.size(); i += NTHREAD) {
				for(int j = 0; j < NTHREAD && (i * NTHREAD + j) < files.size(); ++j)
						promises.push_back(std::async(MD5::hash, std::cref(files[i * NTHREAD + j]), std::cref(key)));

				for(auto &promise : promises)
						res.emplace_back(promise.get()), std::cout << "file finished" << std::endl;

				promises.clear();
		}

		return res;
}

static std::array<TFHE::CipherText<8>, 4>
word_to_byte(const TFHE::CipherText<32> &cip, const TFHE::CloudKey &key) {
		std::array<TFHE::CipherText<8>, 4> res;
		TFHE::Evaluator<32> word_eval(key);
		TFHE::Evaluator<8> byte_eval(key);

		for(int i = 0; i < 4; ++i) {
				TFHE::CipherText<8> tmp(key.get_parameter());

				for (int j = 0; j < 8; ++j)
						byte_eval.setBit(tmp, word_eval.extractBit(cip, i * 8 + j), j);

				res[i] = std::move(tmp);
		}

		return res;
}


HashTree::_Node*
HashTree::_build_tree(std::vector<hash_value_t> hashes, const TFHE::CloudKey &key) {
		std::queue<_Node *> q;
		std::for_each(std::make_move_iterator(hashes.begin()), std::make_move_iterator(hashes.end())
									, [&q](hash_value_t &&hash){
				q.emplace(new _Node(std::forward<hash_value_t>(hash)));
		});

		std::cout << "Start Build Tree" << std::endl;

		std::vector<std::future<_Node *>> futures;

		while(q.size() > 1) {
				int sz = q.size();

				for(int i = 0; (sz - i) > 1; i += NTHREAD * 2) {
						for(int j = 0; j < (NTHREAD * 2) && (sz - (i * NTHREAD * 2 + j)) > 1; j += 2) {
								auto left = q.front(); q.pop();
								auto right = q.front(); q.pop();
								file_stream_t msg;

								auto replace_func = [&key, &msg](const TFHE::CipherText<32> &cip) {
										auto byte = word_to_byte(cip, key);
										msg.insert(msg.end(), std::make_move_iterator(byte.begin()), std::make_move_iterator(byte.end()));
								};

								std::for_each(left->hash_value.begin(), left->hash_value.end(), replace_func);
								std::for_each(right->hash_value.begin(), right->hash_value.end(), replace_func);

								auto *new_node = new _Node();

								futures.push_back(std::async([new_node](const std::vector<TFHE::CipherText<8>>& msg, const TFHE::CloudKey &key){
										new_node->hash_value = MD5::hash(msg, key); return new_node;}, std::move(msg), std::cref(key)));

								new_node->left = left;
								new_node->right = right;
						}

						std::cout << futures.size() << std::endl;

						for(auto &future : futures)
								q.push(future.get());

						futures.clear();
				}

				if((sz % 2) == 1)
						q.push(q.front()), q.pop();
		}

		std::cout << "End Build Tree" << std::endl;

		return q.front();
}


HashTree::HashTree(std::vector<hash_value_t> files, const TFHE::CloudKey &key)
    : _root(_build_tree(std::move(files), key)), _key(key) {
}

HashTree::hash_value_t &
HashTree::query() {
    return _root->hash_value;
}
