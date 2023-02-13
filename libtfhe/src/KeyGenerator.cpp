#include <KeyGenerator.hpp>


using namespace TFHE;

KeyGenerator::KeyGenerator(const Parameter &param) { _param = param; }

SecretKey KeyGenerator::generate_secret_key() const {
  return SecretKey(new_random_gate_bootstrapping_secret_keyset(_param._param.get()));
}
