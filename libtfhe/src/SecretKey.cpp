#include "SecretKey.hpp"
#include <tfhe/tfhe_core.h>
#include <tfhe/tfhe_gate_bootstrapping_functions.h>

using namespace TFHE;

SecretKey::SecretKey(TFheGateBootstrappingSecretKeySet *key) {
    _key = std::shared_ptr<TFheGateBootstrappingSecretKeySet>(key);
}

CloudKey
SecretKey::get_cloud_key() const {
    return CloudKey(&_key->cloud);
}

std::istream &
operator>>(std::istream &is, SecretKey &rhs) {
    rhs._key = std::shared_ptr<TFheGateBootstrappingSecretKeySet>(new_tfheGateBootstrappingSecretKeySet_fromStream(is),
                                                                  delete_gate_bootstrapping_secret_keyset);
    return is;
}

std::ostream &
operator<<(std::ostream &os, const SecretKey &rhs) {
    export_tfheGateBootstrappingSecretKeySet_toStream(os, rhs._key.get());
    return os;
}

