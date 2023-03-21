#include <CloudKey.hpp>
#include <memory>
#include <tfhe/tfhe_core.h>

using namespace TFHE;

CloudKey::CloudKey(const TFheGateBootstrappingCloudKeySet *key) {
    _key = std::shared_ptr<TFheGateBootstrappingCloudKeySet>(const_cast<TFheGateBootstrappingCloudKeySet *>(key),
                                                             [](TFheGateBootstrappingCloudKeySet *) {});
}


CloudKey::CloudKey(TFheGateBootstrappingCloudKeySet *key) {
    _key = std::shared_ptr<TFheGateBootstrappingCloudKeySet>(key, delete_gate_bootstrapping_cloud_keyset);
}

Parameter CloudKey::get_parameter() const {
    return Parameter(_key->params);
}

std::ostream &operator<<(std::ostream &os, const TFHE::CloudKey &param) {
    export_tfheGateBootstrappingCloudKeySet_toStream(os, param._key.get());
    return os;
}

std::istream &operator>>(std::istream &is, TFHE::CloudKey &param) {
    param._key.reset(new_tfheGateBootstrappingCloudKeySet_fromStream(is));
    return is;
}