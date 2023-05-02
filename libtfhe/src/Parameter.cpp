#include <tfhe/tfhe.h>
#include <Parameter.hpp>

using namespace TFHE;

Parameter::Parameter(const int lambda) : _param(new_default_gate_bootstrapping_parameters(lambda),
                                                delete_gate_bootstrapping_parameters) {

}

Parameter::Parameter(const TFheGateBootstrappingParameterSet *p) {
    _param = std::shared_ptr<TFheGateBootstrappingParameterSet>(const_cast<TFheGateBootstrappingParameterSet *>(p),
                                                                [](TFheGateBootstrappingParameterSet *p) {});
}

std::ostream &
operator<<(std::ostream &os, const Parameter &param) {
    export_tfheGateBootstrappingParameterSet_toStream(os, param._param.get());
    return os;
}

std::istream &
operator>>(std::istream &is, Parameter &param) {
    param._param.reset((new_tfheGateBootstrappingParameterSet_fromStream(is)));
    return is;
}
