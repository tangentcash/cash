/**
MIT License

Copyright (c) 2022 Eztero

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Documentation:
https://github.com/input-output-hk/cardano-ledger/blob/master/eras/babbage/test-suite/cddl-files/babbage.cddl
**/

#ifndef TRANSACTION_HPP
#define TRANSACTION_HPP
#include <sodium.h>
#include "transaction_body.hpp"
#include "transaction_witness.hpp"
#include "auxiliary_data.hpp"
#include "certificates.hpp"
#include "metadata.hpp"
#define PROTOCOL_FEE_FIXED 155381
#define PROTOCOL_FEE_PER_BYTE 44
#define PROTOCOL_UTXO_VALUE_PER_WORD 34482

namespace Cardano{

class Transaction{
public:
    struct Digest{
        uint8_t Hash[32];
    };

public:
    explicit Transaction();
    explicit Transaction(uint64_t txfeefixed, uint64_t txfeeperbytes);
    virtual ~Transaction();
    TransactionBody Body;
    AuxiliaryData Auxiliarydata;
    Transaction &addExtendedSigningKey(uint8_t const *const xsk);
    Transaction &addExtendedVerifyingKey(uint8_t const *const xvk, uint8_t const* const signature);
    uint64_t getFeeTransacion_PostBuild(uint64_t const number_of_signatures);
    std::vector<uint8_t> const& build(std::vector<Digest>* signable_hashes32);

private:
    TransactionWitness Witness;
    uint16_t witnessmapcountbit;
    uint64_t bytesskyesInwitness;
    uint8_t blake256[32];
    uint8_t body_signed[64];
    uint8_t xvkeys[96];
    unsigned int bytes_transaction;
    uint64_t feefixed;
    uint64_t feeperbytes;
std::vector<const uint8_t *> xskeys_ptr;
std::vector <uint8_t> cborTransaction;
};
}
#endif
