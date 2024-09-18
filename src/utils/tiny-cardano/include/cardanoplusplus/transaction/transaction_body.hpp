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


#ifndef TRANSACTION_BODY_HPP
#define TRANSACTION_BODY_HPP

#include <sodium.h>
#include <vector>
#include <string>
#include <cstdint>
#include "certificates.hpp"
#include "multiassets.hpp"
#include "../utils/cbor_lite.hpp"
#include "transactionoutput.hpp"
#include "transactioninput.hpp"
#include "withdrawal.hpp"
#include "../utils/cmacros.hpp"

namespace Cardano{
class TransactionBody : private  Multiassets {

public:

    explicit TransactionBody();
    virtual ~TransactionBody();
    TransactionsOutputs TransactionOutput;
    TransactionsInputs TransactionInput;
    Certificates Certificate;
    Withdrawals Withdrawal;
    TransactionBody & addFee(uint64_t const amount);
    TransactionBody & addInvalidAfter(uint64_t const number);
    TransactionBody & addInvalidBefore(uint64_t const number);
    TransactionBody & addAuxiliaryDataHash(uint8_t const *const hash_32bytes);
    TransactionBody & addTotalCollateral(uint64_t const amount);
    std::vector<uint8_t> const & Build();
    std::vector<uint8_t> const & getcborDatums_afterBuild() const;
    std::vector<uint8_t> const & getcborRedeemers_afterBuild() const;
    uint16_t const & getWitnessMapcountbit() const;

private:

    uint8_t const *ptrvec;
    std::size_t buff_sizet;
    uint32_t buff_uint32t;
    uint8_t addr_keyhash_buffer[BECH32_MAX_LENGTH]{};
    uint16_t addr_keyhash_buffer_len;
    uint32_t bodymapcountbit; // pone un bits a 1 si existe la variable, en la posisicion correspondiente al map de el transaccion body
    uint16_t witnessmapcountbit; // pone un bits a 1 si existe la variable, en la posisicion correspondiente al map de el transaccion witness
    uint64_t fee;
    uint64_t ttl;  // time to alive
    uint64_t vis;  // validity interval start
    uint64_t totalcollateral;  // validity interval start
    Utils::CborSerialize cbor;
    std::vector <uint8_t>cbor_redeemers{};
    std::vector <uint8_t>cbor_datums{};
    std::vector <uint8_t>update{};
    std::vector <uint8_t>auxiliary_data_hash{};
    std::vector <uint8_t>validity_interval_start{};
    std::vector <uint8_t>mint{};
    std::vector <uint8_t>collateral_inputs{};
    std::vector <uint8_t>required_signers{};
    std::vector <uint8_t>network_id{};
    std::vector <uint8_t>collateral_return{};
    std::vector <uint8_t>total_collatera{};
    std::vector <uint8_t>reference_inputs{};
    uint8_t V1language_views[444];
    uint8_t V2language_views[467];
};
}

#endif
