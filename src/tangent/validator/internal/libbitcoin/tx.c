/*

 The MIT License (MIT)

 Copyright (c) 2015 Jonas Schnelli

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/

#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "base58.h"
#include "ecc.h"
#include "memory.h"
#include "../../../internal/segwit_addr.h"
#include "serialize.h"
#include "sha2.h"
#include "tx.h"
#include "utils.h"

void btc_tx_in_free(btc_tx_in* tx_in)
{
	if (!tx_in)
		return;

	memset(&tx_in->prevout.hash, 0, sizeof(tx_in->prevout.hash));
	tx_in->prevout.n = 0;

	if (tx_in->script_sig)
	{
		cstr_free(tx_in->script_sig, true);
		tx_in->script_sig = NULL;
	}

	if (tx_in->witness_stack)
	{
		vector_free(tx_in->witness_stack, true);
		tx_in->witness_stack = NULL;
	}

	memset(tx_in, 0, sizeof(*tx_in));
	btc_free(tx_in);
}

//callback for dvector free function
void btc_tx_in_free_cb(void* data)
{
	if (!data)
		return;

	btc_tx_in* tx_in = data;
	btc_tx_in_free(tx_in);
}

void btc_tx_in_witness_stack_free_cb(void* data)
{
	if (!data)
		return;

	cstring* stack_item = data;
	cstr_free(stack_item, true);
}

btc_tx_in* btc_tx_in_new()
{
	btc_tx_in* tx_in;
	tx_in = btc_calloc(1, sizeof(*tx_in));
	memset(&tx_in->prevout, 0, sizeof(tx_in->prevout));
	tx_in->sequence = UINT32_MAX;

	tx_in->witness_stack = vector_new(8, btc_tx_in_witness_stack_free_cb);
	return tx_in;
}

void btc_tx_out_free(btc_tx_out* tx_out)
{
	if (!tx_out)
		return;
	tx_out->value = 0;

	if (tx_out->script_pubkey)
	{
		cstr_free(tx_out->script_pubkey, true);
		tx_out->script_pubkey = NULL;
	}

	memset(tx_out, 0, sizeof(*tx_out));
	btc_free(tx_out);
}

void btc_tx_out_free_cb(void* data)
{
	if (!data)
		return;

	btc_tx_out* tx_out = data;
	btc_tx_out_free(tx_out);
}

btc_tx_out* btc_tx_out_new()
{
	btc_tx_out* tx_out;
	tx_out = btc_calloc(1, sizeof(*tx_out));

	return tx_out;
}

void btc_tx_free(btc_tx* tx)
{
	if (tx->vin)
		vector_free(tx->vin, true);

	if (tx->vout)
		vector_free(tx->vout, true);

	btc_free(tx);
}

btc_tx* btc_tx_new()
{
	btc_tx* tx;
	tx = btc_calloc(1, sizeof(*tx));
	tx->vin = vector_new(8, btc_tx_in_free_cb);
	tx->vout = vector_new(8, btc_tx_out_free_cb);
	tx->version = 1;
	tx->locktime = 0;
	return tx;
}

btc_bool btc_tx_in_deserialize(btc_tx_in* tx_in, struct const_buffer* buf)
{
	deser_u256(tx_in->prevout.hash, buf);
	if (!deser_u32(&tx_in->prevout.n, buf))
		return false;
	if (!deser_varstr(&tx_in->script_sig, buf))
		return false;
	if (!deser_u32(&tx_in->sequence, buf))
		return false;
	return true;
}

btc_bool btc_tx_out_deserialize(btc_tx_out* tx_out, struct const_buffer* buf)
{
	if (!deser_s64(&tx_out->value, buf))
		return false;
	if (!deser_varstr(&tx_out->script_pubkey, buf))
		return false;
	return true;
}

int btc_tx_deserialize(const unsigned char* tx_serialized, size_t inlen, btc_tx* tx, size_t* consumed_length, btc_bool allow_witness)
{
	struct const_buffer buf = { tx_serialized, inlen };
	if (consumed_length)
		*consumed_length = 0;

	//tx needs to be initialized
	deser_s32(&tx->version, &buf);

	uint32_t vlen;
	if (!deser_varlen(&vlen, &buf))
		return false;

	uint8_t flags = 0;
	if (vlen == 0 && allow_witness)
	{
		/* We read a dummy or an empty vin. */
		deser_bytes(&flags, &buf, 1);
		if (flags != 0)
		{
			// contains witness, deser the vin len
			if (!deser_varlen(&vlen, &buf))
				return false;
		}
	}

	unsigned int i;
	for (i = 0; i < vlen; i++)
	{
		btc_tx_in* tx_in = btc_tx_in_new();

		if (!btc_tx_in_deserialize(tx_in, &buf))
		{
			btc_tx_in_free(tx_in);
			return false;
		}
		else
		{
			vector_add(tx->vin, tx_in);
		}
	}

	if (!deser_varlen(&vlen, &buf))
		return false;
	for (i = 0; i < vlen; i++)
	{
		btc_tx_out* tx_out = btc_tx_out_new();

		if (!btc_tx_out_deserialize(tx_out, &buf))
		{
			btc_free(tx_out);
			return false;
		}
		else
		{
			vector_add(tx->vout, tx_out);
		}
	}

	if ((flags & 1) && allow_witness)
	{
		/* The witness flag is present, and we support witnesses. */
		flags ^= 1;
		for (size_t i = 0; i < tx->vin->len; i++)
		{
			btc_tx_in* tx_in = vector_idx(tx->vin, i);
			uint32_t vlen;
			if (!deser_varlen(&vlen, &buf)) return false;
			for (size_t j = 0; j < vlen; j++)
			{
				cstring* witness_item = cstr_new_sz(1024);
				if (!deser_varstr(&witness_item, &buf))
				{
					cstr_free(witness_item, true);
					return false;
				}
				vector_add(tx_in->witness_stack, witness_item); //dvector is responsible for freeing the items memory
			}
		}
	}
	if (flags)
	{
		/* Unknown flag in the serialization */
		return false;
	}

	if (!deser_u32(&tx->locktime, &buf))
		return false;

	if (consumed_length)
		*consumed_length = inlen - buf.len;
	return true;
}

void btc_tx_in_serialize(cstring* s, const btc_tx_in* tx_in)
{
	ser_u256(s, tx_in->prevout.hash);
	ser_u32(s, tx_in->prevout.n);
	ser_varstr(s, tx_in->script_sig);
	ser_u32(s, tx_in->sequence);
}

void btc_tx_out_serialize(cstring* s, const btc_tx_out* tx_out)
{
	ser_s64(s, tx_out->value);
	ser_varstr(s, tx_out->script_pubkey);
}

btc_bool btc_tx_has_witness(const btc_tx* tx)
{
	for (size_t i = 0; i < tx->vin->len; i++)
	{
		btc_tx_in* tx_in = vector_idx(tx->vin, i);
		if (tx_in->witness_stack != NULL && tx_in->witness_stack->len > 0)
		{
			return true;
		}
	}
	return false;
}

void btc_tx_serialize(cstring* s, const btc_tx* tx, btc_bool allow_witness)
{
	ser_s32(s, tx->version);
	uint8_t flags = 0;
	// Consistency check
	if (allow_witness)
	{
		/* Check whether witnesses need to be serialized. */
		if (btc_tx_has_witness(tx))
		{
			flags |= 1;
		}
	}
	if (flags)
	{
		/* Use extended format in case witnesses are to be serialized. */
		uint8_t dummy = 0;
		ser_bytes(s, &dummy, 1);
		ser_bytes(s, &flags, 1);
	}

	ser_varlen(s, tx->vin ? (uint32_t)tx->vin->len : 0);

	unsigned int i;
	if (tx->vin)
	{
		for (i = 0; i < tx->vin->len; i++)
		{
			btc_tx_in* tx_in;

			tx_in = vector_idx(tx->vin, i);
			btc_tx_in_serialize(s, tx_in);
		}
	}

	ser_varlen(s, tx->vout ? (uint32_t)tx->vout->len : 0);

	if (tx->vout)
	{
		for (i = 0; i < tx->vout->len; i++)
		{
			btc_tx_out* tx_out;

			tx_out = vector_idx(tx->vout, i);
			btc_tx_out_serialize(s, tx_out);
		}
	}

	if (flags & 1)
	{
		// serialize the witness stack
		if (tx->vin)
		{
			for (i = 0; i < tx->vin->len; i++)
			{
				btc_tx_in* tx_in;
				tx_in = vector_idx(tx->vin, i);
				if (tx_in->witness_stack)
				{
					ser_varlen(s, (uint32_t)tx_in->witness_stack->len);
					for (unsigned int j = 0; j < tx_in->witness_stack->len; j++)
					{
						cstring* item = vector_idx(tx_in->witness_stack, j);
						ser_varstr(s, item);
					}
				}
			}
		}
	}

	ser_u32(s, tx->locktime);
}

void btc_tx_hash(const btc_tx* tx, uint256 hashout)
{
	cstring* txser = cstr_new_sz(1024);
	btc_tx_serialize(txser, tx, false);


	sha256_Raw((const uint8_t*)txser->str, txser->len, hashout);
	sha256_Raw(hashout, BTC_HASH_LENGTH, hashout);
	cstr_free(txser, true);
}

void btc_tx_in_copy(btc_tx_in* dest, const btc_tx_in* src)
{
	memcpy(&dest->prevout, &src->prevout, sizeof(dest->prevout));
	dest->sequence = src->sequence;

	if (!src->script_sig)
		dest->script_sig = NULL;
	else
	{
		dest->script_sig = cstr_new_sz(src->script_sig->len);
		cstr_append_buf(dest->script_sig,
			src->script_sig->str,
			src->script_sig->len);
	}

	if (!src->witness_stack)
		dest->witness_stack = NULL;
	else
	{
		dest->witness_stack = vector_new(src->witness_stack->len, btc_tx_in_witness_stack_free_cb);
		for (unsigned int i = 0; i < src->witness_stack->len; i++)
		{
			cstring* witness_item = vector_idx(src->witness_stack, i);
			cstring* item_cpy = cstr_new_cstr(witness_item);
			vector_add(dest->witness_stack, item_cpy);
		}
	}
}

void btc_tx_out_copy(btc_tx_out* dest, const btc_tx_out* src)
{
	dest->value = src->value;

	if (!src->script_pubkey)
		dest->script_pubkey = NULL;
	else
	{
		dest->script_pubkey = cstr_new_sz(src->script_pubkey->len);
		cstr_append_buf(dest->script_pubkey,
			src->script_pubkey->str,
			src->script_pubkey->len);
	}
}

void btc_tx_copy(btc_tx* dest, const btc_tx* src)
{
	dest->version = src->version;
	dest->locktime = src->locktime;

	if (!src->vin)
		dest->vin = NULL;
	else
	{
		unsigned int i;

		if (dest->vin)
			vector_free(dest->vin, true);

		dest->vin = vector_new(src->vin->len, btc_tx_in_free_cb);

		for (i = 0; i < src->vin->len; i++)
		{
			btc_tx_in* tx_in_old, * tx_in_new;

			tx_in_old = vector_idx(src->vin, i);
			tx_in_new = btc_malloc(sizeof(*tx_in_new));
			btc_tx_in_copy(tx_in_new, tx_in_old);
			vector_add(dest->vin, tx_in_new);
		}
	}

	if (!src->vout)
		dest->vout = NULL;
	else
	{
		unsigned int i;

		if (dest->vout)
			vector_free(dest->vout, true);

		dest->vout = vector_new(src->vout->len,
			btc_tx_out_free_cb);

		for (i = 0; i < src->vout->len; i++)
		{
			btc_tx_out* tx_out_old, * tx_out_new;

			tx_out_old = vector_idx(src->vout, i);
			tx_out_new = btc_malloc(sizeof(*tx_out_new));
			btc_tx_out_copy(tx_out_new, tx_out_old);
			vector_add(dest->vout, tx_out_new);
		}
	}
}

void btc_tx_prevout_hash(const btc_tx* tx, uint256 hash, btc_bool use_btc_hash)
{
	cstring* s = cstr_new_sz(512);
	unsigned int i;
	btc_tx_in* tx_in;
	for (i = 0; i < tx->vin->len; i++)
	{
		tx_in = vector_idx(tx->vin, i);
		ser_u256(s, tx_in->prevout.hash);
		ser_u32(s, tx_in->prevout.n);
	}

	if (use_btc_hash)
		btc_hash((const uint8_t*)s->str, s->len, hash);
	else
		sha256_Raw((const uint8_t*)s->str, s->len, hash);
	cstr_free(s, true);
}

void btc_tx_sequence_hash(const btc_tx* tx, uint256 hash, btc_bool use_btc_hash)
{
	cstring* s = cstr_new_sz(512);
	unsigned int i;
	btc_tx_in* tx_in;
	for (i = 0; i < tx->vin->len; i++)
	{
		tx_in = vector_idx(tx->vin, i);
		ser_u32(s, tx_in->sequence);
	}

	if (use_btc_hash)
		btc_hash((const uint8_t*)s->str, s->len, hash);
	else
		sha256_Raw((const uint8_t*)s->str, s->len, hash);
	cstr_free(s, true);
}

void btc_tx_outputs_hash(const btc_tx* tx, uint256 hash, btc_bool use_btc_hash)
{
	cstring* s = cstr_new_sz(512);
	unsigned int i;
	btc_tx_out* tx_out;
	for (i = 0; i < tx->vout->len; i++)
	{
		tx_out = vector_idx(tx->vout, i);
		btc_tx_out_serialize(s, tx_out);
	}

	if (use_btc_hash)
		btc_hash((const uint8_t*)s->str, s->len, hash);
	else
		sha256_Raw((const uint8_t*)s->str, s->len, hash);
	cstr_free(s, true);
}

void btc_tx_vin_amount_hash(const btc_tx* tx, const uint64_t* vin_amounts, uint256 hash, btc_bool use_btc_hash)
{
	cstring* s = cstr_new_sz(512);
	unsigned int i;
	for (i = 0; i < tx->vin->len; i++)
		ser_s64(s, vin_amounts[i]);

	if (use_btc_hash)
		btc_hash((const uint8_t*)s->str, s->len, hash);
	else
		sha256_Raw((const uint8_t*)s->str, s->len, hash);
	cstr_free(s, true);
}

void btc_tx_vin_script_hash(const btc_tx* tx, const cstring* const* vin_scripts, uint256 hash, btc_bool use_btc_hash)
{
	cstring* s = cstr_new_sz(512);
	unsigned int i;
	for (i = 0; i < tx->vin->len; i++)
		ser_varstr(s, (cstring*)vin_scripts[i]);

	if (use_btc_hash)
		btc_hash((const uint8_t*)s->str, s->len, hash);
	else
		sha256_Raw((const uint8_t*)s->str, s->len, hash);
	cstr_free(s, true);
}

btc_bool btc_tx_sighash(const btc_tx* tx_to, const enum btc_sig_version sigversion, uint32_t hashtype, const btc_tx_witness_stack* vin_stack, uint32_t input_index, const uint256 leaf_hash, uint256 hash)
{
	if (input_index >= tx_to->vin->len)
		return false;

	cstring* s = NULL;
	btc_bool ret = true;
	btc_bool use_btc_hash = true;
	btc_tx* tx_tmp = btc_tx_new();
	btc_tx_copy(tx_tmp, tx_to);

	if (sigversion == SIGVERSION_WITNESS_V1_TAPROOT || sigversion == SIGVERSION_WITNESS_V1_TAPSCRIPT)
	{
		uint8_t epoch = 0;
		s = cstr_new_sz(512);
		ser_bytes(s, &epoch, 1);
		ser_bytes(s, &hashtype, 1);
		ser_u32(s, tx_tmp->version);
		ser_u32(s, tx_tmp->locktime);

		const uint8_t output_type = (hashtype == SIGHASH_DEFAULT) ? SIGHASH_ALL : (hashtype & SIGHASH_OUTPUT_MASK); // Default (no sighash byte) is equivalent to SIGHASH_ALL
		const uint8_t input_type = hashtype & SIGHASH_INPUT_MASK;
		if (!(hashtype <= 0x03 || (hashtype >= 0x81 && hashtype <= 0x83)))
		{
			ret = false;
			goto out;
		}
		
		if (input_type != SIGHASH_ANYONECANPAY)
		{
			uint256 hash_prevouts;
			btc_hash_clear(hash_prevouts);
			uint256 hash_amounts;
			btc_hash_clear(hash_amounts);
			uint256 hash_scripts;
			btc_hash_clear(hash_scripts);
			uint256 hash_sequence;
			btc_hash_clear(hash_sequence);

			btc_tx_prevout_hash(tx_tmp, hash_prevouts, false);
			btc_tx_vin_amount_hash(tx_tmp, vin_stack->amounts, hash_amounts, false);
			btc_tx_vin_script_hash(tx_tmp, (const cstring* const*)vin_stack->scripts, hash_scripts, false);
			btc_tx_sequence_hash(tx_tmp, hash_sequence, false);
			ser_u256(s, hash_prevouts);
			ser_u256(s, hash_amounts);
			ser_u256(s, hash_scripts);
			ser_u256(s, hash_sequence);
		}

		if (output_type == SIGHASH_ALL)
		{
			uint256 hash_outputs;
			btc_hash_clear(hash_outputs);
			btc_tx_outputs_hash(tx_tmp, hash_outputs, false);
			ser_u256(s, hash_outputs);
		}

		const uint8_t have_annex = false;
		const uint8_t spend_type = (sigversion == SIGVERSION_WITNESS_V1_TAPROOT ? 0 : 2) + (have_annex ? 1 : 0);
		ser_bytes(s, &spend_type, 1);

		if (input_type == SIGHASH_ANYONECANPAY)
		{
			cstring* script = vin_stack->scripts[input_index];
			if (!script)
			{
				ret = false;
				goto out;
			}

			btc_tx_in* tx_in = vector_idx(tx_tmp->vin, input_index);
			ser_u256(s, tx_in->prevout.hash);
			ser_u32(s, tx_in->prevout.n);
			ser_varstr(s, script); // script code
			ser_u64(s, vin_stack->amounts[input_index]);
			ser_u32(s, tx_in->sequence);
		}
		else
			ser_u32(s, input_index);

		if (output_type == SIGHASH_SINGLE)
		{
			if (input_index >= tx_tmp->vout->len)
			{
				ret = false;
				goto out;
			}

			uint256 hash_output;
			cstring* s_out = cstr_new_sz(512);
			btc_tx_out* tx_out = vector_idx(tx_tmp->vout, input_index);
			btc_tx_out_serialize(s_out, tx_out);
			sha256_Raw((const uint8_t*)s_out->str, s_out->len, hash_output);
			cstr_free(s, true);
			ser_u256(s, hash_output);
		}

		if (sigversion == SIGVERSION_WITNESS_V1_TAPSCRIPT)
		{
			uint256 tapleaf_hash = { 0 };
			if (!leaf_hash)
			{
				cstring* script = vin_stack->scripts[input_index];
				if (!script)
				{
					ret = false;
					goto out;
				}

				btc_script_get_leafscripthash(script, tapleaf_hash);
			}
			else
				memcpy(tapleaf_hash, leaf_hash, sizeof(tapleaf_hash));
			ser_u256(s, tapleaf_hash);

			const uint8_t key_version = 0;
			ser_bytes(s, &key_version, 1);

			const uint32_t codeseparator_pos = 0xFFFFFFFF;
			ser_u32(s, codeseparator_pos);
		}

		use_btc_hash = false;
	}
	else if (sigversion == SIGVERSION_WITNESS_V0 || hashtype & SIGHASH_FORKID)
	{
		cstring* stack = vin_stack->stacks[input_index];
		if (!stack)
		{
			ret = false;
			goto out;
		}

		uint256 hash_prevouts;
		btc_hash_clear(hash_prevouts);
		uint256 hash_sequence;
		btc_hash_clear(hash_sequence);
		uint256 hash_outputs;
		btc_hash_clear(hash_outputs);

		if (!(hashtype & SIGHASH_ANYONECANPAY))
			btc_tx_prevout_hash(tx_tmp, hash_prevouts, true);
		if (!(hashtype & SIGHASH_ANYONECANPAY))
			btc_tx_outputs_hash(tx_tmp, hash_outputs, true);
		if (!(hashtype & SIGHASH_ANYONECANPAY) && (hashtype & 0x1f) != SIGHASH_SINGLE && (hashtype & 0x1f) != SIGHASH_NONE)
			btc_tx_sequence_hash(tx_tmp, hash_sequence, true);

		if ((hashtype & 0x1f) != SIGHASH_SINGLE && (hashtype & 0x1f) != SIGHASH_NONE)
		{
			btc_tx_outputs_hash(tx_tmp, hash_outputs, true);
		}
		else if ((hashtype & 0x1f) == SIGHASH_SINGLE && input_index < tx_tmp->vout->len)
		{
			cstring* s1 = cstr_new_sz(512);
			btc_tx_out* tx_out = vector_idx(tx_tmp->vout, input_index);
			btc_tx_out_serialize(s1, tx_out);
			btc_hash((const uint8_t*)s1->str, s1->len, hash);
			cstr_free(s1, true);
		}

		s = cstr_new_sz(512);
		ser_u32(s, tx_tmp->version); // Version

		// Input prevouts/nSequence (none/all, depending on flags)
		ser_u256(s, hash_prevouts);
		ser_u256(s, hash_sequence);

		// The input being signed (replacing the scriptSig with scriptCode + amount)
		// The prevout may already be contained in hashPrevout, and the nSequence
		// may already be contain in hashSequence.
		btc_tx_in* tx_in = vector_idx(tx_tmp->vin, input_index);
		ser_u256(s, tx_in->prevout.hash);
		ser_u32(s, tx_in->prevout.n);

		ser_varstr(s, stack); // script sig
		ser_u64(s, vin_stack->amounts[input_index]);
		ser_u32(s, tx_in->sequence);
		ser_u256(s, hash_outputs); // Outputs (none/one/all, depending on flags)
		ser_u32(s, tx_tmp->locktime); // Locktime
		ser_s32(s, hashtype); // Sighash type
	}
	else
	{
		// standard (non witness) sighash (SIGVERSION_BASE)
		cstring* stack = vin_stack->stacks[input_index];
		if (!stack)
		{
			ret = false;
			goto out;
		}

		cstring* scriptsig = cstr_new_sz(stack->len);
		btc_script_copy_without_op_codeseperator(stack, scriptsig);

		unsigned int i;
		btc_tx_in* tx_in;
		for (i = 0; i < tx_tmp->vin->len; i++)
		{
			tx_in = vector_idx(tx_tmp->vin, i);
			cstr_resize(tx_in->script_sig, 0);
			if (i == input_index)
				cstr_append_buf(tx_in->script_sig, scriptsig->str, scriptsig->len);
		}
		cstr_free(scriptsig, true);

		/* Blank out some of the outputs */
		if ((hashtype & 0x1f) == SIGHASH_NONE)
		{
			/* Wildcard payee */
			if (tx_tmp->vout)
				vector_free(tx_tmp->vout, true);

			tx_tmp->vout = vector_new(1, btc_tx_out_free_cb);

			/* Let the others update at will */
			for (i = 0; i < tx_tmp->vin->len; i++)
			{
				tx_in = vector_idx(tx_tmp->vin, i);
				if (i != input_index)
					tx_in->sequence = 0;
			}
		}
		else if ((hashtype & 0x1f) == SIGHASH_SINGLE)
		{
			/* Only lock-in the txout payee at same index as txin */
			unsigned int n_out = input_index;
			if (n_out >= tx_tmp->vout->len)
			{
				//TODO: set error code
				ret = false;
				goto out;
			}

			vector_resize(tx_tmp->vout, n_out + 1);
			for (i = 0; i < n_out; i++)
			{
				btc_tx_out* tx_out;

				tx_out = vector_idx(tx_tmp->vout, i);
				tx_out->value = -1;
				if (tx_out->script_pubkey)
				{
					cstr_free(tx_out->script_pubkey, true);
					tx_out->script_pubkey = NULL;
				}
			}

			/* Let the others update at will */
			for (i = 0; i < tx_tmp->vin->len; i++)
			{
				tx_in = vector_idx(tx_tmp->vin, i);
				if (i != input_index)
					tx_in->sequence = 0;
			}
		}

		/* Blank out other inputs completely;
		 not recommended for open transactions */
		if (hashtype & SIGHASH_ANYONECANPAY)
		{
			if (input_index > 0)
				vector_remove_range(tx_tmp->vin, 0, input_index);
			vector_resize(tx_tmp->vin, 1);
		}

		s = cstr_new_sz(512);
		btc_tx_serialize(s, tx_tmp, false);
		ser_s32(s, hashtype);
	}

	if (use_btc_hash)
	{
		sha256_Raw((const uint8_t*)s->str, s->len, hash);
		sha256_Raw(hash, BTC_HASH_LENGTH, hash);
	}
	else
	{
		char tag[] = "TapSighash";
		btc_ecc_tagged_sha256((const uint8_t*)s->str, s->len, (const uint8_t*)tag, sizeof(tag) - 1, hash);
	}
	cstr_free(s, true);
out:
	btc_tx_free(tx_tmp);
	return ret;
}

btc_bool btc_tx_add_data_out(btc_tx* tx, const int64_t amount, const uint8_t* data, const size_t datalen)
{
	if (datalen > 80)
		return false;

	btc_tx_out* tx_out = btc_tx_out_new();

	tx_out->script_pubkey = cstr_new_sz(1024);
	btc_script_append_op(tx_out->script_pubkey, OP_RETURN);
	btc_script_append_pushdata(tx_out->script_pubkey, (unsigned char*)data, datalen);

	tx_out->value = amount;

	vector_add(tx->vout, tx_out);

	return true;
}

btc_bool btc_tx_add_puzzle_out(btc_tx* tx, const int64_t amount, const uint8_t* puzzle, const size_t puzzlelen)
{
	if (puzzlelen > BTC_HASH_LENGTH)
		return false;

	btc_tx_out* tx_out = btc_tx_out_new();

	tx_out->script_pubkey = cstr_new_sz(1024);
	btc_script_append_op(tx_out->script_pubkey, OP_HASH256);
	btc_script_append_pushdata(tx_out->script_pubkey, (unsigned char*)puzzle, puzzlelen);
	btc_script_append_op(tx_out->script_pubkey, OP_EQUAL);
	tx_out->value = amount;

	vector_add(tx->vout, tx_out);

	return true;
}

btc_bool btc_tx_add_address_out(btc_tx* tx, const btc_chainparams* chain, int64_t amount, const char* address)
{
	const size_t buflen = sizeof(uint8_t) * strlen(address) * 2;
	uint8_t* buf = (uint8_t*)btc_malloc(buflen);
	int r = btc_base58_decode_check(address, buf, buflen);
	btc_bool success = false;
	if (r > 0 && base58_prefix_check(chain->b58prefix_pubkey_address, buf))
	{
		success = btc_tx_add_p2pkh_hash160_out(tx, amount, buf + base58_prefix_size(chain->b58prefix_pubkey_address));
	}
	else if (r > 0 && base58_prefix_check(chain->b58prefix_script_address, buf))
	{
		success = btc_tx_add_p2sh_hash160_out(tx, amount, buf + base58_prefix_size(chain->b58prefix_script_address));
	}
	else
	{
		// check for bech32
		int version = 0;
		unsigned char programm[40] = { 0 };
		size_t programmlen = 0;
		if (segwit_addr_decode(&version, programm, &programmlen, chain->bech32_hrp, address) != 1)
		{
			btc_free(buf);
			return false;
		}

		if (programmlen == 20)
		{
			success = btc_tx_add_p2wpkh_hash160_out(tx, amount, programm);
		}
		else if (programmlen == 32)
		{
			if (version == 1)
				success = btc_tx_add_p2tr_hash256_out(tx, amount, programm);
			else
				success = btc_tx_add_p2wsh_hash256_out(tx, amount, programm);
		}
	}

	btc_free(buf);
	return true;
}

btc_bool btc_tx_add_p2pk_out(btc_tx* tx, int64_t amount, const uint8_t* pubkey, size_t pubkey_size)
{
	btc_tx_out* tx_out = btc_tx_out_new();

	tx_out->script_pubkey = cstr_new_sz(1024);
	btc_script_build_p2pk(tx_out->script_pubkey, pubkey, pubkey_size);

	tx_out->value = amount;

	vector_add(tx->vout, tx_out);

	return true;
}

btc_bool btc_tx_add_p2pkh_hash160_out(btc_tx* tx, int64_t amount, uint160 hash160)
{
	btc_tx_out* tx_out = btc_tx_out_new();

	tx_out->script_pubkey = cstr_new_sz(1024);
	btc_script_build_p2pkh(tx_out->script_pubkey, hash160);

	tx_out->value = amount;

	vector_add(tx->vout, tx_out);

	return true;
}

btc_bool btc_tx_add_p2sh_hash160_out(btc_tx* tx, int64_t amount, uint160 hash160)
{
	btc_tx_out* tx_out = btc_tx_out_new();

	tx_out->script_pubkey = cstr_new_sz(1024);
	btc_script_build_p2sh(tx_out->script_pubkey, hash160);

	tx_out->value = amount;

	vector_add(tx->vout, tx_out);

	return true;
}

btc_bool btc_tx_add_p2wpkh_hash160_out(btc_tx* tx, int64_t amount, const uint8_t* hash160)
{
	btc_tx_out* tx_out = btc_tx_out_new();

	tx_out->script_pubkey = cstr_new_sz(1024);
	btc_script_build_p2wpkh(tx_out->script_pubkey, hash160);

	tx_out->value = amount;

	vector_add(tx->vout, tx_out);

	return true;
}

btc_bool btc_tx_add_p2wsh_hash256_out(btc_tx* tx, int64_t amount, const uint8_t* hash256)
{
	btc_tx_out* tx_out = btc_tx_out_new();

	tx_out->script_pubkey = cstr_new_sz(1024);
	btc_script_build_p2wsh(tx_out->script_pubkey, hash256);

	tx_out->value = amount;

	vector_add(tx->vout, tx_out);

	return true;
}

btc_bool btc_tx_add_p2tr_hash256_out(btc_tx* tx, int64_t amount, const uint8_t* hash256)
{
	btc_tx_out* tx_out = btc_tx_out_new();

	tx_out->script_pubkey = cstr_new_sz(1024);
	btc_script_build_p2tr(tx_out->script_pubkey, hash256);

	tx_out->value = amount;

	vector_add(tx->vout, tx_out);

	return true;
}

btc_bool btc_tx_outpoint_is_null(btc_tx_outpoint* tx)
{
	(void)(tx);
	return true;
}

btc_bool btc_tx_is_coinbase(btc_tx* tx)
{
	if (tx->vin->len == 1)
	{
		btc_tx_in* vin = vector_idx(tx->vin, 0);

		if (btc_hash_is_empty(vin->prevout.hash) && vin->prevout.n == UINT32_MAX)
			return true;
	}
	return false;
}

btc_bool btc_tx_sign_hash_ecdsa(const uint256 sighash, const btc_key* privkey, uint32_t sighashtype, uint8_t* sigdata_out, size_t* sigdata_size_out)
{
	uint8_t sig[64]; size_t siglen = 0;
	if (!btc_key_sign_hash_compact(privkey, sighash, sig, &siglen))
		return false;

	unsigned char sigder_plus_hashtype[74 + 1]; size_t sigderlen = sizeof(sigder_plus_hashtype);
	if (!btc_ecc_compact_to_der_normalized(sig, sigder_plus_hashtype, &sigderlen))
		return false;

	assert(siglen == sizeof(sig));
	assert(sigderlen <= 74 && sigderlen >= 70);
	sigder_plus_hashtype[sigderlen++] = sighashtype;
	memcpy(sigdata_out, sigder_plus_hashtype, sigderlen);
	*sigdata_size_out = sigderlen;
	return true;
}

btc_bool btc_tx_sign_hash_schnorr(const uint256 sighash, const btc_key* privkey, uint32_t sighashtype, uint8_t* sigdata_out, size_t* sigdata_size_out)
{
	uint256 auxiliary = { 0 };
	uint8_t sig[65]; size_t siglen = 0;
	if (!btc_ecc_sign_schnorr(privkey->privkey, sighash, auxiliary, sig, &siglen))
		return false;

	if (sighashtype)
		sig[siglen++] = sighashtype;

	memcpy(sigdata_out, sig, siglen);
	*sigdata_size_out = siglen;
	return true;
}

const char* btc_tx_sign_result_to_str(const enum btc_tx_sign_result result)
{
	if (result == BTC_SIGN_FINALIZE_OK)
	{
		return "FINALIZE_OK";
	}
	else if (result == BTC_SIGN_HASH_OK)
	{
		return "HASH_OK";
	}
	else if (result == BTC_SIGN_OK)
	{
		return "SIGN_OK";
	}
	else if (result == BTC_SIGN_INVALID_TX_OR_SCRIPT)
	{
		return "INVALID_TX_OR_SCRIPT";
	}
	else if (result == BTC_SIGN_INPUTINDEX_OUT_OF_RANGE)
	{
		return "INPUTINDEX_OUT_OF_RANGE";
	}
	else if (result == BTC_SIGN_INVALID_KEY)
	{
		return "INVALID_KEY";
	}
	else if (result == BTC_SIGN_UNKNOWN_SCRIPT_TYPE)
	{
		return "SIGN_UNKNOWN_SCRIPT_TYPE";
	}
	else if (result == BTC_SIGN_SIGHASH_FAILED)
	{
		return "SIGHASH_FAILED";
	}
	return "UNKOWN";
}

enum btc_tx_sign_result btc_tx_hash_input(btc_tx* tx_in_out, uint32_t sighashtype, enum btc_tx_out_type type, const btc_tx_witness_stack* vin_stack, uint32_t inputindex, uint256 sighash_out)
{
	if (!sighash_out || !tx_in_out || !vin_stack || type == BTC_TX_INVALID)
		return BTC_SIGN_INVALID_TX_OR_SCRIPT;

	if ((size_t)inputindex >= tx_in_out->vin->len)
		return BTC_SIGN_INPUTINDEX_OUT_OF_RANGE;

	btc_tx_in* tx_in = vector_idx(tx_in_out->vin, inputindex);
	switch (type)
	{
		case BTC_TX_PUBKEY:
		case BTC_TX_PUBKEYHASH:
		case BTC_TX_SCRIPTHASH:
		{
			// calculate message hash
			if (!btc_tx_sighash(tx_in_out, SIGVERSION_BASE, sighashtype, vin_stack, inputindex, NULL, sighash_out))
				return BTC_SIGN_SIGHASH_FAILED;

			return BTC_SIGN_HASH_OK;
		}
		case BTC_TX_WITNESS_V0_PUBKEYHASH:
		case BTC_TX_WITNESS_V0_SCRIPTHASH:
		{
			// calculate message hash
			if (!btc_tx_sighash(tx_in_out, SIGVERSION_WITNESS_V0, sighashtype, vin_stack, inputindex, NULL, sighash_out))
				return BTC_SIGN_SIGHASH_FAILED;

			return BTC_SIGN_HASH_OK;
		}
		case BTC_TX_WITNESS_V1_TAPROOT_KEYPATH:
		{
			// calculate message hash
			if (!btc_tx_sighash(tx_in_out, SIGVERSION_WITNESS_V1_TAPROOT, SIGHASH_DEFAULT, vin_stack, inputindex, NULL, sighash_out))
				return BTC_SIGN_SIGHASH_FAILED;

			return BTC_SIGN_HASH_OK;
		}
		case BTC_TX_WITNESS_V1_TAPROOT_SCRIPTPATH:
		{
			cstring* script = vin_stack->scripts[inputindex];
			if (!script)
				return BTC_SIGN_INVALID_TX_OR_SCRIPT;

			// calculate locking leaf script hash
			uint256 locking_leaf_hash;
			btc_script_get_leafscripthash(script, locking_leaf_hash);

			// calculate message hash
			if (!btc_tx_sighash(tx_in_out, SIGVERSION_WITNESS_V1_TAPSCRIPT, SIGHASH_DEFAULT, vin_stack, inputindex, locking_leaf_hash, sighash_out))
				return BTC_SIGN_SIGHASH_FAILED;

			return BTC_SIGN_HASH_OK;
		}
		default:
			return BTC_SIGN_UNKNOWN_SCRIPT_TYPE;
	}
}
enum btc_tx_sign_result btc_tx_sign_input(uint256 sighash, const btc_key* privkey, uint32_t sighashtype, enum btc_tx_out_type type, uint8_t* sigdata_out, size_t* sigdata_size_out)
{
	if (!sighash || !sigdata_out || !sigdata_size_out || type == BTC_TX_INVALID)
		return BTC_SIGN_INVALID_TX_OR_SCRIPT;

	if (!btc_privkey_is_valid(privkey))
		return BTC_SIGN_INVALID_KEY;

	switch (type)
	{
		case BTC_TX_PUBKEY:
		case BTC_TX_PUBKEYHASH:
		case BTC_TX_SCRIPTHASH:
		case BTC_TX_WITNESS_V0_PUBKEYHASH:
		case BTC_TX_WITNESS_V0_SCRIPTHASH:
		{
			// calculate ecdsa signature
			if (!btc_tx_sign_hash_ecdsa(sighash, privkey, sighashtype, sigdata_out, sigdata_size_out))
				return BTC_SIGN_SIGHASH_FAILED;

			return BTC_SIGN_OK;
		}
		case BTC_TX_WITNESS_V1_TAPROOT_KEYPATH:
		case BTC_TX_WITNESS_V1_TAPROOT_SCRIPTPATH:
		{
			// calculate schnorr privkey
			btc_key schnorr_privkey;
			btc_privkey_get_taproot_privkey(privkey, NULL, schnorr_privkey.privkey);

			// calculate schnorr signature
			if (!btc_tx_sign_hash_schnorr(sighash, &schnorr_privkey, SIGHASH_DEFAULT, sigdata_out, sigdata_size_out))
				return BTC_SIGN_SIGHASH_FAILED;

			return BTC_SIGN_OK;
		}
		default:
			return BTC_SIGN_UNKNOWN_SCRIPT_TYPE;
	}
}
enum btc_tx_sign_result btc_tx_finalize_input(btc_tx* tx_in_out, const uint8_t* sigdata, size_t sigdata_size, const btc_pubkey* pubkey, uint32_t sighashtype, enum btc_tx_out_type type, const btc_tx_witness_stack* vin_stack, uint32_t inputindex)
{
	if (!sigdata || !tx_in_out || !vin_stack || type == BTC_TX_INVALID)
		return BTC_SIGN_INVALID_TX_OR_SCRIPT;

	if ((size_t)inputindex >= tx_in_out->vin->len)
		return BTC_SIGN_INPUTINDEX_OUT_OF_RANGE;

	if (!pubkey || !btc_pubkey_is_valid(pubkey))
		return BTC_SIGN_INVALID_KEY;

	unsigned char signature[75];
	size_t signature_size = sizeof(signature) - 1;
	if (sigdata_size == 64)
	{
		memcpy(signature, sigdata, sigdata_size);
		signature_size = sigdata_size;
	}
	else
	{
		btc_ecc_compact_to_der_normalized(sigdata, signature, &signature_size);
		signature[signature_size++] = sighashtype;
	}

	btc_tx_in* tx_in = vector_idx(tx_in_out->vin, inputindex);
	switch (type)
	{
		case BTC_TX_PUBKEY:
		{
			// script_stack: [signature], witness_stack: []
			ser_varlen(tx_in->script_sig, (uint32_t)signature_size);
			ser_bytes(tx_in->script_sig, signature, signature_size);
			return BTC_SIGN_FINALIZE_OK;
		}
		case BTC_TX_PUBKEYHASH:
		case BTC_TX_SCRIPTHASH:
		{
			// script_stack: [signature, pubkey], witness_stack: []
			ser_varlen(tx_in->script_sig, (uint32_t)signature_size);
			ser_bytes(tx_in->script_sig, signature, signature_size);
			ser_varlen(tx_in->script_sig, pubkey->compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH);
			ser_bytes(tx_in->script_sig, pubkey->pubkey, pubkey->compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH);
			return BTC_SIGN_FINALIZE_OK;
		}
		case BTC_TX_WITNESS_V0_PUBKEYHASH:
		{
			cstring* redeem = vin_stack->redeems[inputindex];
			if (redeem)
			{
				// script_stack: [redeem], witness_stack: [signature, pubkey]
				cstr_resize(tx_in->script_sig, 0);
				cstr_append_cstr(tx_in->script_sig, redeem);
				vector_add(tx_in->witness_stack, cstr_new_buf(signature, signature_size));
				vector_add(tx_in->witness_stack, cstr_new_buf(pubkey->pubkey, pubkey->compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH));
			}
			else
			{
				// script_stack: [], witness_stack: [signature, pubkey]
				cstr_resize(tx_in->script_sig, 0);
				vector_add(tx_in->witness_stack, cstr_new_buf(signature, signature_size));
				vector_add(tx_in->witness_stack, cstr_new_buf(pubkey->pubkey, pubkey->compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH));
			}
			return BTC_SIGN_FINALIZE_OK;
		}
		case BTC_TX_WITNESS_V0_SCRIPTHASH:
		{
			cstring* stack = vin_stack->stacks[inputindex];
			if (!stack)
				return BTC_SIGN_INVALID_TX_OR_SCRIPT;

			// script_stack: [], witness_stack: [signature, pubkey, script]
			cstr_resize(tx_in->script_sig, 0);
			vector_add(tx_in->witness_stack, cstr_new_buf(signature, signature_size));
			vector_add(tx_in->witness_stack, cstr_new_buf(pubkey->pubkey, pubkey->compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH));
			vector_add(tx_in->witness_stack, cstr_new_cstr(stack));
			return BTC_SIGN_FINALIZE_OK;
		}
		case BTC_TX_WITNESS_V1_TAPROOT_KEYPATH:
		{
			// script_stack: [], witness_stack: [signature]
			cstr_resize(tx_in->script_sig, 0);
			vector_add(tx_in->witness_stack, cstr_new_buf(signature, signature_size));
			return BTC_SIGN_FINALIZE_OK;
		}
		case BTC_TX_WITNESS_V1_TAPROOT_SCRIPTPATH:
		{
			cstring* script = vin_stack->scripts[inputindex];
			if (!script)
				return BTC_SIGN_INVALID_TX_OR_SCRIPT;

			// calculate control block
			cstring* control_block = cstr_new_sz(512);
			btc_controlblock_append_version(control_block, BTC_TAPSCRIPT_V0);
			btc_controlblock_append_internalpubkey(control_block, pubkey);
			//btc_controlblock_append_leafscripthash(control_block, leaf_hash);

			// script_stack: [], witness_stack: [signature, script, control_block]
			cstr_resize(tx_in->script_sig, 0);
			vector_add(tx_in->witness_stack, cstr_new_buf(signature, signature_size));
			vector_add(tx_in->witness_stack, cstr_new_cstr(script));
			vector_add(tx_in->witness_stack, control_block);
			return BTC_SIGN_FINALIZE_OK;
		}
		default:
			return BTC_SIGN_UNKNOWN_SCRIPT_TYPE;
	}
}
