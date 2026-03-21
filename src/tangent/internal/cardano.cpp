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

**/
#include "cardano.h"
#include "ed25519.h"
#include <iostream>
#include <string>

namespace Cardano
{
	char constexpr B32Chars_encode[33] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
	int8_t constexpr B32Chars_decode[128] = {
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
		-1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
		 1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
		-1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
		 1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
	};

	static inline void store32_be(uint32_t const index, uint8_t* const out) noexcept // store32 bigendian
	{
		out[3] = static_cast<uint8_t>(index);
		out[2] = static_cast<uint8_t>(index >> 8);
		out[1] = static_cast<uint8_t>(index >> 16);
		out[0] = static_cast<uint8_t>(index >> 24);
	}
	bool pbkdf2_hmac512_libsodium(uint8_t const* const key, std::size_t key_len, uint8_t const* const salt, std::size_t salt_len, uint64_t const iterations, std::size_t out_len, uint8_t* const out) noexcept
	{

		std::memset(out, 0, out_len);

		if (out_len > 0xfffffe)
		{  //se limita a una longitud de 16777214 bytes, pero su limite real es, out_len < (2^32 - 1) * 64
			return false;
		}

		uint64_t T_max = static_cast<uint64_t>(std::ceil(static_cast<float>(out_len) / 64));  // indica el numero de bloques que se generaran

		if (T_max >= 255)
		{
			return false;
		}

		crypto_auth_hmacsha512_state init_hctx, hctx;
		uint8_t T_last_bytes = static_cast<uint8_t>(out_len - ((T_max - 1) * 64));   // indica cuantos bytes se tomaran del ultimo bloque
		uint8_t T_index[4];          // el indice de bloque
		uint8_t U[64];               // el PRF, U_1 = hmac512(key, salt || T_index) y U_(n-1) = hmac512(key, U_(n-1))
		uint8_t T[64];               // el Bloque, T = U_1 ^ U_2 ^ ... U_(n-1)
		uint8_t bytes_len = 0;       // indica la cantidad de bytes que se tomaran del bloque
		uint64_t c = 0;              // indica las iteraciones
		uint8_t x = 0;

		crypto_auth_hmacsha512_init(&init_hctx, key, key_len);          // se inicia init_hctx con el key  //(llave)
		crypto_auth_hmacsha512_update(&init_hctx, salt, salt_len);      // se agrega el fragmento del salt  //(mensaje o dato)


		for (uint8_t i = 0; i < T_max; i++)
		{                            // (Ciclo Bloques) ; T_(i)
			store32_be(static_cast<uint32_t>(i + 1), T_index);           // i=1 pasa a ivec[4]; T_index[0]=MSB...T_index[3]=LSB
			std::memcpy(&hctx, &init_hctx, sizeof(init_hctx));                // se pasa a el contenido de init_hctx a hctx
			crypto_auth_hmacsha512_update(&hctx, T_index, 4);                 // se concatena T_i a salt (salt || T_i )
			crypto_auth_hmacsha512_final(&hctx, U);                           // se genera un U_1

			memcpy(T, U, 64);                                                 // se copia U a T

			for (c = 2; c <= iterations; c++)
			{                                // (Ciclo PRF), inicia con c=2 , c < iteraciones
				crypto_auth_hmacsha512_init(&hctx, key, key_len);             // se inicia hctx con el key
				crypto_auth_hmacsha512_update(&hctx, U, 64);                  // se agrega el fragmento U
				crypto_auth_hmacsha512_final(&hctx, U);                       // se genera U_(c), PRF( HmacSha512(key, U_(c-1)) )

				for (x = 0; x < 64; x++)
				{                                     // (Ciclo XOR) va del byte 0 al 63, sha512
					T[x] ^= U[x];                                             // realiza un xor en paralelo por cada byte T[k]=T[k] ^ U[K] , si T=U_1 ; T= U_(j-1) ^ U_(j)
				}
			}

			if (i != (T_max - 1))
			{                                             // si es el ultimo byte, se copia la cantidad indicada en T_last_bytes
				bytes_len = 64;
			}
			else
			{
				bytes_len = T_last_bytes;
			}
			std::memcpy(&out[i * 64], T, static_cast<size_t>(bytes_len));          //  Los byte de cada nuevo bloque los concatenan al anterior hasta completar los bytes requeridos (outlen),
			//  asi un out[96] = T_1[64] || T_2[32]
		}
		sodium_memzero(&init_hctx, sizeof(init_hctx));
		return true;
	}

	CborSerialize::CborSerialize()
	{
		bytes_cbor_data.reserve(150);
	}
	CborSerialize::~CborSerialize()
	{
		//bytes_cbor_data = nullptr;
		bytes_cbor_data.clear();
	}
	void CborSerialize::AddNumber2Vector(uint64_t const& size_array, Pos_hex const& pos)
	{
		switch (pos)
		{
			case Pos_hex::hff:
			{ // < 0x100
				bytes_cbor_data.push_back((uint8_t)size_array);
			}; break;
			case Pos_hex::hff2:
			{ // < 0x10000
				bytes_cbor_data.push_back((size_array >> 8) & 0xff);
				bytes_cbor_data.push_back((size_array) & 0xff);
			}; break;
			case Pos_hex::hff4:
			{ // < 0x100000000
				bytes_cbor_data.push_back((size_array >> 24) & 0xff);
				bytes_cbor_data.push_back((size_array >> 16) & 0xff);
				bytes_cbor_data.push_back((size_array >> 8) & 0xff);
				bytes_cbor_data.push_back((size_array) & 0xff);
			}; break;
			case Pos_hex::hff8:
			{ // < std::UINT64_MAX
				bytes_cbor_data.push_back((size_array >> 56) & 0xff);
				bytes_cbor_data.push_back((size_array >> 48) & 0xff);
				bytes_cbor_data.push_back((size_array >> 40) & 0xff);
				bytes_cbor_data.push_back((size_array >> 32) & 0xff);
				bytes_cbor_data.push_back((size_array >> 24) & 0xff);
				bytes_cbor_data.push_back((size_array >> 16) & 0xff);
				bytes_cbor_data.push_back((size_array >> 8) & 0xff);
				bytes_cbor_data.push_back((size_array) & 0xff);
			}; break;
		}
	}
	void CborSerialize::AddNumber2Vector(uint64_t const& size_array, Pos_hex const& pos, std::vector<uint8_t>& Vector_)
	{
		switch (pos)
		{
			case Pos_hex::hff:
			{ // < 0x100
				Vector_.push_back((uint8_t)size_array);
			}; break;
			case Pos_hex::hff2:
			{ // < 0x10000
				Vector_.push_back((size_array >> 8) & 0xff);
				Vector_.push_back((size_array) & 0xff);
			}; break;
			case Pos_hex::hff4:
			{ // < 0x100000000
				Vector_.push_back((size_array >> 24) & 0xff);
				Vector_.push_back((size_array >> 16) & 0xff);
				Vector_.push_back((size_array >> 8) & 0xff);
				Vector_.push_back((size_array) & 0xff);
			}; break;
			case Pos_hex::hff8:
			{ // < std::UINT64_MAX
				Vector_.push_back((size_array >> 56) & 0xff);
				Vector_.push_back((size_array >> 48) & 0xff);
				Vector_.push_back((size_array >> 40) & 0xff);
				Vector_.push_back((size_array >> 32) & 0xff);
				Vector_.push_back((size_array >> 24) & 0xff);
				Vector_.push_back((size_array >> 16) & 0xff);
				Vector_.push_back((size_array >> 8) & 0xff);
				Vector_.push_back((size_array) & 0xff);
			}; break;
		}
	}
	CborSerialize& CborSerialize::addBytesArray(uint8_t const* const bytes, uint64_t bytes_length)
	{

		if (bytes_length < 0x18)
		{//0...23
			bytes_cbor_data.push_back((uint8_t)(bytes_length + 0x40));
		}

		else if (bytes_length < 0x100)
		{ //24...255
			bytes_cbor_data.push_back(0x58);
			AddNumber2Vector(bytes_length, Pos_hex::hff);
		}

		else if (bytes_length < 0x10000)
		{//256...65535  (uint16)
			bytes_cbor_data.push_back(0x59);
			AddNumber2Vector(bytes_length, Pos_hex::hff2);
		}

		else if (bytes_length < 0x100000000)
		{// 65536...4294967295 (uint32)
			bytes_cbor_data.push_back(0x5a);
			AddNumber2Vector(bytes_length, Pos_hex::hff4);

		}

		else if (bytes_length < UINT64_MAX)
		{ // 4294967296...18446744073709551615 (uint64)

			bytes_cbor_data.push_back(0x5b);
			AddNumber2Vector(bytes_length, Pos_hex::hff8);

		}

		bytes_cbor_data.insert(bytes_cbor_data.end(), bytes, bytes + bytes_length);

		return *this;
	};
	CborSerialize& CborSerialize::addBytesArray(std::vector<uint8_t> const& bytes)
	{
		uint64_t bytes_length = bytes.size();

		if (bytes_length < 0x18)
		{//0...23
			bytes_cbor_data.push_back((uint8_t)(bytes_length + 0x40));
		}

		else if (bytes_length < 0x100)
		{ //24...255
			bytes_cbor_data.push_back(0x58);
			AddNumber2Vector(bytes_length, Pos_hex::hff);
		}

		else if (bytes_length < 0x10000)
		{//256...65535  (uint16)
			bytes_cbor_data.push_back(0x59);
			AddNumber2Vector(bytes_length, Pos_hex::hff2);
		}

		else if (bytes_length < 0x100000000)
		{// 65536...4294967295 (uint32)
			bytes_cbor_data.push_back(0x5a);
			AddNumber2Vector(bytes_length, Pos_hex::hff4);

		}

		else if (bytes_length < UINT64_MAX)
		{ // 4294967296...18446744073709551615 (uint64)

			bytes_cbor_data.push_back(0x5b);
			AddNumber2Vector(bytes_length, Pos_hex::hff8);

		}

		bytes_cbor_data.insert(bytes_cbor_data.end(), bytes.begin(), bytes.end());

		return *this;
	};
	CborSerialize& CborSerialize::addBytesArray()
	{
		bytes_cbor_data.push_back(0x40);
		return *this;
	}
	CborSerialize& CborSerialize::addUint2BytesArray(uint64_t const number)
	{
		std::vector<uint8_t> buffData;
		if (number < 0x18)
		{//0...23
			buffData.push_back((uint8_t)(number + 0x00));
		}

		else if (number < 0x100)
		{ //24...255
			buffData.push_back(0x18);
			AddNumber2Vector(number, Pos_hex::hff, buffData);
		}

		else if (number < 0x10000)
		{//256...65535  (uint16)
			buffData.push_back(0x19);
			AddNumber2Vector(number, Pos_hex::hff2, buffData);
		}

		else if (number < 0x100000000)
		{// 65536...4294967295 (uint32)
			buffData.push_back(0x1a);
			AddNumber2Vector(number, Pos_hex::hff4, buffData);

		}

		else if (number < UINT64_MAX)
		{ // 4294967296...18446744073709551615 (uint64)

			buffData.push_back(0x1b);
			AddNumber2Vector(number, Pos_hex::hff8, buffData);
		}

		addBytesArray(buffData.data(), buffData.size());

		return *this;
	}
	CborSerialize& CborSerialize::bypassVectorCbor(std::vector<uint8_t> const& vectorCbor)
	{
		bytes_cbor_data.insert(bytes_cbor_data.end(), vectorCbor.begin(), vectorCbor.end());
		return *this;
	}
	CborSerialize& CborSerialize::bypassIteratorVectorCbor(std::vector<uint8_t>::const_iterator it_begin, std::vector<uint8_t>::const_iterator it_end)
	{
		bytes_cbor_data.insert(bytes_cbor_data.end(), it_begin, it_end);
		return *this;
	}
	CborSerialize& CborSerialize::bypassPtrUint8Cbor(uint8_t const* const ptrArrayCbor, uint64_t const ptrArrayCbor_len)
	{
		bytes_cbor_data.insert(bytes_cbor_data.end(), ptrArrayCbor, ptrArrayCbor + ptrArrayCbor_len);
		return *this;
	}
	CborSerialize& CborSerialize::addUint(uint64_t const number)
	{
		if (number < 0x18)
		{//0...23
			bytes_cbor_data.push_back((uint8_t)(number + 0x00));
		}

		else if (number < 0x100)
		{ //24...255
			bytes_cbor_data.push_back(0x18);
			AddNumber2Vector(number, Pos_hex::hff);
		}

		else if (number < 0x10000)
		{//256...65535  (uint16)
			bytes_cbor_data.push_back(0x19);
			AddNumber2Vector(number, Pos_hex::hff2);
		}

		else if (number < 0x100000000)
		{// 65536...4294967295 (uint32)
			bytes_cbor_data.push_back(0x1a);
			AddNumber2Vector(number, Pos_hex::hff4);

		}

		else if (number < UINT64_MAX)
		{ // 4294967296...18446744073709551615 (uint64)

			bytes_cbor_data.push_back(0x1b);
			AddNumber2Vector(number, Pos_hex::hff8);
		}
		return *this;
	}
	CborSerialize& CborSerialize::addUint(uint8_t const* const arraynumbe8byteshex)
	{
		uint64_t const number = (static_cast<uint64_t>(arraynumbe8byteshex[0]) << 56) | (static_cast<uint64_t>(arraynumbe8byteshex[1]) << 48) | (static_cast<uint64_t>(arraynumbe8byteshex[2]) << 40) |
			(static_cast<uint64_t>(arraynumbe8byteshex[3]) << 32) | (static_cast<uint64_t>(arraynumbe8byteshex[4]) << 24) | (static_cast<uint64_t>(arraynumbe8byteshex[5]) << 16) |
			(static_cast<uint64_t>(arraynumbe8byteshex[6]) << 8) | static_cast<uint64_t>(arraynumbe8byteshex[7]);


		if (number < 0x18)
		{//0...23
			bytes_cbor_data.insert(bytes_cbor_data.end(), arraynumbe8byteshex + 7, arraynumbe8byteshex + 8);
		}

		else if (number < 0x100)
		{ //24...255
			bytes_cbor_data.push_back(0x18);
			bytes_cbor_data.insert(bytes_cbor_data.end(), arraynumbe8byteshex + 7, arraynumbe8byteshex + 8);
		}

		else if (number < 0x10000)
		{//256...65535  (uint16)
			bytes_cbor_data.push_back(0x19);
			bytes_cbor_data.insert(bytes_cbor_data.end(), arraynumbe8byteshex + 6, arraynumbe8byteshex + 8);
		}

		else if (number < 0x100000000)
		{// 65536...4294967295 (uint32)
			bytes_cbor_data.push_back(0x1a);
			bytes_cbor_data.insert(bytes_cbor_data.end(), arraynumbe8byteshex + 4, arraynumbe8byteshex + 8);
		}

		else if (number < UINT64_MAX)
		{ // 4294967296...18446744073709551615 (uint64)
			bytes_cbor_data.push_back(0x1b);
			bytes_cbor_data.insert(bytes_cbor_data.end(), arraynumbe8byteshex, arraynumbe8byteshex + 8);
		}
		return *this;
	}
	CborSerialize& CborSerialize::addNint_zero_equal_1(uint64_t number)
	{ // toma un uint64_t y lo serializa como un numero negativo de 64bytes, considera 0 como -1

//if(number == 0){
//    throw std::invalid_argument("zero is not part of negative int");
//}

		if (number < 0x18)
		{//0...23
			bytes_cbor_data.push_back((uint8_t)(number + 0x20));
		}

		else if (number < 0x100)
		{ //24...255
			bytes_cbor_data.push_back(0x38);
			AddNumber2Vector(number, Pos_hex::hff);
		}

		else if (number < 0x10000)
		{//256...65535  (uint16)
			bytes_cbor_data.push_back(0x39);
			AddNumber2Vector(number, Pos_hex::hff2);
		}

		else if (number < 0x100000000)
		{// 65536...4294967295 (uint32)
			bytes_cbor_data.push_back(0x3a);
			AddNumber2Vector(number, Pos_hex::hff4);

		}

		else if (number < UINT64_MAX)
		{ // 4294967296...18446744073709551615 (uint64)

			bytes_cbor_data.push_back(0x3b);
			AddNumber2Vector(number, Pos_hex::hff8);
		}

		return *this;
	}
	CborSerialize& CborSerialize::addNint_withoutzero(uint64_t number)
	{ // toma un uint64_t y lo serializa como un numero negativo de 64bytes, se excluye el cero

//if(number == 0){
//    throw std::invalid_argument("zero is not part of negative int");
//}
		if (number > 0)
		{
			number -= 1; // ( n - 1 )
			addNint_zero_equal_1(number);
		}
		return *this;
	}
	CborSerialize& CborSerialize::createArray(uint64_t const size_array)
	{
		if (size_array < 0x18)
		{//0...23
			bytes_cbor_data.push_back((uint8_t)(size_array + 0x80));
		}

		else if (size_array < 0x100)
		{ //24...255
			bytes_cbor_data.push_back(0x98);
			AddNumber2Vector(size_array, Pos_hex::hff);
		}

		else if (size_array < 0x10000)
		{//256...65535  (uint16)
			bytes_cbor_data.push_back(0x99);
			AddNumber2Vector(size_array, Pos_hex::hff2);
		}

		else if (size_array < 0x100000000)
		{// 65536...4294967295 (uint32)
			bytes_cbor_data.push_back(0x9a);
			AddNumber2Vector(size_array, Pos_hex::hff4);
		}

		else if (size_array < UINT64_MAX)
		{ // 4294967296...18446744073709551615 (uint64)

			bytes_cbor_data.push_back(0x9b);
			AddNumber2Vector(size_array, Pos_hex::hff8);


		}
		return *this;
	};
	CborSerialize& CborSerialize::createArrayUndefined()
	{
		bytes_cbor_data.push_back(0x9f);
		return *this;
	}
	CborSerialize& CborSerialize::createMap(uint64_t const size_array)
	{
		if (size_array < 0x18)
		{//0...23
			bytes_cbor_data.push_back((uint8_t)(size_array + 0xa0));
		}

		else if (size_array < 0x100)
		{ //24...255
			bytes_cbor_data.push_back(0xb8);
			AddNumber2Vector(size_array, Pos_hex::hff);
		}

		else if (size_array < 0x10000)
		{//256...65535  (uint16)
			bytes_cbor_data.push_back(0xb9);
			AddNumber2Vector(size_array, Pos_hex::hff2);
		}

		else if (size_array < 0x100000000)
		{// 65536...4294967295 (uint32)
			bytes_cbor_data.push_back(0xba);
			AddNumber2Vector(size_array, Pos_hex::hff4);

		}

		else if (size_array < UINT64_MAX)
		{ // 4294967296...18446744073709551615 (uint64)

			bytes_cbor_data.push_back(0xbb);
			AddNumber2Vector(size_array, Pos_hex::hff8);

		}

		return *this;
	};
	CborSerialize& CborSerialize::addBool(bool b)
	{
		bytes_cbor_data.push_back(b ? 0xf5 : 0xf4);
		return *this;
	};
	CborSerialize& CborSerialize::addNull()
	{
		bytes_cbor_data.push_back(0xf6);
		return *this;
	}
	CborSerialize& CborSerialize::addBreak()
	{
		bytes_cbor_data.push_back(0xff);
		return *this;
	}
	CborSerialize& CborSerialize::addString(std::string const& text)
	{
		uint64_t size_array = text.size();
		if (size_array < 0x18)
		{//0...23
			bytes_cbor_data.push_back((uint8_t)(size_array + 0x60));
		}

		else if (size_array < 0x100)
		{ //24...255
			bytes_cbor_data.push_back(0x78);
			AddNumber2Vector(size_array, Pos_hex::hff);
		}

		else if (size_array < 0x10000)
		{//256...65535  (uint16)
			bytes_cbor_data.push_back(0x79);
			AddNumber2Vector(size_array, Pos_hex::hff2);
		}

		else if (size_array < 0x100000000)
		{// 65536...4294967295 (uint32)
			bytes_cbor_data.push_back(0x7a);
			AddNumber2Vector(size_array, Pos_hex::hff4);

		}

		else if (size_array < UINT64_MAX)
		{ // 4294967296...18446744073709551615 (uint64)

			bytes_cbor_data.push_back(0x7b);
			AddNumber2Vector(size_array, Pos_hex::hff8);

		}

		bytes_cbor_data.insert(bytes_cbor_data.end(), text.begin(), text.end());

		return *this;
	}
	CborSerialize& CborSerialize::addIndexMap(uint64_t const index)
	{
		addUint(index);
		return *this;
	}
	CborSerialize& CborSerialize::addIndexMap(std::string const& text)
	{
		addString(text);
		return *this;
	}
	CborSerialize& CborSerialize::addIndexMap(uint8_t const* const bytesarray, uint64_t bytesarray_length)
	{
		addBytesArray(bytesarray, bytesarray_length);
		return *this;
	}
	CborSerialize& CborSerialize::addIndexMap(uint8_t const* const arraynumbe8byteshex)
	{
		addUint(arraynumbe8byteshex);
		return *this;
	}
	CborSerialize& CborSerialize::addTag(uint64_t const number)
	{
		if (number < 0x18)
		{//0...23
			bytes_cbor_data.push_back((uint8_t)(number + 0xc0));
		}

		else if (number < 0x100)
		{ //24...255
			bytes_cbor_data.push_back(0xd8);
			AddNumber2Vector(number, Pos_hex::hff);
		}

		else if (number < 0x10000)
		{//256...65535  (uint16)
			bytes_cbor_data.push_back(0xd9);
			AddNumber2Vector(number, Pos_hex::hff2);
		}

		else if (number < 0x100000000)
		{// 65536...4294967295 (uint32)
			bytes_cbor_data.push_back(0xda);
			AddNumber2Vector(number, Pos_hex::hff4);

		}

		else if (number < UINT64_MAX)
		{ // 4294967296...18446744073709551615 (uint64)

			bytes_cbor_data.push_back(0xdb);
			AddNumber2Vector(number, Pos_hex::hff8);
		}

		return *this;
	}
	void CborSerialize::clearCbor()
	{
		bytes_cbor_data.clear();
	}
	std::vector<uint8_t> const& CborSerialize::getCbor() const
	{
		return  bytes_cbor_data;
	}

	PlutusJsonSchema::PlutusJsonSchema()
	{
		cborschema.reserve(150);
	};
	PlutusJsonSchema::~PlutusJsonSchema()
	{
		cborschema.clear();
	};
	std::size_t PlutusJsonSchema::find_caracter_it(char const caracter, std::string::const_iterator it, std::string::const_iterator it_end)
	{
		std::size_t posicion_it = 0;

		while (it + posicion_it <= it_end)
		{
			if (it[posicion_it] == caracter)
			{
				return posicion_it;
			}
			posicion_it++;
		}

		return std::string::npos;
	}
	std::size_t PlutusJsonSchema::pos_primer_caracter_it(char const caracter, std::string::const_iterator it, std::string::const_iterator it_end)
	{
		std::size_t posicion_it = 0;

		while (it + posicion_it != it_end)
		{
			switch (*(it + posicion_it))
			{
				case ' ': { posicion_it++; }; break;
				default:
				{
					if (*(it + posicion_it) == caracter)
					{
						return posicion_it;
					}
					else
					{
						return std::string::npos;
					}
				}; break;
			}
		}
		return std::string::npos;
	}
	std::size_t PlutusJsonSchema::pos_ultimo_caracter_it(char const caracter, std::string::const_iterator it, std::string::const_iterator it_end)
	{
		std::size_t posicion_it = 0;

		if (*it_end == '\0')
		{
			posicion_it++;
		}

		while (it_end - posicion_it != it)
		{
			switch (*(it_end - posicion_it))
			{
				case ' ': { posicion_it++; }; break;
				default:
				{
					if (*(it_end - posicion_it) == caracter)
					{
						return std::distance(it, it_end) - (posicion_it);
					}
					else
					{
						return std::string::npos;
					}
				}; break;
			}
		}

		return std::string::npos;
	}
	std::size_t PlutusJsonSchema::posfinal_primer_string_it(std::string const frase, std::string::const_iterator it, std::string::const_iterator it_end)
	{

		std::size_t posicion_it = 0;
		std::size_t a = 0;
		std::size_t const t = frase.size();

		while (it + posicion_it != it_end && a < t)
		{

			switch (*(it + posicion_it))
			{
				case ' ': { posicion_it++; }; break;
				default:
				{
					if (frase[a] == *(it + posicion_it))
					{
						a++;
						posicion_it++;
					}
					else
					{
						return std::string::npos;
					}
				}; break;
			}
		}
		return posicion_it;
	}
	bool PlutusJsonSchema::es_igual_ydesplazaIt(std::string const frase, std::string::iterator& it, std::string::const_iterator const& it_end)
	{ //  busca una igualdad y ademas cambia la posicion de it durante su busqueda
		std::size_t const t = frase.size();

		for (std::size_t a = 0; a < t; a++)
		{
			if (it == it_end || frase[a] != *it)
			{
				return false;
			}
			it++;
		}

		return true;
	}
	uint64_t PlutusJsonSchema::obtener_int_constructor_str(std::string::iterator& it, std::string::const_iterator const& it_end)
	{


		std::size_t cierre_valor = 0;
		bool ciclo_w = true;
		while (ciclo_w && ((it + cierre_valor) != it_end))
		{
			if ((it + cierre_valor) != it_end)
			{
				switch (*(it + cierre_valor))
				{
					case ' ':
					case '0':
					case '1':
					case '2':
					case '3':
					case '4':
					case '5':
					case '6':
					case '7':
					case '8':
					case '9': { cierre_valor++; }; break;
					case ',':
					case '}':
					{
						ciclo_w = false;
					}; break;
					default:
					{
						throw std::invalid_argument("error in \"constructor\":  positive numbers are expected  )");
					}; break;
				}

			}
			else
			{
				throw std::invalid_argument("error in \"constructor\": missing a ( } )");
			}

		}
		// ahora cierre_valor contiene la posicion del } que se usa para extraer los valores int
		std::string recorte;
		recorte.append(it, it + cierre_valor);
		uint64_t r;
		try
		{
			r = std::stoull(recorte, nullptr, 10);
		}
		catch (std::out_of_range&)
		{
			throw std::out_of_range(" error in \"constructor\" : number out of range, they must be in the range  0 .. 2^64");
		}
		it += cierre_valor;  // se dezplaza al final del numero
		return r;

	}
	uint64_t PlutusJsonSchema::obtener_int_str(std::string::iterator& it, std::string::const_iterator const& it_end, bool& npositivo)
	{

		std::size_t cierre_valor = 0;
		std::size_t inicio_valor = 0;
		bool ciclo_w = true;
		while (ciclo_w)
		{
			if ((it + cierre_valor) != it_end)
			{

				switch (*(it + cierre_valor))
				{
					case ' ':
					case '0':
					case '1':
					case '2':
					case '3':
					case '4':
					case '5':
					case '6':
					case '7':
					case '8':
					case '9': { cierre_valor++; }; break;
					case '-': { npositivo = false; cierre_valor++; inicio_valor = cierre_valor; }; break;/// una condicion para agregar numeros negativos
					case '}':
					{
						ciclo_w = false;
					}; break;
					default:
					{
						throw std::invalid_argument("error in \"int\":  numbers are expected  )");
					}; break;
				}

			}
			else
			{
				throw std::invalid_argument("error in \"int\": missing a ( } )");
			}

		}

		// ahora cierre_valor contiene la posicion del } que se usa para extraer los valores int
		std::string recorte {};
		recorte.append(it + inicio_valor, it + cierre_valor);
		uint64_t r;
		try
		{
			r = std::stoull(recorte, nullptr, 10);
		}
		catch (std::out_of_range&)
		{
			throw std::out_of_range(" error in \"int\" : number out of range, they must be in the range -2^64 .. 2^64");
		}
		it += cierre_valor + 1;  // se dezplaza fuera del }
		return r;
	}
	bool PlutusJsonSchema::obtener_bytes_str(std::string::iterator& it, std::string::const_iterator const& it_end, std::vector<uint8_t>& bytes_vector)
	{
		// para bytes
		std::size_t cierre_valor = find_caracter_it('}', it, it_end);
		if (cierre_valor != std::string::npos)
		{
			std::string recorte;
			std::size_t inicio_byte = pos_primer_caracter_it('"', it, it_end);
			if (inicio_byte != std::string::npos)
			{
				inicio_byte++; //para saltar el " del inicio
				std::size_t fin_byte = find_caracter_it('"', it + inicio_byte, it + cierre_valor); // lee solo hasta el }
				if (fin_byte != std::string::npos)
				{
					fin_byte += inicio_byte; // se suma los espacios de inicio_byte porque el calculo de fin_byte parte adelantado

					if (inicio_byte < cierre_valor && fin_byte < cierre_valor)
					{
						if (fin_byte - inicio_byte <= 128)
						{ // 64 bytes * 2 = 128, el maximo de la cadena debe de ser 64bytes
							recorte.append(it + inicio_byte, it + fin_byte);
							std::size_t bytes_uint8_len = 0;
							uint8_t const* bytes_uint8 = hexchararray2uint8array(recorte, &bytes_uint8_len);
							if (bytes_uint8 != nullptr)
							{
								bytes_vector.assign(bytes_uint8, bytes_uint8 + bytes_uint8_len);
								delete[] bytes_uint8;
								it += fin_byte + 1;
								cierre_valor = pos_primer_caracter_it('}', it, it_end);
								if (cierre_valor != std::string::npos)
								{
									it += cierre_valor + 1;
									return true;
								}
								else
								{
									throw std::invalid_argument("error in \"bytes\": missing a ( } ) ");
								}
							}
							else
							{
								throw std::invalid_argument("error in \"bytes\": invalid hexadecimal character");
							}

						}
						else
						{
							throw std::invalid_argument("error in \"bytes\": exceeds 64 bytes");
						}

					}
					else
					{
						throw std::invalid_argument("error in \"bytes\": missing a ( \" ) ");
					}
				}
				else
				{
					throw std::invalid_argument("error in \"bytes\": missing a ( \" ) at end of byte string ");
				}
			}
			else
			{
				throw std::invalid_argument("error in \"bytes\": missing a ( \" ) begin of byte string");
			}
		}
		else
		{
			throw std::invalid_argument("error in \"bytes\": missing a ( } )");
		}
		return false;
	}
	bool PlutusJsonSchema::obtener_key_value_map(std::string::iterator& it, std::string::const_iterator& it_end, std::vector<uint8_t>& key_cbor, std::vector<uint8_t>& value_cbor)
	{
		std::size_t desplazamiento_buffk = posfinal_primer_string_it("{", it, it_end);
		std::size_t desplazamiento_buffv = 0;
		uint8_t bit_keyvalue = 0; // si es igual a 3 es porque se encontro encontro el value y el key

		if (desplazamiento_buffk != std::string::npos)
		{
			it += desplazamiento_buffk;

			do
			{

				desplazamiento_buffk = posfinal_primer_string_it(R"("k")", it, it_end);
				desplazamiento_buffv = posfinal_primer_string_it(R"("v")", it, it_end);

				if (desplazamiento_buffk != std::string::npos)
				{
					it += desplazamiento_buffk;
					desplazamiento_buffk = posfinal_primer_string_it(":", it, it_end);
					if (desplazamiento_buffk != std::string::npos)
					{
						it += desplazamiento_buffk;
						//Aca se crea el tipo en cbor
						key_cbor = obtener_tipo(it, it_end);
						bit_keyvalue |= 0x01;
						desplazamiento_buffk = pos_primer_caracter_it(',', it, it_end);
						if (desplazamiento_buffk != std::string::npos)
						{ // si encuentra una coma, entonces avanza una unidad, si no hara que el ciclo se cierre
							it += desplazamiento_buffk + 1;
						}
					}
					else
					{
						throw std::invalid_argument("error in \"map\" elements: a ( : ) is expected at the end of \"k\"");
					}

				}
				else if (desplazamiento_buffv != std::string::npos)
				{
					it += desplazamiento_buffv;
					desplazamiento_buffv = posfinal_primer_string_it(":", it, it_end);
					if (desplazamiento_buffv != std::string::npos)
					{
						it += desplazamiento_buffv;
						//Aca se crea el tipo en cbor
						value_cbor = obtener_tipo(it, it_end);
						bit_keyvalue |= 0x02;
						desplazamiento_buffv = pos_primer_caracter_it(',', it, it_end);
						if (desplazamiento_buffv != std::string::npos)
						{ // si encuentra una coma, entonces avanza una unidad, si no hara que el ciclo se cierre
							it += desplazamiento_buffv + 1;
						}

					}
					else
					{
						throw std::invalid_argument("error in \"map\" elements: a ( : ) is expected at the end of \"v\"");
					}
				}

			} while (desplazamiento_buffk != std::string::npos || desplazamiento_buffv != std::string::npos);


			if (bit_keyvalue != 3)
			{
				std::string ex_error;
				if (bit_keyvalue == 0x01)
				{
					ex_error = "error in \"map\" elements: missing value ( \"v\" )";
				}
				else if (bit_keyvalue == 0x02)
				{
					ex_error = "error in \"map\" elements: missing key ( \"k\" ) ";
				}
				else
				{
					ex_error = "error in \"map\" elements: missing value or key ( \"v\" or \"k\" ) ";
				}
				throw std::invalid_argument(ex_error);
			}


			desplazamiento_buffk = posfinal_primer_string_it("}", it, it_end);
			if (desplazamiento_buffk != std::string::npos)
			{
				it += desplazamiento_buffk; // se sale del { } que contiene el value y key

			}
			else
			{
				//return false;
				throw std::invalid_argument("error in \"map\" elements: missing a ( } )");
			}

		}
		else
		{
			throw std::invalid_argument("error in \"map\" elements: missing a ( { )");
		}

		return true;
	}
	std::vector<uint8_t> PlutusJsonSchema::obtener_list_cbor(std::string::iterator& it, std::string::const_iterator& it_end)
	{
		std::unique_ptr<CborSerialize> a(new CborSerialize);

		std::size_t pos_corchete_inicio = pos_primer_caracter_it('[', it, it_end); // se delimita el espacio de trabajo de field
		std::size_t pos_corchete_fin = 0;
		std::size_t pos_coma = 0;
		std::vector<uint8_t> listvalue_cbor;
		std::vector<uint8_t> value_cbor;
		uint64_t numero_elementos_lista = 0;



		if (pos_corchete_inicio != std::string::npos)
		{
			it += pos_corchete_inicio + 1; //agrega una unidad para avanzar desde el [

			while (pos_coma != std::string::npos && it < it_end)
			{

				value_cbor = obtener_tipo(it, it_end);
				numero_elementos_lista++;
				listvalue_cbor.insert(listvalue_cbor.end(), value_cbor.begin(), value_cbor.end());
				value_cbor.clear();


				pos_coma = pos_primer_caracter_it(',', it, it_end);
				if (pos_coma != std::string::npos)
				{
					it += pos_coma + 1; // se avanza la posicion de la coma
				}

			}

			pos_corchete_fin = pos_primer_caracter_it(']', it, it_end);
			if (pos_corchete_fin != std::string::npos)
			{
				it += pos_corchete_fin + 1;
				//a->createArray(numero_elementos_lista); // las listas de momento se representan como array indefinidos
				a->createArrayUndefined();
				a->bypassIteratorVectorCbor(listvalue_cbor.begin(), listvalue_cbor.end());
				a->addBreak();
				return a->getCbor();
			}
			else
			{
				throw std::invalid_argument("error in list of element: missing a ( ] )");
			}

		}
		else
		{
			throw std::invalid_argument("error in list of element: missing a ( [ )");
		}

		return a->getCbor();
	}
	std::vector<uint8_t> PlutusJsonSchema::obtener_tipo(std::string::iterator& it, std::string::const_iterator& it_end)
	{
		std::unique_ptr<CborSerialize> a(new CborSerialize);
		std::size_t pos_caracter = 0;

		tipo_t elemento = detectar_tipo(it, it_end);

		if (elemento != tipo_t::tipo_error)
		{

			pos_caracter = pos_primer_caracter_it(':', it, it_end);

			if (pos_caracter != std::string::npos)
			{
				it += pos_caracter + 1;

				switch (elemento)
				{
					case tipo_t::tipo_constructor:
					case tipo_t::tipo_constructor_field:
					{

						uint64_t tag_constructor = 0;
						std::vector<uint8_t> field_constructor;
						std::size_t pos_coma = 0;

						while (pos_coma != std::string::npos && it < it_end)
						{



							if (elemento == tipo_t::tipo_constructor)
							{
								tag_constructor = obtener_int_constructor_str(it, it_end);
							}
							else if (elemento == tipo_t::tipo_constructor_field)
							{
								field_constructor = obtener_list_cbor(it, it_end);
							}

							pos_coma = pos_primer_caracter_it(',', it, it_end);
							if (pos_coma != std::string::npos)
							{
								it += pos_coma + 1; // se avanza la posicion de la coma
								elemento = detectar_tipo(it, it_end);

								if (elemento == tipo_t::tipo_error)
								{
									throw std::invalid_argument("error in constructor element, unknown element type");
								}
								else
								{
									pos_caracter = pos_primer_caracter_it(':', it, it_end); // avanza de los :
									if (pos_caracter != std::string::npos)
									{
										it += pos_caracter + 1;
									}
									else
									{
										std::string ex_error = " error, ( : ) is expected at the end of  ";
										switch (elemento)
										{
											case tipo_t::tipo_int: { ex_error.append("\"int\""); }; break;
											case tipo_t::tipo_bytes: { ex_error.append("\"bytes\""); }; break;
											case tipo_t::tipo_map: { ex_error.append("\"map\""); }; break;
											case tipo_t::tipo_list: { ex_error.append("\"list\""); }; break;
											case tipo_t::tipo_constructor: { ex_error.append("\"constructor\""); }; break;
											case tipo_t::tipo_constructor_field: { ex_error.append("\"fields\""); }; break;
											default: break;
										}
										throw std::invalid_argument(ex_error);
									}
								}

							}
						}

						pos_coma = pos_primer_caracter_it('}', it, it_end);
						if (pos_coma != std::string::npos)
						{
							it += pos_coma + 1; // se avanza la posicion del }
						}
						else
						{
							throw std::invalid_argument("error in constructor element, missing ( } ) at end");
						}

						if (tag_constructor < 128)
						{

							if (tag_constructor < 7)
							{
								tag_constructor += 121;
							}
							else
							{
								tag_constructor += 1273;
							}
							a->addTag(tag_constructor);

						}
						else
						{
							a->addTag(102);
							a->createArray(2);
							a->addUint(tag_constructor);
						}

						a->bypassIteratorVectorCbor(field_constructor.begin(), field_constructor.end());

						return a->getCbor();

					}; break;
					case tipo_t::tipo_int:
					{
						bool n_positivo = true;
						uint64_t n_entero = obtener_int_str(it, it_end, n_positivo);
						if (n_entero == 0)
						{
							n_positivo = true;
						}
						if (n_positivo)
						{
							a->addUint(n_entero);
						}
						else
						{
							a->addNint_withoutzero(n_entero);
						}

						return a->getCbor();;

					}; break;
					case tipo_t::tipo_bytes:
					{
						std::vector<uint8_t> bytes_;
						if (obtener_bytes_str(it, it_end, bytes_))
						{
							a->addBytesArray(bytes_);
							return a->getCbor();
						}
					}; break;
					case tipo_t::tipo_map:
					{

						std::size_t pos_corchete_inicio = pos_primer_caracter_it('[', it, it_end); // se delimita el espacio de trabajo de map
						std::size_t pos_corchete_fin = 0;
						std::size_t pos_coma = 0;
						std::vector<uint8_t> keyvalue_cbor;
						std::vector<uint8_t> key_cbor;
						std::vector<uint8_t> value_cbor;
						uint64_t numero_elementos_mapa = 0;

						if (pos_corchete_inicio != std::string::npos)
						{
							it += pos_corchete_inicio + 1; //agrega una unidad para avanzar desde el [

							while (pos_coma != std::string::npos && it < it_end)
							{

								if (obtener_key_value_map(it, it_end, key_cbor, value_cbor))
								{
									numero_elementos_mapa++;
									keyvalue_cbor.insert(keyvalue_cbor.end(), key_cbor.begin(), key_cbor.end());
									keyvalue_cbor.insert(keyvalue_cbor.end(), value_cbor.begin(), value_cbor.end());
									key_cbor.clear();
									value_cbor.clear();
								}
								else
								{
									throw std::invalid_argument("error in \"map\": could not determine the value of a variable");
								}

								pos_coma = pos_primer_caracter_it(',', it, it_end);
								if (pos_coma != std::string::npos)
								{
									it += pos_coma + 1; // se avanza la posicion de la coma
								}

							}

							pos_corchete_fin = pos_primer_caracter_it(']', it, it_end);  // realiza la busqueda del ] del mapa
							if (pos_corchete_fin != std::string::npos)
							{
								it += pos_corchete_fin + 1;
								pos_corchete_fin = pos_primer_caracter_it('}', it, it_end); // Se sale del esquema map y se crea el mapa en cbor
								if (pos_corchete_fin != std::string::npos)
								{
									it += pos_corchete_fin + 1;
									a->createMap(numero_elementos_mapa);
									a->bypassIteratorVectorCbor(keyvalue_cbor.begin(), keyvalue_cbor.end());
									return a->getCbor();;

								}
								else
								{
									throw std::invalid_argument("error in \"map\", missing ( } ) at end");
								}
							}
							else
							{
								throw std::invalid_argument("error in \"map\": missing a ( ] )");
							}



						}
						else
						{
							throw std::invalid_argument("error in \"map\": missing a ( [ )");
						}

					}; break;
					case tipo_t::tipo_list:
					{ /// poner el contenido de list en una funcion para que se pueda reutilizar en field, ver lo mismo con map

 //if(!obtener_list_cbor(it, it_end, cbor_data)){  // se pasa el vector cbor_data para que se serialize dentro de obtener_list_cbor(), pero tambien esta ligado al elemento CborSerialize de esta funcion
 //    return false;                               // pero en este "case" no se llama, asi que no genera sobre escrituras de datos
 //}
						std::vector<uint8_t> const& cbor_data = obtener_list_cbor(it, it_end);
						std::size_t pos_llave_fin = pos_primer_caracter_it('}', it, it_end); // Se sale del esquema list y se crea el mapa en cbor
						if (pos_llave_fin != std::string::npos)
						{
							it += pos_llave_fin + 1;
							return cbor_data;

						}
						else
						{
							throw std::invalid_argument("error in \"list\", missing ( } ) at end");
						}


					}; break;
					default:
					{
						throw std::invalid_argument("error could not find the data type");
					}; break;
				}

			}
			else
			{
				std::string ex_error = " error, ( : ) is expected at the end of  ";
				switch (elemento)
				{
					case tipo_t::tipo_int: { ex_error.append("\"int\""); }; break;
					case tipo_t::tipo_bytes: { ex_error.append("\"bytes\""); }; break;
					case tipo_t::tipo_map: { ex_error.append("\"map\""); }; break;
					case tipo_t::tipo_list: { ex_error.append("\"list\""); }; break;
					case tipo_t::tipo_constructor: { ex_error.append("\"constructor\""); }; break;
					case tipo_t::tipo_constructor_field: { ex_error.append("\"fields\""); }; break;
					default: break;
				}
				throw std::invalid_argument(ex_error);
			}

		}
		return a->getCbor();
	}
	PlutusJsonSchema::tipo_t PlutusJsonSchema::detectar_tipo(std::string::iterator& it, std::string::const_iterator const& it_end)
	{ //PROBADO
		uint8_t bit_caracter = 0;
		while (it != it_end)
		{
			switch (*it)
			{
				case ' ': { }; break; // en caso de espacios no hace nada
				case '"':
				{  // si no detecta previamente { , lanza error , no cuenta para el constructor
					if (bit_caracter == 1)
					{
						bit_caracter |= 0x02;
					}
					else
					{
						if (*(it + 1) == 'c' || *(it + 1) == 'f')
						{
							bit_caracter = 3;
						}
						else
						{
							throw std::invalid_argument("error, can't find element type: missing a ( { )");
							//return tipo_t::tipo_error;
						}
					}
				}; break;
				case '{':
				{ // si detecta algun otro caracter previo, lanza error
					if (bit_caracter == 0)
					{
						bit_caracter |= 0x01;
					}
					else
					{
						throw std::invalid_argument("error, can't find element type: missing a ( \" ) ");
						return tipo_t::tipo_error;
					}
				}; break;
				case 'i':
				{ // en caso de detectar un int
					if (bit_caracter == 3)
					{
						if (es_igual_ydesplazaIt("int\"", it, it_end))
						{
							return tipo_t::tipo_int;
						}
						else
						{
							throw std::invalid_argument("error, expected a ( \"int\" ) ");
						}
					}
					else
					{
						throw std::invalid_argument("error, can't find element type: missing a ( \" ) ");
					}
				}; break;
				case 'b':
				{ // en caso de detectar un bytes
					if (bit_caracter == 3)
					{
						if (es_igual_ydesplazaIt("bytes\"", it, it_end))
						{
							return tipo_t::tipo_bytes;
						}
						else
						{
							throw std::invalid_argument("error, expected a ( \"bytes\" ) ");
						}
					}
					else
					{
						throw std::invalid_argument("error, can't find element type: missing a ( \" ) ");
					}
				}; break;
				case 'm':
				{ // en caso de detectar un map
					if (bit_caracter == 3)
					{
						if (es_igual_ydesplazaIt("map\"", it, it_end))
						{
							return tipo_t::tipo_map;
						}
						else
						{
							throw std::invalid_argument("error, expected a ( \"map\" ) ");
						}
					}
					else
					{
						throw std::invalid_argument("error, can't find element type: missing a ( \" ) ");
					}
				}; break;
				case 'l':
				{ // en caso de detectar un list
					if (bit_caracter == 3)
					{
						if (es_igual_ydesplazaIt("list\"", it, it_end))
						{
							return tipo_t::tipo_list;
						}
						else
						{
							throw std::invalid_argument("error, expected a ( \"list\" ) ");
						}
					}
					else
					{
						throw std::invalid_argument("error, can't find element type: missing a ( \" ) ");
					}
				}; break;
				case 'c':
				{ // en caso de detectar un constructor
					if (bit_caracter == 3)
					{
						if (es_igual_ydesplazaIt("constructor\"", it, it_end))
						{
							return tipo_t::tipo_constructor;
						}
						else
						{
							throw std::invalid_argument("error, expected a ( \"constructor\" ) ");
						}
					}
					else
					{
						throw std::invalid_argument("error, can't find element type: missing a ( \" ) ");
					}
				}; break;
				case 'f':
				{ // en caso de detectar un fileds
					if (bit_caracter == 3)
					{
						if (es_igual_ydesplazaIt("fields\"", it, it_end))
						{
							return tipo_t::tipo_constructor_field;
						}
						else
						{
							throw std::invalid_argument("error, expected a ( \"fields\" ) ");
						}
					}
					else
					{
						throw std::invalid_argument("error, can't find element type: missing a ( \" ) ");
					}
				}; break;
				default:
				{ /** genera error **/
					std::string ex_error = "error, can't find element type: invalid argument  ( ";
					ex_error.append(1, static_cast<char>(*it));
					ex_error.append(" ) ; expect ( \" ) , ( { ) or the name of some element, eg: \"int\" ");
					throw std::invalid_argument(ex_error);
				}; break; // para el resto genera un error
			}
			if (it != it_end)
			{ // es un seguro para evitar el desbordamiento, en caso de que it halla llegado al final de su cadena, debido al uso de la funcion es_igual_ydesplazaIt()
				it++;
			}
		}

		return tipo_t::tipo_error;
	};
	void PlutusJsonSchema::addSchemaJson(std::string json)
	{


		std::string::iterator cit = json.begin(); // crea un puntero al primer elemento del string
		std::string::const_iterator cit_end = json.cend(); // crea un puntero al primer elemento del string


		try
		{
			cborschema = obtener_tipo(cit, cit_end);
		}
		catch (std::logic_error& erl)
		{
			cborschema.clear();
			std::cerr << "Plutus Json Schema: " << erl.what() << std::endl;

		}
	};
	std::vector<uint8_t> const& PlutusJsonSchema::getCborSchemaJson() const
	{

		return cborschema;

	};
	uint8_t* PlutusJsonSchema::getHash32CborSchemaJson()
	{

		crypto_generichash_blake2b(datum_hash, 32, cborschema.data(), cborschema.size(), nullptr, 0);

		return datum_hash;
	};

	Metadatas::Metadatas()
	{
		metadata_count = 0;
		ptrvec = nullptr;
	}
	//CborMetadata contain a metadata in cbor format
	void Metadatas::addMetadata(uint64_t const keytag, std::vector<uint8_t> const& CborMetadata)
	{
		// 8 (keytag) + 8(CborMetadata.size) + UINT16_MAX (CborMetadata) = 16bytes + UINT16_MAX bytes

		if (metadata_count < UINT16_MAX && CborMetadata.size() < UINT16_MAX)
		{
			addUint64toVector(metadata, keytag);
			addUint64toVector(metadata, CborMetadata.size());
			metadata.insert(metadata.end(), CborMetadata.begin(), CborMetadata.end());
			metadata_count++;
		}
	}
	bool Metadatas::arethereMetadatas() const
	{
		return metadata_count > 0 ? true : false;
	}
	std::vector<uint8_t> const& Metadatas::getCborMetadatas()
	{

		if (metadata_count > 0)
		{

			cbor.clearCbor();
			ptrvec = metadata.data();
			uint16_t metadataLen = 0;

			cbor.createMap(metadata_count);                              /// { }
			for (uint16_t m = 0; m < metadata_count; m++)
			{

				cbor.addIndexMap(ptrvec);                                /// transaction_metadatum_label :
				metadataLen = (
							static_cast<uint16_t>(ptrvec[14]) << 8) |
					static_cast<uint16_t>(ptrvec[15]
					  ); // se obtiene solo los 16bytes
				cbor.bypassPtrUint8Cbor(&ptrvec[16], metadataLen);     /// transaction_metadatum_label : transaction_metadatum

				ptrvec += 15 + metadataLen; //16 + metadataLen - 1 = 15 + metadataLen, Se resta uno menos en puntero

			}
		}
		return cbor.getCbor();
	}

	AuxiliaryData::AuxiliaryData() : Metadatas()
	{
		auxiliarymapcountbit = 0;
	}
	bool AuxiliaryData::arethereAuxiliaryData() const
	{
		return (arethereMetadatas()) ? true : false;
	}
	std::vector<uint8_t> const& AuxiliaryData::Build()
	{
		if (arethereMetadatas())
		{
			auxiliarymapcountbit |= 0x01;
		}

		//CborSerialize cbor(&cborAuxiliaryData);
		cbor.clearCbor();
		uint8_t contador = 0;

		if (auxiliarymapcountbit > 0)
		{

			for (uint8_t x = 0; x < 4; x++)
			{ //se realiza un conteo de los mapas que existen en auxiliary data
				contador += (auxiliarymapcountbit >> x) & 0x01;
			}
			cbor.addTag(259);
			cbor.createMap(contador);   /// { }
			for (uint8_t a = 0; a < 4; a++)
			{ //se asignan los datos

				if ((auxiliarymapcountbit >> a) & 0x01)
				{  //revisa cada item del transaction witness
					switch (a)
					{
						case 0:
						{
							cbor.addIndexMap(static_cast<uint64_t>(0));    /// 0 :
							cbor.bypassVectorCbor(getCborMetadatas());       /// Metadata
						}; break;
						case 1: { }; break;
						case 2: { }; break;
						case 3: { }; break;
					}
				}
			}
		}
		else
		{
			cbor.addNull();
		}
		return cbor.getCbor();
	}

	Multiassets::Multiassets()
	{
		//cbor = new CborSerialize( &buffer_cbor ); ///si no puede asignar memoria que lanze un error
	}
	Multiassets::~Multiassets()
	{
	}
	Multiassets& Multiassets::addAsset(uint8_t const* const policyID, uint8_t const* const assetname, std::size_t const& assetname_len, uint64_t const amount)
	{
		if (capsula.size() == 0)
		{ //si no se han creado datos en la capsula se crea el primer dato
			capsula.push_back(std::vector<uint8_t>(0));
			capsula[0].push_back(0); //se agrega el primer elemento del array
			capsula[0].reserve(30);
		}
		uint8_t igual = 0;  // indica si el policyid es el mismo
		std::size_t posicion = 0; //parte de la posicion cero
		std::vector<uint8_t>::iterator it = capsula[0].begin();

		for (int b = 0; b < capsula[0][0]; b++)
		{ //solo si existen policyID en capsula[0] se entra a comparar
			posicion += 1; // se pasa a la siguiente posicion (columna)
			igual = 0;
			for (int a = 0; a < 28; a++)
			{  // compara en largos de 28bytes, revisa si se repiten los policyID
				++it;  // inicia saltando a la primera posicion
				if (*it == policyID[a])
				{
					igual++;
				}
			}
			if (igual == 28)
			{    //si encuentra similitud sale del bucle
				break;  // o it = capsula[0].end();
			}

		}
		if (assetname_len < 32)
		{ // el largo del nombre no debe exceder los 32 bytes
			if (igual == 28)
			{

				cbor.clearCbor();
				cbor.addBytesArray(assetname, assetname_len);
				cbor.addUint(amount);
				std::vector<uint8_t> const& buffer_cbor = cbor.getCbor();
				capsula[posicion][0] += 1;  ///aumenta la cantidad de elementos en el mapa ///PONER LIMITE A 254 elementos
				capsula[posicion].insert(capsula[posicion].end(), buffer_cbor.begin(), buffer_cbor.end()); //inserta los datos en cbor

			}
			else
			{
				capsula[0][0] += 1;
				capsula[0].insert(capsula[0].end(), policyID, policyID + 28); //agrego el nuevo policyID, a la primera columna
				capsula.push_back(std::vector<uint8_t>(0));  //se crea otra columna para almacenar los datos de esa posicion
				posicion += 1; // se pasa a la siguiente posicion (columna)
				capsula[posicion].push_back(0); //se agrega el primer elemento del array en esa posicion

				cbor.clearCbor();
				cbor.addBytesArray(assetname, assetname_len);
				cbor.addUint(amount);
				std::vector<uint8_t> const& buffer_cbor = cbor.getCbor();
				capsula[posicion][0] += 1;  //aumenta la cantidad de elementos en el mapa
				capsula[posicion].insert(capsula[posicion].end(), buffer_cbor.begin(), buffer_cbor.end()); //inserta los datos en cbor

			}
		}
		return *this;
	}
	Multiassets& Multiassets::addAsset(uint8_t const* const policyID, std::string assetname, uint64_t const amount)
	{

		addAsset(policyID, (const uint8_t*)assetname.c_str(), assetname.size(), amount);
		return *this;
	}
	std::vector<uint8_t> const& Multiassets::getCborMultiassets()
	{
		cbor.clearCbor();
		int policyID_count = (int)static_cast<uint64_t>(capsula[0][0]);
		if (policyID_count != 0)
		{ // si no esta vacio se procede con el resto
			uint8_t* ptr_policyID = capsula[0].data();
			ptr_policyID++; //salta la primera posicion
			cbor.createMap(capsula[0][0]);

			policyID_count += 1; //aumento en uno, para que concuerde la posicion de los datos en las otras columnas
			for (int a = 1; a < policyID_count; a++)
			{
				cbor.addBytesArray(ptr_policyID, 28);
				cbor.createMap(static_cast<uint64_t>(capsula[a][0]));
				cbor.bypassIteratorVectorCbor(capsula[a].begin() + 1, capsula[a].end());
				ptr_policyID += 28;
			}
		}
		return cbor.getCbor();
	}

	Withdrawals::Withdrawals()
	{

		withdrawals_count = 0; //maximo 65534
		redeemer_withdrawals_count = 0;
		bodymap_countbit = 0;
		witnessmap_countbit = 0;
		buff_sizet = 0;

	}
	Withdrawals::~Withdrawals()
	{

	}
	Withdrawals& Withdrawals::addWithdrawals(uint8_t const* const raw_stake_address, uint64_t const amount)
	{ // ? 5 : withdrawals
/// 2(index) + 29 (raw stake address) + 8 (amount) = 39
		if (withdrawals_count < UINT16_MAX && !existen_coincidencias(raw_stake_address, withdrawals.data(), 29, withdrawals_count, 41))
		{ // Comprueba de que no se repitan las direcciones, si hay coincidencia se omite la direccion

			buff_sizet = static_cast<std::size_t>(withdrawals.capacity()) - static_cast<std::size_t>(withdrawals.size());

			// Si la capacidad reservada es menor a la que se debe ingresar se aumenta el espacio de reserva
			if (buff_sizet < 39)
			{
				withdrawals.reserve(withdrawals.size() + 39);
			}
			addUint16toVector(withdrawals, withdrawals_count);  // Index
			withdrawals.insert(withdrawals.end(), raw_stake_address, raw_stake_address + 29);
			addUint64toVector(withdrawals, amount);

			bodymap_countbit |= 0x0020;
			++withdrawals_count;

		}

		/// SINO LANZAR ERROR

		return *this;
	}
	Withdrawals& Withdrawals::addWithdrawals(std::string& stake_address, uint64_t const amount)
	{ // ? 5 : withdrawals
/// 2 (index) + 29 (raw stake address)  + 8 (amount) = 39
		uint16_t buffbech32_len = 0;
		if (bech32_decode(stake_address.c_str(), buffbech32, &buffbech32_len))
		{
			if (buffbech32_len == 29)
			{
				addWithdrawals(buffbech32, amount);
			}
			/// SINO LANZAR ERROR
		}

		return *this;
	}
	void Withdrawals::addRedeemer(std::string& json_redeemer, uint64_t const cpusteps, uint64_t const memoryunits)
	{
		std::unique_ptr<CborSerialize> rcbor(new CborSerialize);
		std::unique_ptr<CborSerialize> unitscbor(new CborSerialize);
		std::unique_ptr<PlutusJsonSchema> Json_p(new PlutusJsonSchema);

		unitscbor->createArray(2);
		unitscbor->addUint(memoryunits); // mem
		unitscbor->addUint(cpusteps);    // step

		Json_p->addSchemaJson(json_redeemer);

		std::vector<uint8_t> const& cbor_units = unitscbor->getCbor();
		std::vector<uint8_t> const& cbor_plutusdata = Json_p->getCborSchemaJson();
		if (!withdrawals_count)
			throw std::invalid_argument("Error in addRedeemer: no previous Withdrawals found");

		addUint16toVector(redeemer_withdrawals, withdrawals_count - 1);
		redeemer_withdrawals.push_back(static_cast<uint8_t>(3));                                          // tag = 3
		addUint64toVector(redeemer_withdrawals, cbor_plutusdata.size());                                 // plutusdata_len
		redeemer_withdrawals.insert(redeemer_withdrawals.end(), cbor_plutusdata.begin(), cbor_plutusdata.end()); // plutusdata
		addUint64toVector(redeemer_withdrawals, cbor_units.size());                                      // cbor_ex_units_len
		redeemer_withdrawals.insert(redeemer_withdrawals.end(), cbor_units.begin(), cbor_units.end());           // cbor_ex_units

		++redeemer_withdrawals_count;
		witnessmap_countbit |= 0x20;
		bodymap_countbit |= 0x800;
	}
	void Withdrawals::alphanumeric_organization()
	{

		std::unique_ptr<std::vector<uint8_t>> vector_data(new std::vector<uint8_t> {});
		uint8_t* ptr_data = nullptr;
		std::vector<uint8_t*> ptr_wdrl(withdrawals_count, nullptr);
		std::vector<uint8_t*> ptr_redeemers(redeemer_withdrawals_count, nullptr);
		uint16_t countmenosuno;
		int w_cmp = 0;


		if (withdrawals_count > 0)
		{
			ptr_data = withdrawals.data();
			for (uint16_t i = 0; i < withdrawals_count; i++)
			{ // asigno las localizaciones a punteros
				ptr_wdrl[i] = ptr_data;
				ptr_data += 39;
			}

			countmenosuno = withdrawals_count - 1;                // reordeno los punteros
			for (uint16_t i = 0; i < countmenosuno; i++)
			{
				for (uint16_t e = 0; e < countmenosuno; e++)
				{
					w_cmp = std::memcmp(ptr_wdrl[e] + 2, ptr_wdrl[e + 1] + 2, 29);
					if (w_cmp > 0)
					{
						ptr_data = ptr_wdrl[e];
						ptr_wdrl[e] = ptr_wdrl[e + 1];
						ptr_wdrl[e + 1] = ptr_data;
					}
				}
			}
		}


		if (redeemer_withdrawals_count > 0)
		{
			ptr_data = redeemer_withdrawals.data();
			for (uint16_t i = 0; i < redeemer_withdrawals_count; i++)
			{ // asigno las localizaciones a punteros
				ptr_redeemers[i] = ptr_data;
				ptr_data += extract8bytestoUint64(ptr_data + 3) + 11;
				ptr_data += extract8bytestoUint64(ptr_data) + 8;

			}
			// reasigna los index
			for (uint16_t i = 0; i < redeemer_withdrawals_count; i++)
			{
				for (uint16_t e = 0; e < withdrawals_count; e++)
				{
					if (ptr_redeemers[i][0] == ptr_wdrl[e][0] && ptr_redeemers[i][1] == ptr_wdrl[e][1])
					{
						replaceUint16toVector(ptr_redeemers[i], e);
						break;
					}
				}
			}
			// reordena los punteros
			countmenosuno = redeemer_withdrawals_count - 1;
			for (uint16_t i = 0; i < countmenosuno; i++)
			{
				for (uint16_t c = 0; c < countmenosuno; c++)
				{
					if (extract2bytestoUint16(ptr_redeemers[c]) > extract2bytestoUint16(ptr_redeemers[c + 1]))
					{
						ptr_data = ptr_redeemers[c];
						ptr_redeemers[c] = ptr_redeemers[c + 1];
						ptr_redeemers[c + 1] = ptr_data;
						break;
					}
				}
			}
		}


		// Reemplaza los vectores actuales
		if (withdrawals_count > 0)
		{
			vector_data->clear();
			vector_data->reserve(withdrawals_count * 39);
			for (uint16_t i = 0; i < withdrawals_count; i++)
			{
				vector_data->insert(vector_data->end(), ptr_wdrl[i], ptr_wdrl[i] + 39);
			}
			withdrawals.assign(vector_data->begin(), vector_data->end());
		}


		if (redeemer_withdrawals_count > 0)
		{
			vector_data->clear();
			for (uint16_t i = 0; i < redeemer_withdrawals_count; i++)
			{
				std::size_t ptr_redeeemers_len = extract8bytestoUint64(ptr_redeemers[i] + 3) + 11;
				ptr_redeeemers_len += extract8bytestoUint64(ptr_redeemers[i] + ptr_redeeemers_len) + 8;
				vector_data->insert(vector_data->end(), ptr_redeemers[i], ptr_redeemers[i] + ptr_redeeemers_len);
			}
			redeemer_withdrawals.assign(vector_data->begin(), vector_data->end());
		}

	}
	uint16_t const& Withdrawals::getWithdrawalRedeemersCount() const
	{
		return redeemer_withdrawals_count;
	}
	uint32_t const& Withdrawals::getBodyMapcountbit() const
	{
		return bodymap_countbit;
	}
	uint16_t const& Withdrawals::getWitnessMapcountbit() const
	{
		return witnessmap_countbit;
	}
	uint16_t const& Withdrawals::getWithdrawalsCount() const
	{
		return withdrawals_count;
	}
	std::vector<uint8_t> const& Withdrawals::getWithdrawals() const
	{
		return withdrawals;
	}
	std::vector<uint8_t> const& Withdrawals::getWithdrawalRedeemers() const
	{
		return redeemer_withdrawals;
	}

	Certificates::Certificates()
	{
		cbor_certificates_count = 0;
		redeemer_cert_count = 0;
		bodymap_countbit = 0;
		witnessmap_countbit = 0;
	}
	Certificates::~Certificates()
	{
	}
	void Certificates::addStakeRegistration(Credential const ckey, uint8_t const* const stake_credential)
	{
		// stake_credential_vk(28bytes)
		//crypto_generichash_blake2b(blake224, 28, stake_credential_vk, 32, nullptr, 0);
		cert_cbor.clearCbor();
		cert_cbor.createArray(2);                                          // [ , ]
		cert_cbor.addUint(static_cast<uint64_t>(0));                       // [0,   ]
		cert_cbor.createArray(2);                                          // [0,[ ] ]
		switch (ckey)
		{
			case Credential::RawAddressKeyHash:
			{
				cert_cbor.addUint(static_cast<uint64_t>(0));                       // [0,[0, ] ]
				cert_cbor.addBytesArray(stake_credential, 28);                             // [0,[0, addr_keyhash ] ]

			}; break;
			case Credential::RawScriptHash:
			{
				cert_cbor.addUint(static_cast<uint64_t>(1));                       // [0,[1, ] ]
				cert_cbor.addBytesArray(stake_credential, 28);                             // [0,[1, scripthash ] ]
			}; break;
		}


		std::vector<uint8_t> const& cbor = cert_cbor.getCbor();
		cbor_certificates.insert(cbor_certificates.end(), cbor.begin(), cbor.end());

		++cbor_certificates_count;
		bodymap_countbit = 0x10;

	}
	void Certificates::addStakeDeregistration(Credential const ckey, uint8_t const* const stake_credential)
	{
		// stake_credential_vk(28bytes)
		//crypto_generichash_blake2b(blake224, 28, stake_credential_vk, 32, nullptr, 0);
		cert_cbor.clearCbor();
		cert_cbor.createArray(2);                                                       // [ , ]
		cert_cbor.addUint(1);                                                           // [1,   ]
		cert_cbor.createArray(2);                                                       // [1,[ ] ]
		switch (ckey)
		{
			case Credential::RawAddressKeyHash:
			{
				cert_cbor.addUint(static_cast<uint64_t>(0));                                    // [1,[0, ] ]
				cert_cbor.addBytesArray(stake_credential, 28);                                  // [1,[0, addr_keyhash ] ]

			}; break;
			case Credential::RawScriptHash:
			{
				cert_cbor.addUint(static_cast<uint64_t>(1));                                    // [1,[1, ] ]
				cert_cbor.addBytesArray(stake_credential, 28);                                  // [1,[1, scripthash ] ]
			}; break;
		}

		std::vector<uint8_t> const& cbor = cert_cbor.getCbor();
		cbor_certificates.insert(cbor_certificates.end(), cbor.begin(), cbor.end());

		++cbor_certificates_count;
		bodymap_countbit = 0x10;
	}
	void Certificates::addStakeDelegation(Credential const ckey, uint8_t const* const stake_credential, uint8_t const* const pool_keyhash)
	{
		// stake_credential_vk(28bytes) + addr_poolkeyhash(28bytes) = 56
		//crypto_generichash_blake2b(blake224, 28, stake_credential_vk, 32, nullptr, 0);
		cert_cbor.clearCbor();
		cert_cbor.createArray(3);                                                       // [ , , ]
		cert_cbor.addUint(2);                                                           // [2, , ]
		cert_cbor.createArray(2);                                                       // [2,[ , ], ]
		switch (ckey)
		{
			case Credential::RawAddressKeyHash:
			{
				cert_cbor.addUint(static_cast<uint64_t>(0));                                    // [2,[0, ] ]
				cert_cbor.addBytesArray(stake_credential, 28);                                  // [2,[0, addr_keyhash ] ]

			}; break;
			case Credential::RawScriptHash:
			{
				cert_cbor.addUint(static_cast<uint64_t>(1));                                    // [2,[1, ] ]
				cert_cbor.addBytesArray(stake_credential, 28);                                  // [2,[1, scripthash ] ]
			}; break;
		}
		cert_cbor.addBytesArray(pool_keyhash, 28);                                      // [2,[ 0/1, keyhash/scripthash ], poolkeyhash ]

		std::vector<uint8_t> const& cbor = cert_cbor.getCbor();
		cbor_certificates.insert(cbor_certificates.end(), cbor.begin(), cbor.end());

		++cbor_certificates_count;
		bodymap_countbit = 0x10;
	}
	void Certificates::addStakeDelegation(Credential const ckey, uint8_t const* const stake_credential, std::string const& poolID_bech32)
	{
		uint8_t pool_keyhash[BECH32_MAX_LENGTH] {};
		uint16_t pool_keyhash_len = 0;
		if (!bech32_decode(poolID_bech32.data(), pool_keyhash, &pool_keyhash_len) && pool_keyhash_len != 28)
		{
			throw std::invalid_argument("addStakeDelegation error, poolID_bech32 is not a valid bech32");
		}
		addStakeDelegation(ckey, stake_credential, pool_keyhash);
	}
	// redeemer = [ tag: redeemer_tag, index: uint, data: plutus_data, ex_units: ex_units ]
	void Certificates::addRedeemer(std::string& json_redeemer, uint64_t const cpusteps, uint64_t const memoryunits)
	{

		std::unique_ptr<CborSerialize> rcbor(new CborSerialize);
		std::unique_ptr<CborSerialize> unitscbor(new CborSerialize);
		std::unique_ptr<PlutusJsonSchema> Json_p(new PlutusJsonSchema);

		unitscbor->createArray(2);
		unitscbor->addUint(memoryunits); // mem
		unitscbor->addUint(cpusteps);    // step

		Json_p->addSchemaJson(json_redeemer);

		std::vector<uint8_t> const& cbor_units = unitscbor->getCbor();
		std::vector<uint8_t> const& cbor_plutusdata = Json_p->getCborSchemaJson();
		if (!cbor_certificates_count)
			throw std::invalid_argument("Error in addRedeemer: no previous Certificates found");

		addUint16toVector(redeemer_cert, cbor_certificates_count - 1);
		redeemer_cert.push_back(static_cast<uint8_t>(2));                                    // tag = 2
		addUint64toVector(redeemer_cert, cbor_plutusdata.size());                           // plutusdata_len
		redeemer_cert.insert(redeemer_cert.end(), cbor_plutusdata.begin(), cbor_plutusdata.end());  // plutusdata
		addUint64toVector(redeemer_cert, cbor_units.size());                                // cbor_ex_units_len
		redeemer_cert.insert(redeemer_cert.end(), cbor_units.begin(), cbor_units.end());            // cbor_ex_units

		++redeemer_cert_count;
		bodymap_countbit |= 0x800;
		witnessmap_countbit |= 0x20;

	}
	std::vector<uint8_t> const& Certificates::getCertificateRedeemers() const
	{
		return redeemer_cert;
	}
	uint16_t const& Certificates::getCertificateRedeemersCount() const
	{
		return redeemer_cert_count;
	}
	uint16_t const& Certificates::getCborCertificatesCount() const
	{
		return cbor_certificates_count;
	}
	uint32_t const& Certificates::getBodyMapcountbit() const
	{
		return bodymap_countbit;
	}
	uint16_t const& Certificates::getWitnessMapcountbit() const
	{
		return witnessmap_countbit;
	}
	std::vector<uint8_t> const& Certificates::getCborCertificates() const
	{
		return cbor_certificates;
	}

	TransactionWitness::TransactionWitness()
	{
		ptrvec = nullptr;
		vkeywitness_count = 0;
		witnessmapcountbit = 0;
		buff_sizet = 0;
	}
	TransactionWitness::~TransactionWitness()
	{
		ptrvec = nullptr;
	}
	TransactionWitness& TransactionWitness::addVkeyWitness(uint8_t const* const public_key, uint8_t const* const signature_transactionbody)
	{
		//32 (public_key) + 64 (signature) = 96 bytes

		if (vkeywitness_count < UINT16_MAX && !existen_coincidencias(public_key, vkeywitness.data(), 32, vkeywitness_count, 96))
		{ //comprueba de que no se repitan los publickey
			buff_sizet = static_cast<std::size_t>(vkeywitness.capacity()) - static_cast<std::size_t>(vkeywitness.size());
			if (buff_sizet < 28)
			{
				vkeywitness.reserve(vkeywitness.size() + 96);
			}
			vkeywitness.insert(vkeywitness.end(), public_key, public_key + 32);
			vkeywitness.insert(vkeywitness.end(), signature_transactionbody, signature_transactionbody + 64);
			vkeywitness_count++;

			witnessmapcountbit |= 0x01;
		}
		return *this;
	}
	// ? 1: [* native_script ]
	// esquema:
	// para este caso no es necesario incorporar el largo de la cadena del cborNativeScript ya que viene seriealizado en cbor
	// y todos ellos iran incluido en un array de datos por lo que solo se necesita la cantidad de elementos de este array
	// |cantidad | nativescript1 |  nativescript2 | ... |
	// Recibe los native_script de las transacciones input
	//TransactionWitness &TransactionWitness::addNativeScript( uint8_t const *const cborNativeScript, std::size_t const cborNativeScript_len ){
	//    cbor_native_script.assign(cborNativeScript, cborNativeScript + cborNativeScript_len );
	//    return *this;
	//}
	TransactionWitness& TransactionWitness::addNativeScript(std::vector<uint8_t> const& cborNativeScript)
	{

		cbor_native_script = &cborNativeScript;
		witnessmapcountbit |= 0x02;

		return *this;
	}
	// ? 5: [*redeemer]
	// redeemer = [ tag: redeemer_tag, index: uint, data: plutus_data, ex_units: ex_units ]
	// esquema:  |cantidad | redeemer1 |  redeemer2 | ... |
	// Recibe los redeemer de las transacciones input
	TransactionWitness& TransactionWitness::addRedeemer(std::vector <uint8_t> const& cborRedeemers)
	{

		cbor_redeemers.assign(cborRedeemers.begin(), cborRedeemers.end());
		witnessmapcountbit |= 0X20;

		return *this;
	}
	//? 4: [* plutus_data ]
	// esquema:  |cantidad | datum1 | datum2 | ... |
	// Recibe los datum (en cbor , no hash32) de las transacciones input y output
	TransactionWitness& TransactionWitness::addDatum(std::vector <uint8_t> const& cborDatums)
	{

		cbor_datums.assign(cborDatums.begin(), cborDatums.end());
		witnessmapcountbit |= 0X10;

		return *this;
	}
	// ? 3: [* plutus_v1_script ]
	// esquema:  |cantidad | plutus_v1_script1 | plutus_v1_script2 | ... |
	// Recibe los plutus_v1_script de las transacciones input
	TransactionWitness& TransactionWitness::addPlutusV1Script(std::vector <uint8_t> const& cborPlutusV1Scripts)
	{
		cbor_plutusv1scripts = &cborPlutusV1Scripts;
		//cbor_plutusv1scripts.assign(cborPlutusV1Scripts.begin(), cborPlutusV1Scripts.end());
		witnessmapcountbit |= 0x08;
		return *this;
	}
	// ? 6: [* plutus_v2_script ]
	// esquema:  |cantidad | plutus_v2_script1 | plutus_v2_script2 | ... |
	// Recibe los plutus_v2_script de las transacciones input
	TransactionWitness& TransactionWitness::addPlutusV2Script(std::vector <uint8_t> const& cborPlutusV2Scripts)
	{
		cbor_plutusv2scripts = &cborPlutusV2Scripts;
		//cbor_plutusv2scripts.assign(cborPlutusV2Scripts.begin(), cborPlutusV2Scripts.end());
		witnessmapcountbit |= 0x40;
		return *this;
	}
	std::vector<uint8_t> const& TransactionWitness::Build()
	{
		//CborSerialize cbor(&cbor_TransactionWitness);
		cbor.clearCbor();
		uint8_t contador = 0;

		if (witnessmapcountbit > 0)
		{

			for (uint8_t x = 0; x < 7; x++)
			{ //se realiza un conteo de los mapas que existen en el transaccion witness
				contador += (witnessmapcountbit >> x) & 0x01;
			}

			cbor.createMap(contador);                                          /// { }
			for (uint8_t x = 0; x < 7; x++)
			{ //se asignan los datos

				if ((witnessmapcountbit >> x) & 0x01)
				{  //revisa cada item del transaction witness
					switch (x)
					{
						case 0:
						{
							ptrvec = vkeywitness.data();
							cbor.addIndexMap(static_cast<uint64_t>(0));                 /// ? 0:
							cbor.createArray(vkeywitness_count);                        /// [ ]
							for (uint16_t v = 0; v < vkeywitness_count; v++)
							{
								cbor.createArray(2);                                    /// [ , ]
								cbor.addBytesArray(&ptrvec[0], 32);                     /// [vkey, ]
								cbor.addBytesArray(&ptrvec[32], 64);                    /// [vkey,signature]
								ptrvec += 96;
							}

						}; break;
						case 1:
						{
							cbor.addIndexMap(static_cast<uint64_t>(1));                 /// ? 1:
							cbor.createArray(extract2bytestoUint16(cbor_native_script->data()));
							cbor.bypassIteratorVectorCbor(cbor_native_script->begin() + 2, cbor_native_script->end());
						}; break;
						case 2:
						{

						}; break;
						case 3:
						{
							cbor.addIndexMap(static_cast<uint64_t>(3));                 /// ? 3:
							cbor.createArray(extract2bytestoUint16(cbor_plutusv1scripts->data()));
							cbor.bypassIteratorVectorCbor(cbor_plutusv1scripts->begin() + 2, cbor_plutusv1scripts->end());
						}; break;
						case 4:
						{
							cbor.addIndexMap(static_cast<uint64_t>(4));                 /// ? 4:
							cbor.bypassVectorCbor(cbor_datums);
						}; break;
						case 5:
						{
							cbor.addIndexMap(static_cast<uint64_t>(5));                 /// ? 5:
							cbor.bypassVectorCbor(cbor_redeemers);
						}; break;
						case 6:
						{
							cbor.addIndexMap(static_cast<uint64_t>(6));                 /// ? 6:
							cbor.createArray(extract2bytestoUint16(cbor_plutusv2scripts->data()));
							cbor.bypassIteratorVectorCbor(cbor_plutusv2scripts->begin() + 2, cbor_plutusv2scripts->end());
						}; break;
					}
				}
			}

		}
		else
		{
			cbor.createMap(0);
		}
		return cbor.getCbor();
	}

	TransactionsInputs::TransactionsInputs()
	{
		bodymap_countbit = 0;
		witnessmap_countbit = 0;
		tx_input_count = 0;
		reference_input_count = 0;
		collateral_input_count = 0;
		datum_input_count = 0;
		buff_sizet = 0;
		redeemer_input_count = 0;
		plutusscript1_input_count = 0;
		plutusscript2_input_count = 0;
		nativescript_input_count = 0;
		globalreferencescript = ScriptType::None;

	}
	bool TransactionsInputs::addUtxoInput(uint8_t const t_selector, uint8_t const* const& TxHash, uint64_t const& TxIx)
	{   //0 : set<transaction_input> --> transaction_input = [ transaction_id : hash32, index : uint]
///2(index) + 32(TxHash) + 8(TxIx) = 42 bytes de largo cada input

		std::vector<uint8_t>* data_input = nullptr;
		uint16_t* data_input_count = nullptr;

		switch (t_selector)
		{
			case 0x00:
			{
				data_input = &tx_input;
				data_input_count = &tx_input_count;
				bodymap_countbit |= 0x0001;
			}; break;
			case 0x01:
			{
				data_input = &reference_input;
				data_input_count = &reference_input_count;
				bodymap_countbit |= 0x40000;
			}; break;
			case 0x02:
			{
				data_input = &collateral_input;
				data_input_count = &collateral_input_count;
				bodymap_countbit |= 0x2000;
			}; break;
		}

		if ((*data_input_count < UINT16_MAX) && (!existen_coincidencias(TxHash, data_input->data(), 32, *data_input_count, 40)))
		{
			buff_sizet = static_cast<std::size_t>(data_input->capacity()) - static_cast<std::size_t>(data_input->size());

			// Si la capacidad reservada es menor a la que se debe ingresar se aumenta el espacio de reserva
			if (buff_sizet < 42)
			{
				data_input->reserve(data_input->size() + 42);
			}

			addUint16toVector(data_input, data_input_count);  // Index
			data_input->insert(data_input->end(), TxHash, TxHash + 32);
			addUint64toVector(*data_input, TxIx);

			*data_input_count += 1;

			return true;
		}

		return false;
	}
	// 0 : set<transaction_input>    ; inputs
	TransactionsInputs& TransactionsInputs::addInput(std::string const& TxHash, uint64_t const TxIx)
	{
		std::size_t txhash_len;
		uint8_t const* const TxHash_uint8t = hexchararray2uint8array(TxHash, &txhash_len);
		if (txhash_len == 32)
		{
			addUtxoInput(0, TxHash_uint8t, TxIx);
		}
		delete[] TxHash_uint8t;

		return *this;
	}
	// ? 18 : set<transaction_input> ; reference inputs;
	TransactionsInputs& TransactionsInputs::addInlineScript(ScriptType const script_type, std::string const& TxHash, uint64_t const TxIx)
	{
		// de momento reference_type no tiene uso, mas alla de ser un tag para indicar el tipo de script que se usa
		std::size_t txhash_len;
		uint8_t const* const TxHash_uint8t = hexchararray2uint8array(TxHash, &txhash_len);
		if (txhash_len == 32)
		{
			addUtxoInput(1, TxHash_uint8t, TxIx);
		}
		else
		{
			delete[] TxHash_uint8t;
			throw std::invalid_argument("Error in addInlineScript: TXHash length is incorrect ");
		}
		delete[] TxHash_uint8t;
		if (script_type == ScriptType::Plutus_Script_V2)
		{
			setGlobalReferencesStriptsType(script_type);
		}
		else
		{
			throw std::invalid_argument("Error in addInlineScript: Only Plutus v2 scripts allowed");
		}

		return *this;
	}
	// ? 13 : set<transaction_input> ; collateral inputs
	TransactionsInputs& TransactionsInputs::addCollateral(std::string const& TxHash, uint64_t const TxIx)
	{
		std::size_t txhash_len;
		uint8_t const* const TxHash_uint8t = hexchararray2uint8array(TxHash, &txhash_len);
		if (txhash_len == 32)
		{
			addUtxoInput(2, TxHash_uint8t, TxIx);
		}
		delete[] TxHash_uint8t;

		return *this;
	}
	TransactionsInputs& TransactionsInputs::addDatum(std::string& json_datum)
	{

		std::unique_ptr<PlutusJsonSchema> Json_p(new PlutusJsonSchema());
		Json_p->addSchemaJson(json_datum);
		std::vector<uint8_t> const& cbor_datum = Json_p->getCborSchemaJson();
		if (!tx_input_count)
			throw std::invalid_argument("Error in addDatum: no previous Tx Input found");
		
		addUint16toVector(datum_input, tx_input_count - 1);
		addUint64toVector(datum_input, cbor_datum.size());
		datum_input.insert(datum_input.end(), cbor_datum.begin(), cbor_datum.end());
		++datum_input_count;

		bodymap_countbit |= 0x800;
		witnessmap_countbit |= 0x10;


		return *this;                                   // cbor_datum_len
	}
	// plutus_data
	//TransactionsInputs &TransactionsInputs::addSpendingDatum(std::string & json_datum){
	//    std::unique_ptr<PlutusJsonSchema> Json_p(new PlutusJsonSchema());
	//    Json_p->addSchemaJson(json_datum);
	//    std::vector<uint8_t> const & cbor_datum = Json_p->getCborSchemaJson();
	//
	//    addUint16toVector( datum_input, (tx_input_count - 1 ) );                                /// Index_datum , LANZAR ERROR SI tx_input_count=0
	//    addUint64toVector(datum_input,cbor_datum.size());                                       // cbor_datum_len
	//
	//    datum_input.insert(datum_input.end(),cbor_datum.begin(),cbor_datum.end());
	//    ++datum_input_count;
	//
	//    bodymap_countbit |= 0x800;
	//    witnessmap_countbit |= 0x10;
	//
	//    return *this;
	//}
	// redeemer = [ tag: redeemer_tag, index: uint, data: plutus_data, ex_units: ex_units ]
	TransactionsInputs& TransactionsInputs::addRedeemer(std::string& json_redeemer, uint64_t const cpusteps, uint64_t const memoryunits)
	{


		std::unique_ptr<CborSerialize> rcbor(new CborSerialize);
		std::unique_ptr<CborSerialize> unitscbor(new CborSerialize);
		std::unique_ptr<PlutusJsonSchema> Json_p(new PlutusJsonSchema);

		unitscbor->createArray(2);
		unitscbor->addUint(memoryunits); // mem
		unitscbor->addUint(cpusteps);    // step

		Json_p->addSchemaJson(json_redeemer);

		std::vector<uint8_t> const& cbor_units = unitscbor->getCbor();
		std::vector<uint8_t> const& cbor_plutusdata = Json_p->getCborSchemaJson();
		if (!tx_input_count)
			throw std::invalid_argument("Error in addRedeemer: no previous Tx Inputs found");

		addUint16toVector(redeemer_input, tx_input_count - 1);                                /// Index_redeemer , LANZAR ERROR SI tx_input_count=0
		redeemer_input.push_back(static_cast<uint8_t>(0));                                    // tag = 0
		addUint64toVector(redeemer_input, cbor_plutusdata.size());                                  // plutusdata_len
		redeemer_input.insert(redeemer_input.end(), cbor_plutusdata.begin(), cbor_plutusdata.end()); // plutusdata
		addUint64toVector(redeemer_input, cbor_units.size());                                       // cbor_ex_units_len
		redeemer_input.insert(redeemer_input.end(), cbor_units.begin(), cbor_units.end());           // cbor_ex_units

		++redeemer_input_count;
		bodymap_countbit |= 0x800;
		witnessmap_countbit |= 0x20;

		return *this;
	}
	TransactionsInputs& TransactionsInputs::addScript(ScriptType const script_type, uint8_t const* const& script, std::size_t& script_len)
	{
		switch (script_type)
		{

			case ScriptType::Native_Script:
			{
				if (nativescript_input_count == 0)
				{
					nativescript_input.assign(2, 0);  // crea un espacio con ceros para despues indicar la cantidad de script en el array
				}
				nativescript_input.insert(nativescript_input.end(), script, script + script_len);
				nativescript_input_count++;
				witnessmap_countbit |= 0x02;
			}; break;
			case ScriptType::Plutus_Script_V1:
			{
				if (plutusscript1_input_count == 0)
				{
					plutusscript1_input.assign(2, 0);  // crea un espacio con ceros para despues indicar la cantidad de script en el array
				}
				plutusscript1_input.insert(plutusscript1_input.end(), script, script + script_len);
				plutusscript1_input_count++;
				witnessmap_countbit |= 0x08;
			}; break;
			case ScriptType::Plutus_Script_V2:
			{
				if (plutusscript2_input_count == 0)
				{
					plutusscript2_input.assign(2, 0);  // crea un espacio con ceros para despues indicar la cantidad de script en el array
				}
				plutusscript2_input.insert(plutusscript2_input.end(), script, script + script_len);
				plutusscript2_input_count++;
				witnessmap_countbit |= 0x40;
			}; break;
			default: { throw std::invalid_argument("Error in addScript: ScriptType enum not valid"); }; break;
		}
		setGlobalReferencesStriptsType(script_type);
		return *this;
	}
	TransactionsInputs& TransactionsInputs::addScript(ScriptType const script_type, std::string const& script)
	{
		std::size_t script_tipo_len = 0;
		uint8_t const* script_tipo = hexchararray2uint8array(script, &script_tipo_len);
		addScript(script_type, script_tipo, script_tipo_len);
		delete[] script_tipo;
		return *this;
	}
	TransactionsInputs& TransactionsInputs::setGlobalReferencesStriptsType(ScriptType const script_type)
	{
		globalreferencescript = script_type;
		return *this;
	}
	void TransactionsInputs::alphanumeric_organization()
	{

		std::unique_ptr<std::vector<uint8_t>> vector_data(new std::vector<uint8_t> {});
		uint8_t* ptr_buffer = nullptr;
		std::vector<uint8_t*> ptr_input(tx_input_count, nullptr);
		std::vector<uint8_t*> ptr_reference_input(reference_input_count, nullptr);
		std::vector<uint8_t*> ptr_collateral_input(collateral_input_count, nullptr);
		std::vector<uint8_t*> ptr_datums(datum_input_count, nullptr);
		std::vector<uint8_t*> ptr_redeemers(redeemer_input_count, nullptr);
		uint16_t countmenosuno;
		int i_cmp = 0;

		// Inputs
		if (tx_input_count > 0)
		{
			ptr_buffer = tx_input.data();
			for (uint16_t i = 0; i < tx_input_count; i++)
			{ // asigno las localizaciones a punteros
				ptr_input[i] = ptr_buffer;
				ptr_buffer += 42;
			}
			countmenosuno = tx_input_count - 1;
			for (uint16_t i = 0; i < countmenosuno; i++)
			{
				for (uint16_t e = 0; e < countmenosuno; e++)
				{
					i_cmp = std::memcmp(ptr_input[e] + 2, ptr_input[e + 1] + 2, 40);
					if (i_cmp > 0)
					{
						ptr_buffer = ptr_input[e];
						ptr_input[e] = ptr_input[e + 1];
						ptr_input[e + 1] = ptr_buffer;
					}
				}
			}
		}

		if (reference_input_count > 0)
		{
			ptr_buffer = reference_input.data();
			for (uint16_t i = 0; i < reference_input_count; i++)
			{ // asigno las localizaciones a punteros
				ptr_reference_input[i] = ptr_buffer;
				ptr_buffer += 42;
			}

			countmenosuno = reference_input_count - 1;
			for (uint16_t i = 0; i < countmenosuno; i++)
			{
				for (uint16_t e = 0; e < countmenosuno; e++)
				{
					i_cmp = std::memcmp(ptr_reference_input[e] + 2, ptr_reference_input[e + 1] + 2, 40);
					if (i_cmp > 0)
					{
						ptr_buffer = ptr_reference_input[e];
						ptr_reference_input[e] = ptr_reference_input[e + 1];
						ptr_reference_input[e + 1] = ptr_buffer;
					}
				}
			}

		}
		// Callateral Inputs
		if (collateral_input_count > 0)
		{
			ptr_buffer = collateral_input.data();
			for (uint16_t i = 0; i < collateral_input_count; i++)
			{ // asigno las localizaciones a punteros
				ptr_collateral_input[i] = ptr_buffer;
				ptr_buffer += 42;
			}

			countmenosuno = collateral_input_count - 1;
			for (uint16_t i = 0; i < countmenosuno; i++)
			{
				for (uint16_t e = 0; e < countmenosuno; e++)
				{
					i_cmp = std::memcmp(ptr_collateral_input[e] + 2, ptr_collateral_input[e + 1] + 2, 40);
					if (i_cmp > 0)
					{
						ptr_buffer = ptr_collateral_input[e];
						ptr_collateral_input[e] = ptr_collateral_input[e + 1];
						ptr_collateral_input[e + 1] = ptr_buffer;
					}
				}
			}

		}

		// Datums
		if (datum_input_count > 0)
		{
			ptr_buffer = datum_input.data();
			for (uint16_t i = 0; i < datum_input_count; i++)
			{ // asigno las localizaciones a punteros
				ptr_datums[i] = ptr_buffer;
				ptr_buffer += extract8bytestoUint64(ptr_buffer + 2) + 10;
			}

			// reasigna los index
			for (uint16_t i = 0; i < datum_input_count; i++)
			{
				for (uint16_t e = 0; e < tx_input_count; e++)
				{
					if (ptr_datums[i][0] == ptr_input[e][0] && ptr_datums[i][1] == ptr_input[e][1])
					{
						replaceUint16toVector(ptr_datums[i], e);
						break;
					}
				}

			}
			// ordena los punteros
			countmenosuno = datum_input_count - 1;
			for (uint16_t i = 0; i < countmenosuno; i++)
			{
				for (uint16_t c = 0; c < countmenosuno; c++)
				{
					if (extract2bytestoUint16(ptr_datums[c]) > extract2bytestoUint16(ptr_datums[c + 1]))
					{
						ptr_buffer = ptr_datums[c];
						ptr_datums[c] = ptr_datums[c + 1];
						ptr_datums[c + 1] = ptr_buffer;
						break;
					}
				}
			}

		}

		// Redeemer
		if (redeemer_input_count > 0)
		{
			ptr_buffer = redeemer_input.data();
			for (uint16_t i = 0; i < redeemer_input_count; i++)
			{ // asigno las localizaciones a punteros
				ptr_redeemers[i] = ptr_buffer;
				ptr_buffer += extract8bytestoUint64(ptr_buffer + 3) + 11;
				ptr_buffer += extract8bytestoUint64(ptr_buffer) + 8;

			}
			// reasigna los index
			for (uint16_t i = 0; i < redeemer_input_count; i++)
			{
				for (uint16_t e = 0; e < tx_input_count; e++)
				{
					if (ptr_redeemers[i][0] == ptr_input[e][0] && ptr_redeemers[i][1] == ptr_input[e][1])
					{
						replaceUint16toVector(ptr_redeemers[i], e);
						break;
					}
				}
			}
			// reordena los punteros
			countmenosuno = redeemer_input_count - 1;
			for (uint16_t i = 0; i < countmenosuno; i++)
			{
				for (uint16_t c = 0; c < countmenosuno; c++)
				{
					if (extract2bytestoUint16(ptr_redeemers[c]) > extract2bytestoUint16(ptr_redeemers[c + 1]))
					{
						ptr_buffer = ptr_redeemers[c];
						ptr_redeemers[c] = ptr_redeemers[c + 1];
						ptr_redeemers[c + 1] = ptr_buffer;
						break;
					}
				}
			}


		}


		// Reemplaza los vectores actuales
		if (tx_input_count > 0)
		{
			vector_data->clear();
			vector_data->reserve(tx_input_count * 42);
			for (uint16_t i = 0; i < tx_input_count; i++)
			{
				vector_data->insert(vector_data->end(), ptr_input[i], ptr_input[i] + 42);
			}
			tx_input.assign(vector_data->begin(), vector_data->end());
		}

		if (reference_input_count > 0)
		{
			vector_data->clear();
			vector_data->reserve(reference_input_count * 42);
			for (uint16_t i = 0; i < reference_input_count; i++)
			{
				vector_data->insert(vector_data->end(), ptr_reference_input[i], ptr_reference_input[i] + 42);
			}
			reference_input.assign(vector_data->begin(), vector_data->end());
		}

		if (collateral_input_count > 0)
		{
			vector_data->clear();
			vector_data->reserve(collateral_input_count * 42);
			for (uint16_t i = 0; i < collateral_input_count; i++)
			{
				vector_data->insert(vector_data->end(), ptr_collateral_input[i], ptr_collateral_input[i] + 42);
			}
			collateral_input.assign(vector_data->begin(), vector_data->end());
		}

		if (datum_input_count > 0)
		{
			vector_data->clear();
			for (uint16_t i = 0; i < datum_input_count; i++)
			{
				std::size_t ptr_datums_len = extract8bytestoUint64(ptr_datums[i] + 2) + 10;
				vector_data->insert(vector_data->end(), ptr_datums[i], ptr_datums[i] + ptr_datums_len);
			}
			datum_input.assign(vector_data->begin(), vector_data->end());
		}

		if (redeemer_input_count > 0)
		{
			vector_data->clear();
			for (uint16_t i = 0; i < redeemer_input_count; i++)
			{
				std::size_t ptr_redeeemers_len = extract8bytestoUint64(ptr_redeemers[i] + 3) + 11;
				ptr_redeeemers_len += extract8bytestoUint64(ptr_redeemers[i] + ptr_redeeemers_len) + 8;
				vector_data->insert(vector_data->end(), ptr_redeemers[i], ptr_redeemers[i] + ptr_redeeemers_len);
			}
			redeemer_input.assign(vector_data->begin(), vector_data->end());
		}


	}
	uint32_t const& TransactionsInputs::getBodyMapcountbit() const
	{
		return bodymap_countbit;
	}
	uint16_t const& TransactionsInputs::getWitnessMapcountbit() const
	{
		return witnessmap_countbit;
	}
	ScriptType TransactionsInputs::getGlobalReferencesScriptsType() const
	{
		return globalreferencescript;
	}
	uint16_t const& TransactionsInputs::getInputsCount() const
	{
		return tx_input_count;
	}
	uint16_t const& TransactionsInputs::getInputsReferencesCount() const
	{
		return reference_input_count;
	}
	uint16_t const& TransactionsInputs::getCollateralCount() const
	{
		return collateral_input_count;
	}
	uint16_t const& TransactionsInputs::getDatumsCount() const
	{
		return datum_input_count;
	}
	uint16_t const& TransactionsInputs::getSpendingRedeemersCount() const
	{
		return redeemer_input_count;
	}
	uint16_t const& TransactionsInputs::getPlutusV1ScriptsCount() const
	{
		return plutusscript1_input_count;
	}
	uint16_t const& TransactionsInputs::getPlutusV2ScriptsCount() const
	{
		return plutusscript2_input_count;
	}
	uint16_t const& TransactionsInputs::getNativeScriptsCount() const
	{
		return nativescript_input_count;
	}
	std::vector<uint8_t> const& TransactionsInputs::getInputs() const
	{
		return tx_input;
	}
	std::vector<uint8_t> const& TransactionsInputs::getInputsReferences() const
	{
		return reference_input;
	}
	std::vector<uint8_t> const& TransactionsInputs::getCollateral() const
	{
		return collateral_input;
	}
	std::vector<uint8_t> const& TransactionsInputs::getDatums() const
	{
		return datum_input;
	}
	std::vector<uint8_t> const& TransactionsInputs::getSpendingRedeemers() const
	{
		return redeemer_input;
	}
	std::vector<uint8_t> const& TransactionsInputs::getPlutusV1Scripts()
	{
		replaceUint16toVector(plutusscript1_input.data(), plutusscript1_input_count);
		return plutusscript1_input;
	}
	std::vector<uint8_t> const& TransactionsInputs::getgetPlutusV2Scripts()
	{
		replaceUint16toVector(plutusscript2_input.data(), plutusscript2_input_count);
		return plutusscript2_input;
	}
	std::vector<uint8_t> const& TransactionsInputs::getNativeScripts()
	{
		replaceUint16toVector(nativescript_input.data(), nativescript_input_count);
		return nativescript_input;
	}

	TransactionsOutputs::TransactionsOutputs()
	{
		//cbor.reset(new CborSerialize( &cbor_array ));
		outputmap_countbit = 0;
		bodymap_countbit = 0; ///  0x0002 , Tiene que iniciar con cero
		tx_output_count = 0;      // maximo 65534
		buff_sizet = 0;
		addr_keyhash_buffer_len = 0;
		pos_registro_elementos = 0;
	}
	// 0: address
	// 1: value / [value , multiasset]
	TransactionsOutputs& TransactionsOutputs::addOutput(uint8_t const* const address_keyhash, std::size_t const& address_keyhash_len, uint64_t const& amount)
	{

		if (outputmap_countbit & 0x02)
		{ // si tiene un asset previo, se borran los datos
			std::vector<uint8_t> const& cbor_array = getCborMultiassets();
			tx_output.push_back(0x01); //separador
			addUint64toVector(tx_output, cbor_array.size()); // se agrega el largo de la cadena data_cbor
			tx_output.insert(tx_output.end(), cbor_array.begin(), cbor_array.end()); // se agrega data_cbor
			outputmap_countbit &= 0xfb;  // se pone a cero el outputmap_countbit para asset, en caso de un error evita que se vuelva a copiar
			tx_output[pos_registro_elementos] += 1;  // se agrega el conteo a asset
			tx_output[pos_registro_elementos + 1] = 0;  // indica que existen assets en este output
			capsula.clear(); // se borran los assets anteriores

		}

		if (address_keyhash_len == 29 || address_keyhash_len == 57)
		{
			outputmap_countbit &= 0xf0; //se borran todos los bits excepto el de colateral return, ya que solo puede haber uno en transaccion output
			if (tx_output_count < UINT16_MAX)
			{  // se procede si no excede el limite maximo de almacenaje


//----------- Para optimizar el almacenamiento y uso de memoria ------------
				buff_sizet = static_cast<std::size_t>(tx_output.capacity()) - static_cast<std::size_t>(tx_output.size());
				addr_keyhash_buffer_len = (uint16_t)address_keyhash_len + 10;

				// Si la capacidad reservada es menor a la que se debe ingresar se aumenta el espacio de reserva
				if (buff_sizet < addr_keyhash_buffer_len)
				{
					tx_output.reserve(tx_output.size() + addr_keyhash_buffer_len);  // Se reserva el espacio necesario para almacenar la direccion y el monto
				}
				//---------------------------------------------------------------

				tx_output_count++;
				tx_output.push_back(0); // indica que es el inicio de esta transaccion
				tx_output.push_back(1); // indica la cantidad de elementos de esta transaccion, se inicia agregando output
				pos_registro_elementos = (uint32_t)tx_output.size() - 1; // guardas la posicion del vector donde se debe registrarse la cantidad de elementos
				tx_output.push_back(1); // agrega el indicador que define la existencia de assets en este output, 1 = no hay
				tx_output.push_back(static_cast<uint8_t>(address_keyhash_len)); //Agrega el address_keyhash_len en un bytes antes del address_keyhash
				tx_output.insert(tx_output.end(), address_keyhash, address_keyhash + address_keyhash_len); //Agrega el array address_keyhash
				addUint64toVector(tx_output, amount); //Agrega el amount en 8 bytes
				//tx_output.push_back(0); // cierra esta transaccion
				bodymap_countbit |= 0x0002;
				outputmap_countbit |= 0x01;

			}

		}

		return *this;
	}
	TransactionsOutputs& TransactionsOutputs::addOutput(std::string const payment_address, uint64_t const amount)
	{

		if (bech32_decode(payment_address.c_str(), addr_keyhash_buffer, &addr_keyhash_buffer_len))
		{
			addOutput(addr_keyhash_buffer, addr_keyhash_buffer_len, amount);
		}
		else
		{
			throw std::invalid_argument("addOutput error, It is not a valid address");
		}

		return *this;
	}
	TransactionsOutputs& TransactionsOutputs::addColateralReturn(uint8_t const* const address_keyhash, std::size_t const& address_keyhash_len, uint64_t const& amount)
	{
		if ((outputmap_countbit & 0x10) == 0)
		{   // si no existe un returncolateral


			outputmap_countbit = 0;
			if (tx_output_count < UINT16_MAX)
			{  // se procede si no excede el limite maximo de almacenaje


//----------- Para optimizar el almacenamiento y uso de memoria ------------
				buff_sizet = static_cast<std::size_t>(tx_output.capacity()) - static_cast<std::size_t>(tx_output.size());
				addr_keyhash_buffer_len = (uint16_t)address_keyhash_len + 10;

				// Si la capacidad reservada es menor a la que se debe ingresar se aumenta el espacio de reserva
				if (buff_sizet < addr_keyhash_buffer_len)
				{
					tx_output.reserve(tx_output.size() + addr_keyhash_buffer_len);  // Se reserva el espacio necesario para almacenar la direccion y el monto
				}
				//---------------------------------------------------------------

				tx_output_count++;
				tx_output.push_back(5); // separador, indica que es el inicio de esta transaccion
				tx_output.push_back(static_cast<uint8_t>(address_keyhash_len)); //Agrega el address_keyhash_len en un bytes antes del address_keyhash
				tx_output.insert(tx_output.end(), address_keyhash, address_keyhash + address_keyhash_len); //Agrega el array address_keyhash
				addUint64toVector(tx_output, amount); //Agrega el amount en 8 bytes
				//tx_output.push_back(0); // cierra esta transaccion
				bodymap_countbit |= 0x10000;  // indica a txbody que existe un return colateral
				outputmap_countbit |= 0x10;

			}

		}


		return *this;
	}
	TransactionsOutputs& TransactionsOutputs::addColateralReturn(std::string const payment_address, uint64_t const amount)
	{

		if (bech32_decode(payment_address.c_str(), addr_keyhash_buffer, &addr_keyhash_buffer_len))
		{
			addColateralReturn(addr_keyhash_buffer, addr_keyhash_buffer_len, amount);
		}

		return *this;
	}
	//          [x][0]     --> cantidad de elementos en el mapa cbor (policyID o assetname)
	//capsula:  [0][x+1]   --> POLICYID(1),...,POLICYID2(n-1)
	//          [1][x+1]   --> assetname,assetname,assetname
	//          [n-1][x+1] --> assetname,assetname,assetname
	// multiasset = { * policyID : * {assetname : amount }}
	TransactionsOutputs& TransactionsOutputs::addAsset(uint8_t const* const policyID, uint8_t const* const assetname, std::size_t const& assetname_len, uint64_t const amount)
	{

		if ((outputmap_countbit & 0x01))
		{  //si existe un output

			if (capsula.size() == 0)
			{ //si no se han creado datos en la capsula se crea el primer dato
				capsula.push_back(std::vector<uint8_t>(0));
				capsula[0].push_back(0); //se agrega el primer elemento del array
				capsula[0].reserve(30);
			}
			uint8_t igual = 0;   // indica si el policyid es el mismo
			std::size_t posicion = 0; // parte de la posicion cero
			std::vector<uint8_t>::iterator it = capsula[0].begin();

			//----- Comprueba si se repiten los policyID ---------
			for (int b = 0; b < capsula[0][0]; b++)
			{ // solo si existen policyID en capsula[0] se entra a comparar
				posicion += 1;                  // se pasa a la siguiente posicion (columna)
				igual = 0;
				for (int a = 0; a < 28; a++)
				{  // compara en largos de 28bytes, revisa si se repiten los policyID
					++it;                     // inicia saltando a la primera posicion
					if (*it == policyID[a])
					{
						igual++;
					}
				}
				if (igual == 28)
				{    //si encuentra similitud sale del bucle
					break;  // o it = capsula[0].end();
				}
			}
			//-------------------------------------------------

			if (assetname_len < 32)
			{   // el largo del nombre no debe exceder los 32 bytes
				if (igual == 28)
				{      // Si se encontro el mismo PolicyID , solo se agregan el assetname

					cbor.clearCbor();
					cbor.addBytesArray(assetname, assetname_len);
					cbor.addUint(amount);
					std::vector<uint8_t> const& cbor_array = cbor.getCbor();
					capsula[posicion][0] += 1;  ///aumenta la cantidad de elementos en el mapa ///PONER LIMITE A 254 elementos
					capsula[posicion].insert(capsula[posicion].end(), cbor_array.begin(), cbor_array.end()); //inserta los datos en cbor

				}
				else
				{              // Si no encontro el mismo PolicyID , solo se agregan el policyID y el assetname
					capsula[0][0] += 1;
					capsula[0].insert(capsula[0].end(), policyID, policyID + 28); //agrego el nuevo policyID, a la primera columna
					capsula.push_back(std::vector<uint8_t>(0));  //se crea otra columna para almacenar los datos de esa posicion
					posicion += 1; // se pasa a la siguiente posicion (columna)
					capsula[posicion].push_back(0); //se agrega el primer elemento del array en esa posicion

					cbor.clearCbor();
					cbor.addBytesArray(assetname, assetname_len);
					cbor.addUint(amount);
					std::vector<uint8_t> const& cbor_array = cbor.getCbor();
					capsula[posicion][0] += 1;  //aumenta la cantidad de elementos en el mapa
					capsula[posicion].insert(capsula[posicion].end(), cbor_array.begin(), cbor_array.end()); //inserta los datos en cbor

				}
				outputmap_countbit |= 0x02;
			}

		}

		return *this;

	}
	TransactionsOutputs& TransactionsOutputs::addAsset(std::string  policyID, std::string assetname, uint64_t const amount)
	{

		std::size_t policy_id_len = 0;
		uint8_t const* policy_id = hexchararray2uint8array(policyID, &policy_id_len);
		if (policy_id_len != 28)
		{
			delete[] policy_id;
			throw std::invalid_argument("addAsset error, PolicyID is not a 28 byte array ");
		}
		addAsset(policy_id, (const uint8_t*)assetname.c_str(), assetname.size(), amount);
		delete[] policy_id;
		return *this;
	}
	// ? datum = h'hash32'
	TransactionsOutputs& TransactionsOutputs::addDatumHash(uint8_t const* const new_datum_hash, std::size_t const& datum_hash_len)
	{
		if ((outputmap_countbit & 0x05) == 1)
		{   // si existe un output y no existe un datumhash
			cbor.clearCbor();
			cbor.addBytesArray(new_datum_hash, datum_hash_len);
			std::vector<uint8_t> const& cbor_array = cbor.getCbor();

			tx_output.push_back(2); //separador
			addUint64toVector(tx_output, cbor_array.size());               // cantidad de bytes del datumhash
			tx_output.insert(tx_output.end(), cbor_array.begin(), cbor_array.end()); // datumhash
			outputmap_countbit |= 0x04;             // indica que existe un datum  o un datumhash ligado a una direccion
			tx_output[pos_registro_elementos] += 1; // se aumenta en 1 el contador de elementos en tx_output
		}
		return *this;
	}
	// ? datum = h'hash32'
	TransactionsOutputs& TransactionsOutputs::addDatumHashcreatedfromJson(std::string& json_datum)
	{
		std::unique_ptr<PlutusJsonSchema> Json_p(new PlutusJsonSchema());
		Json_p->addSchemaJson(json_datum);

		if ((outputmap_countbit & 0x05) == 1)
		{   // si existe un output y no existe un datumhash
			cbor.clearCbor();
			cbor.addBytesArray(Json_p->getHash32CborSchemaJson(), 32);
			std::vector<uint8_t> const& cbor_array = cbor.getCbor();

			tx_output.push_back(2); //separador
			addUint64toVector(tx_output, cbor_array.size());               // cantidad de bytes del datumhash
			tx_output.insert(tx_output.end(), cbor_array.begin(), cbor_array.end()); // datumhash
			outputmap_countbit |= 0x04;            // indica que existe un datum  o un datumhash ligado a una direccion
			tx_output[pos_registro_elementos] += 1; // se aumenta en 1 el contador de elementos en tx_output
		}
		return *this;
	}
	// ? datum = 24(h'datum_value cbor')]
	TransactionsOutputs& TransactionsOutputs::addInlineDatumIntValue(uint64_t const integer_datum)
	{
		if ((outputmap_countbit & 0x05) == 1)
		{  // si existe un output y no existe un datumvalue
			cbor.clearCbor();
			cbor.addTag(24);
			cbor.addUint2BytesArray(integer_datum);
			std::vector<uint8_t> const& cbor_array = cbor.getCbor();

			tx_output.push_back(3); //separador
			addUint64toVector(tx_output, cbor_array.size()); // cantidad de bytes del datum
			tx_output.insert(tx_output.end(), cbor_array.begin(), cbor_array.end()); // datum
			outputmap_countbit |= 0x04;             // indica que existe un datum  o un datumhash ligado a una direccion
			tx_output[pos_registro_elementos] += 1; // se aumenta en 1 el contador de elementos en tx_output
		}
		return *this;
	}
	// ? datum = 24(h'datum_value cbor')]
	TransactionsOutputs& TransactionsOutputs::addInlineDatum(std::string& json_datum)
	{
		std::unique_ptr<PlutusJsonSchema> Json_p(new PlutusJsonSchema());
		Json_p->addSchemaJson(json_datum);
		if ((outputmap_countbit & 0x05) == 1)
		{  // si existe un output y no existe un datumvalue
			cbor.clearCbor();
			cbor.addTag(24);
			cbor.addBytesArray(Json_p->getCborSchemaJson());
			std::vector<uint8_t> const& cbor_array = cbor.getCbor();

			tx_output.push_back(3); //separador
			addUint64toVector(tx_output, cbor_array.size()); // cantidad de bytes del datum
			tx_output.insert(tx_output.end(), cbor_array.begin(), cbor_array.end());  // datum
			outputmap_countbit |= 0x04;            // indica que existe un datum  o un datumhash ligado a una direccion
			tx_output[pos_registro_elementos] += 1; // se aumenta en 1 el contador de elementos en tx_output
		}
		return *this;
	}
	//? script_ref = 24(h'script')
	TransactionsOutputs& TransactionsOutputs::addInlineScript(ScriptType const script_type, uint8_t const* const script_, std::size_t& script_len)
	{
		if (script_type == ScriptType::None)
		{
			throw std::invalid_argument("error in addInlineScript(): ScriptType not valid");
		}
		if ((outputmap_countbit & 0x09) == 1)
		{ // si existe un output y no existe un scriptref
			std::vector<uint8_t> buff_vector;
			cbor.clearCbor();
			cbor.createArray(2);
			cbor.addUint(static_cast<uint64_t>(script_type));
			cbor.bypassPtrUint8Cbor(script_, script_len);
			std::vector<uint8_t> const& cbor_array = cbor.getCbor(); // como es un alias a la valiable privada de cbor, cbor_array actualizara su valor si cbor cambia mas adelante

			buff_vector.insert(buff_vector.begin(), cbor_array.begin(), cbor_array.end());
			cbor.clearCbor();
			cbor.addTag(24);
			cbor.addBytesArray(buff_vector.data(), buff_vector.size());

			tx_output.push_back(4); //separador
			addUint64toVector(tx_output, cbor_array.size());
			tx_output.insert(tx_output.end(), cbor_array.begin(), cbor_array.end());
			outputmap_countbit |= 0x08;
			tx_output[pos_registro_elementos] += 1;

		}
		return *this;
	}
	TransactionsOutputs& TransactionsOutputs::addInlineScript(ScriptType const script_type, std::string& script_)
	{

		std::size_t script_tipo_len = 0;
		uint8_t const* script_tipo = hexchararray2uint8array(script_, &script_tipo_len);
		addInlineScript(script_type, script_tipo, script_tipo_len);
		delete[] script_tipo;

		return *this;
	}
	uint32_t const& TransactionsOutputs::getBodyMapcountbit() const
	{
		return bodymap_countbit;
	}
	std::vector<uint8_t> const& TransactionsOutputs::getCborMultiassets()
	{
		cbor.clearCbor();
		int policyID_count = (int)static_cast<uint64_t>(capsula[0][0]);
		if (policyID_count != 0)
		{ // si no esta vacio se procede con el resto
			uint8_t* ptr_policyID = capsula[0].data();
			ptr_policyID++; //salta la primera posicion
			cbor.createMap(capsula[0][0]);

			policyID_count += 1; //aumento en uno, para que concuerde la posicion de los datos en las otras columnas
			for (int a = 1; a < policyID_count; a++)
			{
				cbor.addBytesArray(ptr_policyID, 28);
				cbor.createMap(static_cast<uint64_t>(capsula[a][0]));
				cbor.bypassIteratorVectorCbor(capsula[a].begin() + 1, capsula[a].end());
				ptr_policyID += 28;
			}
		}
		return cbor.getCbor();
	}
	std::vector<uint8_t> const& TransactionsOutputs::getTransactionsOutputs()
	{
		if (outputmap_countbit & 0x02)
		{    // en caso de que no se cree una nueva salida (addOutput), se escriben los asset almacenados en memoria a la ultima salida
			std::vector<uint8_t> const& cbor_array = getCborMultiassets();
			tx_output.push_back(0x01); //separador
			addUint64toVector(tx_output, cbor_array.size()); // se agrega el largo de la cadena data_cbor
			tx_output.insert(tx_output.end(), cbor_array.begin(), cbor_array.end()); // se agrega data_cbor
			outputmap_countbit &= 0xfb;  // se pone a cero el outputmap_countbit para asset, en caso de un error evita que se vuelva a copiar
			tx_output[pos_registro_elementos] += 1;  // se agrega el conteo a assets
			tx_output[pos_registro_elementos + 1] = 0;  // indica que existen assets en este output
			//capsula.clear(); // se borran los assets anteriores
		}
		return tx_output;
	}
	uint16_t const& TransactionsOutputs::getAmountTransactionsOutputs() const
	{
		return tx_output_count;
	}

	TransactionBody::TransactionBody() : Multiassets(),
		V1language_views {
			0xa1,0x41,0x00,0x59,0x01,0xb6,0x9f,0x1a,0x00,0x03,0x23,0x61,0x19,0x03,0x2c,0x01,0x01,0x19,0x03,0xe8,0x19,0x02,0x3b,0x00,
			0x01,0x19,0x03,0xe8,0x19,0x5e,0x71,0x04,0x01,0x19,0x03,0xe8,0x18,0x20,0x1a,0x00,0x01,0xca,0x76,0x19,0x28,0xeb,0x04,0x19,
			0x59,0xd8,0x18,0x64,0x19,0x59,0xd8,0x18,0x64,0x19,0x59,0xd8,0x18,0x64,0x19,0x59,0xd8,0x18,0x64,0x19,0x59,0xd8,0x18,0x64,
			0x19,0x59,0xd8,0x18,0x64,0x18,0x64,0x18,0x64,0x19,0x59,0xd8,0x18,0x64,0x19,0x4c,0x51,0x18,0x20,0x1a,0x00,0x02,0xac,0xfa,
			0x18,0x20,0x19,0xb5,0x51,0x04,0x1a,0x00,0x03,0x63,0x15,0x19,0x01,0xff,0x00,0x01,0x1a,0x00,0x01,0x5c,0x35,0x18,0x20,0x1a,
			0x00,0x07,0x97,0x75,0x19,0x36,0xf4,0x04,0x02,0x1a,0x00,0x02,0xff,0x94,0x1a,0x00,0x06,0xea,0x78,0x18,0xdc,0x00,0x01,0x01,
			0x19,0x03,0xe8,0x19,0x6f,0xf6,0x04,0x02,0x1a,0x00,0x03,0xbd,0x08,0x1a,0x00,0x03,0x4e,0xc5,0x18,0x3e,0x01,0x1a,0x00,0x10,
			0x2e,0x0f,0x19,0x31,0x2a,0x01,0x1a,0x00,0x03,0x2e,0x80,0x19,0x01,0xa5,0x01,0x1a,0x00,0x02,0xda,0x78,0x19,0x03,0xe8,0x19,
			0xcf,0x06,0x01,0x1a,0x00,0x01,0x3a,0x34,0x18,0x20,0x19,0xa8,0xf1,0x18,0x20,0x19,0x03,0xe8,0x18,0x20,0x1a,0x00,0x01,0x3a,
			0xac,0x01,0x19,0xe1,0x43,0x04,0x19,0x03,0xe8,0x0a,0x1a,0x00,0x03,0x02,0x19,0x18,0x9c,0x01,0x1a,0x00,0x03,0x02,0x19,0x18,
			0x9c,0x01,0x1a,0x00,0x03,0x20,0x7c,0x19,0x01,0xd9,0x01,0x1a,0x00,0x03,0x30,0x00,0x19,0x01,0xff,0x01,0x19,0xcc,0xf3,0x18,
			0x20,0x19,0xfd,0x40,0x18,0x20,0x19,0xff,0xd5,0x18,0x20,0x19,0x58,0x1e,0x18,0x20,0x19,0x40,0xb3,0x18,0x20,0x1a,0x00,0x01,
			0x2a,0xdf,0x18,0x20,0x1a,0x00,0x02,0xff,0x94,0x1a,0x00,0x06,0xea,0x78,0x18,0xdc,0x00,0x01,0x01,0x1a,0x00,0x01,0x0f,0x92,
			0x19,0x2d,0xa7,0x00,0x01,0x19,0xea,0xbb,0x18,0x20,0x1a,0x00,0x02,0xff,0x94,0x1a,0x00,0x06,0xea,0x78,0x18,0xdc,0x00,0x01,
			0x01,0x1a,0x00,0x02,0xff,0x94,0x1a,0x00,0x06,0xea,0x78,0x18,0xdc,0x00,0x01,0x01,0x1a,0x00,0x0c,0x50,0x4e,0x19,0x77,0x12,
			0x04,0x1a,0x00,0x1d,0x6a,0xf6,0x1a,0x00,0x01,0x42,0x5b,0x04,0x1a,0x00,0x04,0x0c,0x66,0x00,0x04,0x00,0x1a,0x00,0x01,0x4f,
			0xab,0x18,0x20,0x1a,0x00,0x03,0x23,0x61,0x19,0x03,0x2c,0x01,0x01,0x19,0xa0,0xde,0x18,0x20,0x1a,0x00,0x03,0x3d,0x76,0x18,
			0x20,0x19,0x79,0xf4,0x18,0x20,0x19,0x7f,0xb8,0x18,0x20,0x19,0xa9,0x5d,0x18,0x20,0x19,0x7d,0xf7,0x18,0x20,0x19,0x95,0xaa,
			0x18,0x20,0x1a,0x03,0x74,0xf6,0x93,0x19,0x4a,0x1f,0x0a,0xff
	}, V2language_views {
		   0xa1,0x01,0x98,0xaf,0x1a,0x00,0x03,0x23,0x61,0x19,0x03,0x2c,0x01,0x01,0x19,0x03,0xe8,0x19,0x02,0x3b,0x00,0x01,0x19,0x03,
		   0xe8,0x19,0x5e,0x71,0x04,0x01,0x19,0x03,0xe8,0x18,0x20,0x1a,0x00,0x01,0xca,0x76,0x19,0x28,0xeb,0x04,0x19,0x59,0xd8,0x18,
		   0x64,0x19,0x59,0xd8,0x18,0x64,0x19,0x59,0xd8,0x18,0x64,0x19,0x59,0xd8,0x18,0x64,0x19,0x59,0xd8,0x18,0x64,0x19,0x59,0xd8,
		   0x18,0x64,0x18,0x64,0x18,0x64,0x19,0x59,0xd8,0x18,0x64,0x19,0x4c,0x51,0x18,0x20,0x1a,0x00,0x02,0xac,0xfa,0x18,0x20,0x19,
		   0xb5,0x51,0x04,0x1a,0x00,0x03,0x63,0x15,0x19,0x01,0xff,0x00,0x01,0x1a,0x00,0x01,0x5c,0x35,0x18,0x20,0x1a,0x00,0x07,0x97,
		   0x75,0x19,0x36,0xf4,0x04,0x02,0x1a,0x00,0x02,0xff,0x94,0x1a,0x00,0x06,0xea,0x78,0x18,0xdc,0x00,0x01,0x01,0x19,0x03,0xe8,
		   0x19,0x6f,0xf6,0x04,0x02,0x1a,0x00,0x03,0xbd,0x08,0x1a,0x00,0x03,0x4e,0xc5,0x18,0x3e,0x01,0x1a,0x00,0x10,0x2e,0x0f,0x19,
		   0x31,0x2a,0x01,0x1a,0x00,0x03,0x2e,0x80,0x19,0x01,0xa5,0x01,0x1a,0x00,0x02,0xda,0x78,0x19,0x03,0xe8,0x19,0xcf,0x06,0x01,
		   0x1a,0x00,0x01,0x3a,0x34,0x18,0x20,0x19,0xa8,0xf1,0x18,0x20,0x19,0x03,0xe8,0x18,0x20,0x1a,0x00,0x01,0x3a,0xac,0x01,0x19,
		   0xe1,0x43,0x04,0x19,0x03,0xe8,0x0a,0x1a,0x00,0x03,0x02,0x19,0x18,0x9c,0x01,0x1a,0x00,0x03,0x02,0x19,0x18,0x9c,0x01,0x1a,
		   0x00,0x03,0x20,0x7c,0x19,0x01,0xd9,0x01,0x1a,0x00,0x03,0x30,0x00,0x19,0x01,0xff,0x01,0x19,0xcc,0xf3,0x18,0x20,0x19,0xfd,
		   0x40,0x18,0x20,0x19,0xff,0xd5,0x18,0x20,0x19,0x58,0x1e,0x18,0x20,0x19,0x40,0xb3,0x18,0x20,0x1a,0x00,0x01,0x2a,0xdf,0x18,
		   0x20,0x1a,0x00,0x02,0xff,0x94,0x1a,0x00,0x06,0xea,0x78,0x18,0xdc,0x00,0x01,0x01,0x1a,0x00,0x01,0x0f,0x92,0x19,0x2d,0xa7,
		   0x00,0x01,0x19,0xea,0xbb,0x18,0x20,0x1a,0x00,0x02,0xff,0x94,0x1a,0x00,0x06,0xea,0x78,0x18,0xdc,0x00,0x01,0x01,0x1a,0x00,
		   0x02,0xff,0x94,0x1a,0x00,0x06,0xea,0x78,0x18,0xdc,0x00,0x01,0x01,0x1a,0x00,0x11,0xb2,0x2c,0x1a,0x00,0x05,0xfd,0xde,0x00,
		   0x02,0x1a,0x00,0x0c,0x50,0x4e,0x19,0x77,0x12,0x04,0x1a,0x00,0x1d,0x6a,0xf6,0x1a,0x00,0x01,0x42,0x5b,0x04,0x1a,0x00,0x04,
		   0x0c,0x66,0x00,0x04,0x00,0x1a,0x00,0x01,0x4f,0xab,0x18,0x20,0x1a,0x00,0x03,0x23,0x61,0x19,0x03,0x2c,0x01,0x01,0x19,0xa0,
		   0xde,0x18,0x20,0x1a,0x00,0x03,0x3d,0x76,0x18,0x20,0x19,0x79,0xf4,0x18,0x20,0x19,0x7f,0xb8,0x18,0x20,0x19,0xa9,0x5d,0x18,
		   0x20,0x19,0x7d,0xf7,0x18,0x20,0x19,0x95,0xaa,0x18,0x20,0x1a,0x02,0x23,0xac,0xcc,0x0a,0x1a,0x03,0x74,0xf6,0x93,0x19,0x4a,
		   0x1f,0x0a,0x1a,0x02,0x51,0x5e,0x84,0x19,0x80,0xb3,0x0a
	}
	{
		ptrvec = nullptr;
		buff_sizet = 0;
		buff_uint32t = 0;
		addr_keyhash_buffer_len = 0;
		bodymapcountbit = 0;
		witnessmapcountbit = 0;
		//withdrawals_count = 0;
		totalcollateral = 0;
		fee = 0;
		ttl = 0;
		vis = 0;

	}
	TransactionBody::~TransactionBody()
	{
		ptrvec = nullptr;
	}
	TransactionBody& TransactionBody::addFee(uint64_t const amount)
	{ // 2 : coin; fee   --> (uint)amount lovelance
		fee = amount;
		bodymapcountbit |= 0x0004;
		return *this;
	}
	TransactionBody& TransactionBody::addInvalidAfter(uint64_t const number)
	{ // ? 3 : uint; time to live --> numberslot+200
		ttl = number;
		bodymapcountbit |= 0x0008;
		return *this;
	}
	TransactionBody& TransactionBody::addInvalidBefore(uint64_t const number)
	{ // ? 8: uint; validity interval start
		vis = number;
		bodymapcountbit |= 0x0100;
		return *this;
	}
	/**
	TransactionBody &TransactionBody::addWithdrawals(uint8_t const *const raw_stake_address, uint64_t const amount){ // ? 5 : withdrawals
		/// 29 (stake addr keyhash) + 8 (amount) = 37
		if(withdrawals_count < UINT16_MAX && !existen_coincidencias(raw_stake_address, withdrawals.data(), 29, withdrawals_count, 37) ){ // Comprueba de que no se repitan las direcciones, si hay coincidencia se omite la direccion

			buff_sizet = static_cast<std::size_t>( withdrawals.capacity() ) - static_cast<std::size_t>( withdrawals.size() );

			// Si la capacidad reservada es menor a la que se debe ingresar se aumenta el espacio de reserva
			if(buff_sizet < 37){
				withdrawals.reserve(withdrawals.size() + 37);
			}

			withdrawals_count++;
			withdrawals.insert(withdrawals.end(), raw_stake_address, raw_stake_address + 29);
			addUint64toVector(withdrawals, amount);

			bodymapcountbit |= 0x0020;

		}
		return *this;
	}

	TransactionBody &TransactionBody::addWithdrawals(std::string &stake_address, uint64_t const amount){ // ? 5 : withdrawals
		/// 29 (stake addr keyhash) + 8 (amount) = 37

		if(bech32_decode(stake_address.c_str(), addr_keyhash_buffer, &addr_keyhash_buffer_len)){
			if(addr_keyhash_buffer_len == 29){

				addWithdrawals(addr_keyhash_buffer, amount);

			}

		}

		return *this;
	}

	**/
	TransactionBody& TransactionBody::addTotalCollateral(uint64_t const amount)
	{
		totalcollateral = amount;
		bodymapcountbit |= 0x20000;
		return *this;
	}
	TransactionBody& TransactionBody::addAuxiliaryDataHash(uint8_t const* const hash_32bytes)
	{ // ? 7 : byte array ; auxiliary_data_hash --> blake2b256(auxiliary_data)
// Reserva 32 bytes para contener el hash blake2b256
		auxiliary_data_hash.reserve(32);

		// Inserta el hash_32bytes en auxiliary_data_hash
		auxiliary_data_hash.assign(hash_32bytes, hash_32bytes + 32);

		bodymapcountbit |= 0x0080;
		return *this;
	}
	//-------
	std::vector<uint8_t> const& TransactionBody::Build()
	{
		//CborSerialize cbor(&cborTransactionBody);
		cbor.clearCbor();
		uint64_t contador = 0;
		witnessmapcountbit = TransactionInput.getWitnessMapcountbit();
		witnessmapcountbit |= Certificate.getWitnessMapcountbit();
		witnessmapcountbit |= Withdrawal.getWitnessMapcountbit();
		bodymapcountbit |= TransactionOutput.getBodyMapcountbit();
		bodymapcountbit |= TransactionInput.getBodyMapcountbit();
		bodymapcountbit |= Certificate.getBodyMapcountbit();
		bodymapcountbit |= Withdrawal.getBodyMapcountbit();

		TransactionInput.alphanumeric_organization();
		Withdrawal.alphanumeric_organization();


		if (bodymapcountbit > 0)
		{ //Condicion que salta el proceso en caso de que no hayan datos

//Aca agregar al bodymapcountbit, la existencia de certificados (bodymapcountbit |= 0x0010;)
			for (uint8_t x = 0; x < 19; x++)
			{ //se realiza un conteo de los mapas que existen en el transaccion body 0 - 18
				contador += (bodymapcountbit >> x) & 0x01;
			}

			cbor.createMap(contador);                                      /// { }

			for (uint8_t x = 0; x < 19; x++)
			{ //se asignan los datos

				if ((bodymapcountbit >> x) & 0x01)
				{  //revisa cada item del transaction body

					switch (x)
					{
						case 0:
						{
							ptrvec = TransactionInput.getInputs().data();
							uint16_t const& input_count = TransactionInput.getInputsCount();

							cbor.addIndexMap(static_cast<uint64_t>(0));   /// 0:
							cbor.createArray(input_count);                     /// [  ]
							for (uint16_t t = 0; t < input_count; t++)
							{
								cbor.createArray(2);                           /// [ , ],
								cbor.addBytesArray(&ptrvec[2], 32);            /// [ TxHash , ],
								cbor.addUint(&ptrvec[34]);                     /// [ TxHash , TxIx ],
								ptrvec += 42;
							}


							uint16_t const& collateralinput_count = TransactionInput.getCollateralCount();
							if (collateralinput_count > 0)
							{
								ptrvec = TransactionInput.getCollateral().data();

								cbor.addIndexMap(13);                              /// 13:
								cbor.createArray(collateralinput_count);           /// [  ]
								for (uint16_t t = 0; t < collateralinput_count; t++)
								{
									cbor.createArray(2);                           /// [ , ],
									cbor.addBytesArray(&ptrvec[2], 32);            /// [ TxHash , ],
									cbor.addUint(&ptrvec[34]);                     /// [ TxHash , TxIx ],
									ptrvec += 42;
								}


							}
							uint16_t const& referenceinput_count = TransactionInput.getInputsReferencesCount();
							if (referenceinput_count > 0)
							{
								ptrvec = TransactionInput.getInputsReferences().data();
								cbor.addIndexMap(18);                              /// 18:
								cbor.createArray(referenceinput_count);           /// [  ]
								for (uint16_t t = 0; t < referenceinput_count; t++)
								{
									cbor.createArray(2);                           /// [ , ],
									cbor.addBytesArray(&ptrvec[2], 32);            /// [ TxHash , ],
									cbor.addUint(&ptrvec[34]);                     /// [ TxHash , TxIx ],
									ptrvec += 42;
								}

							}
						}; break;
						case 1:
						{
							buff_uint32t = 0; // Se encargara de guardar el tamaño del array , max
							ptrvec = TransactionOutput.getTransactionsOutputs().data();
							uint16_t const& output_count = TransactionOutput.getAmountTransactionsOutputs(); // se obtiene la cantidad de direcciones de salida
							uint8_t const* pos_map_transaccion_output[6] {};  // la ultima esta reservada para collateral return y no se borra
							uint8_t count_map_transaccion = 0;

							cbor.addIndexMap(1);
							// en caso de existir un returncolateral se resta 1 ya que no pertenece a este array,
							// return colateral se agregara posteriormente                                         /// 1:
							cbor.createArray(output_count - ((TransactionOutput.getBodyMapcountbit() & 0x10000) >> 16));   /// [{q},{w},{n},..]

							for (uint8_t i = 0; i < output_count; i++)
							{ // { 0: address_keyhash, 1: amount, ? 2: datum_option, ? 3: script_ref},
// Se borran los punteros previos de 0 - 4
								for (int c = 0; c < 5; c++)
								{
									pos_map_transaccion_output[c] = nullptr;
								}
								// Se extraen la cantidad de elementos del mapa,  ¿usar switch?
								if (*ptrvec == 0x00)
								{  // en caso de detectar este separador
									count_map_transaccion = *(ptrvec + 1);
									// {a,b,c,d}  "el addOutput vale por 2 (0: address y 1:amount) y por 1 en 1:[amount, assets]
									cbor.createMap(static_cast<uint64_t>(count_map_transaccion + *(ptrvec + 2)));

								}
								else if (*ptrvec == 0x05)
								{ //en caso de detectar el separador de collateral return
									count_map_transaccion = 1;
								}
								//Se ordenan los datos en un vector de puntero (pos_map_transaccion_output)
								/// Se podria facilmente escribir los datos aqui, pero para una mejor lectura en cbor se respetaran las posiciones antes de escribir los datos.
								/// Funcionalmente el orden no deberia afectar.
								for (uint8_t c = 0; c < count_map_transaccion; c++)
								{
									switch (*ptrvec)
									{
										case 0x00:
										{    //"addOutput"
											ptrvec += 3;
											pos_map_transaccion_output[0] = ptrvec;
											ptrvec += *ptrvec + 8 + 1;
										}; break;
										case 0x01:
										{   //"addAsset
											ptrvec += 1;
											pos_map_transaccion_output[1] = ptrvec;
											ptrvec += extract8bytestoUint64(ptrvec) + 8; //el numero 8, es un buffer de 8 bytes que almacena el largo en bytes del la variable
										}; break;
										case 0x02:
										{   //addDatumHash
											ptrvec += 1;
											pos_map_transaccion_output[2] = ptrvec;
											ptrvec += extract8bytestoUint64(ptrvec) + 8;
										}; break;
										case 0x03:
										{   //addInlineDatum
											ptrvec += 1;
											pos_map_transaccion_output[3] = ptrvec;
											ptrvec += extract8bytestoUint64(ptrvec) + 8;
										}; break;
										case 0x04:
										{  //addInlineScript
											ptrvec += 1;
											pos_map_transaccion_output[4] = ptrvec;
											ptrvec += extract8bytestoUint64(ptrvec) + 8;
										}; break;
										case 0x05:
										{  //addReturnColateral
											ptrvec += 1;
											pos_map_transaccion_output[5] = ptrvec;
											ptrvec += *ptrvec + 8 + 1;
										}; break;
									}
								}

								// Se escriben los datos de manera ordenada, se excluye a addReturnColateral de este paso
								for (int c = 0; c < 5; c++)
								{
									if (pos_map_transaccion_output[c] != nullptr)
									{
										switch (c)
										{
											case 0:
											{                                                                        /// 0: address_keyhash, 1: amount,
												cbor.addIndexMap(static_cast<uint64_t>(0));
												buff_uint32t = static_cast<uint16_t>(*pos_map_transaccion_output[c]);
												cbor.addBytesArray(pos_map_transaccion_output[c] + 1, buff_uint32t);  //pos_map_transaccion_output[c][n]
												cbor.addIndexMap(1);
												if (pos_map_transaccion_output[1] != nullptr)
												{
													cbor.createArray(2);
												}
												cbor.addUint(pos_map_transaccion_output[c] + 1 + buff_uint32t);

											}; break;
											case 1:
											{                                                                        ///  1: [amount, ? assets] ,
												buff_uint32t = (uint32_t)extract8bytestoUint64(pos_map_transaccion_output[c]);
												cbor.bypassPtrUint8Cbor(pos_map_transaccion_output[c] + 8, buff_uint32t);
											}; break;
											case 2:
											{                                                                        /// ? 2: [0,hash32] ,
												cbor.addIndexMap(2).createArray(2).addUint(static_cast<uint64_t>(0));

												buff_uint32t = (uint32_t)extract8bytestoUint64(pos_map_transaccion_output[c]);
												cbor.bypassPtrUint8Cbor(pos_map_transaccion_output[c] + 8, buff_uint32t);

											}; break;
											case 3:
											{                                                                        /// ? 2: [1,data] ,
												cbor.addIndexMap(2).createArray(2).addUint(1);
												buff_uint32t = (uint32_t)extract8bytestoUint64(pos_map_transaccion_output[c]);
												cbor.bypassPtrUint8Cbor(pos_map_transaccion_output[c] + 8, buff_uint32t);
											}; break;
											case 4:
											{                                                                        /// ? 3: script_ref,
												cbor.addIndexMap(3);
												buff_uint32t = (uint32_t)extract8bytestoUint64(pos_map_transaccion_output[c]);
												cbor.bypassPtrUint8Cbor(pos_map_transaccion_output[c] + 8, buff_uint32t);
											}; break;
										}
									}
								}
							}

							/// ? 16 : transaction_output ;collateral return
							if (pos_map_transaccion_output[5] != nullptr)
							{
								cbor.addIndexMap(16).createMap(2).addIndexMap(static_cast<uint64_t>(0));;
								buff_uint32t = static_cast<uint16_t>(*pos_map_transaccion_output[5]);
								cbor.addBytesArray(pos_map_transaccion_output[5] + 1, buff_uint32t);  //pos_map_transaccion_output[c][n]
								cbor.addIndexMap(1);
								cbor.addUint(pos_map_transaccion_output[5] + 1 + buff_uint32t);
							}
						}; break;
						case 2:
						{
							cbor.addIndexMap(2);                                 /// 2:
							cbor.addUint(fee);                                   /// fee
						}; break;
						case 3:
						{
							cbor.addIndexMap(3);                                 /// 3:
							cbor.addUint(ttl);                                   /// ttl
						}; break;
						case 4:
						{
							cbor.addIndexMap(4);                                       /// 4:
							cbor.createArray(static_cast<uint64_t>(Certificate.getCborCertificatesCount()));
							cbor.bypassVectorCbor(Certificate.getCborCertificates());  /// certificates
						}; break;
						case 5:
						{
							uint16_t const& withdrawals_count = Withdrawal.getWithdrawalsCount();
							ptrvec = Withdrawal.getWithdrawals().data();
							cbor.addIndexMap(5);                                 /// 5:
							cbor.createMap(withdrawals_count);                   /// {  }
							for (uint8_t i = 0; i < withdrawals_count; i++)
							{
								cbor.addIndexMap(&ptrvec[2], 29);                /// stake_address_keyhash :
								cbor.addUint(&ptrvec[31]);                       /// stake_address_keyhash : amount
								ptrvec += 39;
							}
						}; break;
						case 6: { }; break;
						case 7:
						{
							cbor.addIndexMap(7);                                 /// 7:
							cbor.addBytesArray(auxiliary_data_hash.data(), 32);   /// auxiliary_data_hash
						}; break;
						case 8:
						{
							cbor.addIndexMap(8);                                 /// 8:
							cbor.addUint(vis);                                   /// validity interval start
						}; break;
						case 9: { }; break;
						case 10: { }; break;
						case 11:
						{   // redeemers | datums | laguage views

							std::unique_ptr<CborSerialize> script_data(new CborSerialize);
							uint16_t const& datum_data_count = TransactionInput.getDatumsCount();
							uint16_t const& spendredeemer_data_count = TransactionInput.getSpendingRedeemersCount();
							uint16_t const& certredeemer_data_count = Certificate.getCertificateRedeemersCount();
							uint16_t const& rewardredeemer_data_count = Withdrawal.getWithdrawalRedeemersCount();

							switch ((witnessmapcountbit & 0x30))
							{
								case 0x10:
								{

									ptrvec = TransactionInput.getDatums().data();
									script_data->createArray(0);                                                       //  80
									script_data->createArray(static_cast<uint64_t>(datum_data_count));            //  [datums]
									for (uint16_t t = 0; t < datum_data_count; t++)
									{
										script_data->bypassPtrUint8Cbor(ptrvec + 10, extract8bytestoUint64(ptrvec + 2));
										ptrvec += extract8bytestoUint64(ptrvec + 2) + 10;
									}
									script_data->createMap(0);                                                          //  A0

									std::vector<uint8_t> const& buff_getCbor = script_data->getCbor();  // se agrega la serializacion a la variable cbor_datums (se usa en witnnes)
									cbor_datums.assign(buff_getCbor.begin() + 1, buff_getCbor.end() - 1);

								}; break;
								case 0x30:
								case 0x20:
								{
									uint16_t const redeemer_data_count = spendredeemer_data_count + certredeemer_data_count + rewardredeemer_data_count;

									script_data->createArray(static_cast<uint64_t>(redeemer_data_count));                // [ ]

									if (spendredeemer_data_count)
									{
										ptrvec = TransactionInput.getSpendingRedeemers().data();
										for (uint16_t t = 0; t < spendredeemer_data_count; t++)
										{
											script_data->createArray(4);                                                           // [ , , , ]
											script_data->addUint(*(ptrvec + 2));                                               // tag
											script_data->addUint(extract2bytestoUint16(ptrvec));                                 // index
											script_data->bypassPtrUint8Cbor(ptrvec + 11, extract8bytestoUint64(ptrvec + 3));   // plutus_data
											ptrvec += extract8bytestoUint64(ptrvec + 3) + 11;                                    // cambio al posicion de ptrvec
											script_data->bypassPtrUint8Cbor(ptrvec + 8, extract8bytestoUint64(ptrvec));          // ex_units
											ptrvec += extract8bytestoUint64(ptrvec) + 8;
										}

									}

									if (certredeemer_data_count)
									{
										ptrvec = Certificate.getCertificateRedeemers().data();
										for (uint16_t t = 0; t < certredeemer_data_count; t++)
										{
											script_data->createArray(4);                                                           // [ , , , ]
											script_data->addUint(*(ptrvec + 2));                                               // tag
											script_data->addUint(extract2bytestoUint16(ptrvec));                                 // index
											script_data->bypassPtrUint8Cbor(ptrvec + 11, extract8bytestoUint64(ptrvec + 3));   // plutus_data
											ptrvec += extract8bytestoUint64(ptrvec + 3) + 11;                                    // cambio al posicion de ptrvec
											script_data->bypassPtrUint8Cbor(ptrvec + 8, extract8bytestoUint64(ptrvec));          // ex_units
											ptrvec += extract8bytestoUint64(ptrvec) + 8;
										}

									}

									if (rewardredeemer_data_count)
									{
										ptrvec = Withdrawal.getWithdrawalRedeemers().data();
										for (uint16_t t = 0; t < certredeemer_data_count; t++)
										{
											script_data->createArray(4);                                                           // [ , , , ]
											script_data->addUint(*(ptrvec + 2));                                               // tag
											script_data->addUint(extract2bytestoUint16(ptrvec));                                 // index
											script_data->bypassPtrUint8Cbor(ptrvec + 11, extract8bytestoUint64(ptrvec + 3));   // plutus_data
											ptrvec += extract8bytestoUint64(ptrvec + 3) + 11;                                    // cambio al posicion de ptrvec
											script_data->bypassPtrUint8Cbor(ptrvec + 8, extract8bytestoUint64(ptrvec));          // ex_units
											ptrvec += extract8bytestoUint64(ptrvec) + 8;
										}

									}


									std::vector<uint8_t> const& buff_getCbor = script_data->getCbor();  // se agrega la serializacion a la variable cbor_redeemers (se usa en witnnes)
									cbor_redeemers.assign(buff_getCbor.begin(), buff_getCbor.end());

									if (datum_data_count)
									{
										ptrvec = TransactionInput.getDatums().data();
										script_data->createArray(static_cast<uint64_t>(datum_data_count));                 //  [datums]
										for (uint16_t t = 0; t < datum_data_count; t++)
										{
											script_data->bypassPtrUint8Cbor(ptrvec + 10, extract8bytestoUint64(ptrvec + 2));
											ptrvec += extract8bytestoUint64(ptrvec + 2) + 10;

										}
									}

									cbor_datums.assign(buff_getCbor.begin() + cbor_redeemers.size(), buff_getCbor.end());   // se agrega la serializacion a la variable cbor_datums (se usa en witnnes)

									switch (TransactionInput.getGlobalReferencesScriptsType())
									{                                //  language views
										case ScriptType::Plutus_Script_V1: { script_data->bypassPtrUint8Cbor(V1language_views, 444); }; break;
										case ScriptType::Plutus_Script_V2: { script_data->bypassPtrUint8Cbor(V2language_views, 467); }; break;
										default: { throw std::invalid_argument("error in ScriptType: type not valid , for input references, set script with setGlobalReferencesStriptsType()"); }; break;
											/// poner un error en el default si no se selecciono un tipo
									}


								}; break;
							}

							std::vector<uint8_t> const& cbor_script_data = script_data->getCbor();
							uint8_t script_data_hash[32];

							/**
							std::cout <<"\n cbor_script_data: ";
							for (uint8_t i : cbor_script_data){
								std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(i);
							}
							std::cout <<std::endl;
							**/



							crypto_generichash_blake2b(script_data_hash, 32, cbor_script_data.data(), cbor_script_data.size(), nullptr, 0); //blake2b256(cbor_script_data)
							cbor.addIndexMap(11);                         /// 11:
							cbor.addBytesArray(script_data_hash, 32);      /// script_data_hash

						}; break;
						case 12: { }; break;
						case 13:
						{
							// 13: transacction_input ; collateral input
							// se agregara en case 0

						}; break;
						case 14: { }; break;
						case 15: { }; break;
						case 16:
						{
							// 16: transacction_output ; collateral return
							// se agregara en case 1
						}; break;
						case 17:
						{
							cbor.addIndexMap(17);                                 /// 17:
							cbor.addUint(totalcollateral);                        /// total collateral
						}; break;
						case 18:
						{
							// 18 : set<transaction_input> ; reference inputs;
							// Se agregara en case 0
						}; break;
					}
				}
			}
		}
		else
		{
			cbor.createArray(0);
		}
		return cbor.getCbor();
	}
	std::vector<uint8_t> const& TransactionBody::getcbor_afterBuild() const
	{
		return cbor.getCbor();
	}
	std::vector<uint8_t> const& TransactionBody::getcborDatums_afterBuild() const
	{
		return cbor_datums;
	}
	std::vector<uint8_t> const& TransactionBody::getcborRedeemers_afterBuild() const
	{
		return cbor_redeemers;
	}
	uint16_t const& TransactionBody::getWitnessMapcountbit() const
	{
		return witnessmapcountbit;
	}

	Transaction::Transaction()
	{
		if (sodium_init() < 0)
		{
			throw std::invalid_argument("Transaction error, could not start libsodium");
		}

		feefixed = PROTOCOL_FEE_FIXED;
		feeperbytes = PROTOCOL_FEE_PER_BYTE;

		bytesskyesInwitness = 0;
		witnessmapcountbit = 0;
		bytes_transaction = 0;
	}
	Transaction::~Transaction()
	{
		xskeys_ptr.clear();
	}
	Transaction::Transaction(uint64_t txfeefixed, uint64_t txfeeperbytes) : feefixed { txfeefixed }, feeperbytes { txfeeperbytes }
	{

		bytesskyesInwitness = 0;
		witnessmapcountbit = 0;
		bytes_transaction = 0;
	}
	Transaction& Transaction::addExtendedSigningKey(uint8_t const* const xsk)
	{
		if (xsk != nullptr)
		{
			xskeys_ptr.push_back(xsk);
		}

		witnessmapcountbit |= 0x0001;
		return *this;
	}
	Transaction& Transaction::addExtendedVerifyingKey(uint8_t const* const xvk, uint8_t const* const signature)
	{
		if (xvk != nullptr)
		{
			Witness.addVkeyWitness(xvk, signature);
		}

		return *this;
	}
	uint64_t Transaction::getFeeTransacion_PostBuild(uint64_t const number_of_signatures)
	{
		// Obtener Los datos por partes
		if (xskeys_ptr.size() == 0)
		{
			uint64_t bytes_key_sig = 3 + ((bytes_structure_cbornumber(32) + bytes_structure_cbornumber(64) + 32 + 64) * number_of_signatures);
			return ((bytes_transaction + bytes_key_sig + 9) * feeperbytes) + feefixed;
		}
		return ((bytes_transaction + 9) * feeperbytes) + feefixed;
	}
	std::vector<uint8_t> const& Transaction::build(std::vector<Digest>* signable_hashes32)
	{

		std::vector<uint8_t> const& auxiliary_data = Auxiliarydata.Build();
		// Primero se consulta los datos  de auxiliary data
		// y se agrega el auxiliarydatahash al transaccion body, si es que existe

		//std::size_t txFeeFixed = 155381;
		//std::size_t txFeePerByte = 44;

		if (Auxiliarydata.arethereAuxiliaryData())
		{
			uint8_t blake256_hash[32] = {};
			crypto_generichash_blake2b(blake256_hash, 32, auxiliary_data.data(), auxiliary_data.size(), nullptr, 0);
			Body.addAuxiliaryDataHash(blake256_hash);

		}

		std::vector<uint8_t> const& body = Body.Build();
		//Se recostruyen los datos Nuevamente

		uint16_t const& witness_build = Body.getWitnessMapcountbit();
		witnessmapcountbit |= witness_build;

		for (uint8_t x = 0; x < 7; x++)
		{ //se asignan los datos

			if ((witnessmapcountbit >> x) & 0x01)
			{  //revisa cada item del transaction witness
				switch (x)
				{
					case 0:
					{
						for (uint64_t v = 0; v < xskeys_ptr.size(); v++)
						{
							crypto_generichash_blake2b(blake256, 32, body.data(), body.size(), nullptr, 0);
							if (signable_hashes32 != nullptr)
							{
								Digest digest;
								memcpy(digest.Hash, blake256, sizeof(blake256));
								signable_hashes32->push_back(digest);
								memset(xvkeys, 0, sizeof(xvkeys));
								memset(body_signed, 0, sizeof(body_signed));
							}
							else
							{
								signature(xskeys_ptr[v], blake256, 32, body_signed);
								rawprivatekey_to_rawpublickey(xskeys_ptr[v], xvkeys);
								if (!verify(xvkeys, blake256, sizeof(blake256), body_signed))
									throw std::invalid_argument("failed to sign one of the inputs (invalid private key)");
							}
							Witness.addVkeyWitness(xvkeys, body_signed);
						}
					}; break;
					case 1:
					{
						Witness.addNativeScript(Body.TransactionInput.getNativeScripts());
					}; break;
					case 2: { }; break;
					case 3:
					{
						Witness.addPlutusV1Script(Body.TransactionInput.getPlutusV1Scripts());
					}; break;
					case 4:
					{
						Witness.addDatum(Body.getcborDatums_afterBuild());
					}; break;
					case 5:
					{
						Witness.addRedeemer(Body.getcborRedeemers_afterBuild());
					}; break;
					case 6:
					{
						Witness.addPlutusV2Script(Body.TransactionInput.getgetPlutusV2Scripts());
					}; break;
				}
			}
		}

		std::vector<uint8_t> const& witness = Witness.Build(); // se crea el witness
		/// en este paso se debera boorrar los datos VkeyWitness previos para crear los nuevos
		/// con los nuevos datos del txbody, AGREGAR UNA FUNCION A WITNESS PARA BORRAR LAS VkeyWitness



		///------------------Formando TRansaccion-------------

		// Se construye la transaccion con los datos obtenidos
		cborTransaction.clear(); // Borra todo antes de crear
		cborTransaction.push_back(0x84);                                                             /// [ , , , ]
		cborTransaction.insert(cborTransaction.end(), body.begin(), body.end());                       /// [transaction_body, , , ]
		cborTransaction.insert(cborTransaction.end(), witness.begin(), witness.end());                 /// [transaction_body, transaction_witness_set, , ]
		cborTransaction.push_back(0xf5);                                                             /// [transaction_body, transaction_witness_set, true, ]
		cborTransaction.insert(cborTransaction.end(), auxiliary_data.begin(), auxiliary_data.end());   /// [transaction_body, transaction_witness_set, true, auxiliary_data/null ]
		bytes_transaction = (uint32_t)cborTransaction.size();
		return cborTransaction;
	}

	unsigned int bytes_structure_cbornumber(uint64_t number) noexcept
	{
		if (number < 0x18)
		{//0...23
			return 1;
		}

		else if (number < 0x100)
		{ //24...255
			return 2;
		}

		else if (number < 0x10000)
		{//256...65535  (uint16)
			return 3;
		}

		else if (number < 0x100000000)
		{// 65536...4294967295 (uint32)
			return 5;
		}

		else if (number < UINT64_MAX)
		{ // 4294967296...18446744073709551615 (uint64)
			return 9;
		}

		return 0;
	}
	void addUint64toVector(std::vector <uint8_t>& bytesvector, uint64_t const& numero)
	{
		bytesvector.push_back((numero >> 56) & 0xff);
		bytesvector.push_back((numero >> 48) & 0xff);
		bytesvector.push_back((numero >> 40) & 0xff);
		bytesvector.push_back((numero >> 32) & 0xff);
		bytesvector.push_back((numero >> 24) & 0xff);
		bytesvector.push_back((numero >> 16) & 0xff);
		bytesvector.push_back((numero >> 8) & 0xff);
		bytesvector.push_back((numero) & 0xff);
	}
	void addUint16toVector(std::vector <uint8_t>& bytesvector, uint16_t const& numero)
	{
		bytesvector.push_back((numero >> 8) & 0xff);
		bytesvector.push_back((numero) & 0xff);
	}
	void addUint16toVector(std::vector <uint8_t>*& bytesvector, uint16_t*& numero)
	{
		bytesvector->push_back((*numero >> 8) & 0xff);
		bytesvector->push_back((*numero) & 0xff);
	}
	void replaceUint16toVector(uint8_t* bytesvector, uint16_t const& numero) noexcept
	{
		*bytesvector = ((numero >> 8) & 0xff);
		*(bytesvector + 1) = ((numero) & 0xff);
	}
	uint64_t extract8bytestoUint64(uint8_t const* const array8bytes) noexcept
	{

		return ((static_cast<uint64_t>(*array8bytes) << 56) | (static_cast<uint64_t>(*(array8bytes + 1)) << 48) | (static_cast<uint64_t>(*(array8bytes + 2)) << 40) | (static_cast<uint64_t>(*(array8bytes + 3)) << 32) | (static_cast<uint64_t>(*(array8bytes + 4)) << 24) | (static_cast<uint64_t>(*(array8bytes + 5)) << 16) | (static_cast<uint64_t>(*(array8bytes + 6)) << 8) | (static_cast<uint64_t>(*(array8bytes + 7))));

	}
	uint16_t extract2bytestoUint16(uint8_t  const* const array2bytes) noexcept
	{

		return ((static_cast<uint16_t>(*(array2bytes)) << 8) | (static_cast<uint16_t>(*(array2bytes + 1))));

	}
	bool existen_coincidencias(uint8_t const* data1, uint8_t const* data2, uint16_t const data_len, uint16_t const ciclos, uint16_t const salto) noexcept
	{
		uint16_t buff_sizet = 0;
		for (int e = 0; e < ciclos; e++)
		{
			data2 = data2 + salto * e;
			buff_sizet = 0;
			for (int u = 0; u < data_len; u++)
			{
				if (data1[u] == data2[u])
				{
					buff_sizet++;
				}
			}
			if (buff_sizet == data_len)
			{
				return true;
			}
		}

		return false;
	}
	bool existen_coincidencias_output(uint8_t const* data, uint8_t const* output, uint16_t const data_len, uint16_t const ciclos, uint16_t const salto) noexcept
	{
		uint16_t buff_sizet = 0;
		uint16_t addr_keyhash_buffer_len = 0;
		for (int e = 0; e < ciclos; e++)
		{

			output = output + addr_keyhash_buffer_len;
			buff_sizet = 0;
			for (int u = 0; u < data_len; u++)
			{
				if (data[u] == output[u + 1])
				{
					buff_sizet++;
				}
			}
			if (buff_sizet == data_len)
			{
				return true;
			}
			addr_keyhash_buffer_len = output[0] + salto;
		}

		return false;
	}
	static bool is_only_hex(std::string const& string_hex)
	{
		for (char c : string_hex)
		{
			switch (c)
			{
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
				case 'a':
				case 'b':
				case 'c':
				case 'd':
				case 'e':
				case 'f':
				case 'A':
				case 'B':
				case 'C':
				case 'D':
				case 'E':
				case 'F': { }; break;
				default: { return false; }; break;
			}
		}
		return true;
	}
	uint8_t* hexchararray2uint8array(std::string const& string_hex, std::size_t* const hexchararray2uint8array_len) noexcept
	{
		//se crea una memoria dinamica para un nuevo array char_hexa[]

		if (is_only_hex(string_hex))
		{

			std::size_t array_hex_len = static_cast<std::size_t>(string_hex.size() / 2);
			if (hexchararray2uint8array_len != nullptr)
			{
				*hexchararray2uint8array_len = array_hex_len;
			}
			uint8_t* array_hex = new (std::nothrow) uint8_t[array_hex_len]();
			if (array_hex != nullptr)
			{
				for (std::size_t ha = 0; ha < array_hex_len; ha++)
				{
					array_hex[ha] = static_cast<uint8_t>(std::stoul(string_hex.substr(ha * 2, 2), nullptr, 16));
				}
			}
			return array_hex;

		}

		return nullptr;
	};

	///concat_data= data1 || data2 || add_bytes
	static uint8_t* concat_data(uint8_t const* const data1, uint16_t const* const data1_len, uint8_t const* const data2, uint16_t const* const data2_len, uint16_t const add_bytes, uint16_t* const data_out_len) noexcept
	{
		*data_out_len = (*data2_len) + (*data1_len) + add_bytes;  // se espera que el valor no supere los 65535 bytes de largo
		uint8_t* data_out = new (std::nothrow) uint8_t[*data_out_len]();
		//uint8_t *data_out = static_cast<uint8_t*>(std::calloc(*data_out_len, sizeof(uint8_t)));
		if (data_out != nullptr)
		{
			for (uint16_t i = 0; i < (*data_out_len); i++)
			{
				if (i < (*data1_len))
				{
					data_out[i] = data1[i];
				}
				else
				{
					data_out[i] = data2[i - (*data1_len)];
				}
			}
		}
		return data_out;
	}
	/// Encode
	static uint8_t* convert_bits(uint8_t const* const data, uint16_t const* const data_len, uint16_t const fromBits, uint16_t const toBits, uint16_t* const convert_bits_len) noexcept
	{
		uint16_t acc = 0;
		uint16_t bits = 0;
		uint16_t maxv = (1 << toBits) - 1;
		uint16_t maxacc = (1 << (fromBits + toBits - 1)) - 1;
		uint16_t cv_bits_len = (*data_len) * 2;
		uint8_t* cv_bits = new (std::nothrow) uint8_t[cv_bits_len]();
		//uint8_t *cv_bits = static_cast<uint8_t*>(std::calloc(cv_bits_len, sizeof(uint8_t)));
		if (cv_bits != nullptr)
		{
			*convert_bits_len = 0;

			for (uint16_t i = 0; i < *data_len; i++)
			{
				if ((data[i] >> fromBits) > 0)
				{
					*convert_bits_len = 0;
					sodium_memzero(cv_bits, cv_bits_len);
					delete[] cv_bits;
					//std::free(cv_bits);
					return nullptr;
				}
				acc = ((acc << fromBits) | data[i]) & maxacc;
				bits += fromBits;
				while (bits >= toBits)
				{
					bits -= toBits;
					cv_bits[*convert_bits_len] = static_cast<uint8_t>((acc >> bits) & maxv);
					*convert_bits_len += 1;
				}
			}
			if (bits > 0)
			{
				cv_bits[*convert_bits_len] = static_cast<uint8_t>((acc << (toBits - bits)) & maxv);
				*convert_bits_len += 1;
			}
		}
		return cv_bits;

	}
	///Decode cardano addr
	static bool decode_bits(uint8_t const* const data, uint16_t const data_len, uint16_t const fromBits, uint16_t const toBits, uint8_t* const bits_out, uint16_t* const bits_out_len, uint16_t max_size) noexcept
	{
		uint16_t blen = 0;
		uint16_t acc = 0;
		uint16_t bits = 0;
		uint16_t maxv = (1 << toBits) - 1;
		uint16_t maxacc = (1 << (fromBits + toBits - 1)) - 1;

		if (bits_out_len != nullptr)
		{
			if (max_size < *bits_out_len - 1)
				max_size = *bits_out_len - 1;
			*bits_out_len = 0;
		}
		for (uint16_t i = 0; i < data_len; i++)
		{
			if ((data[i] >> fromBits) > 0)
			{
				return false;
			}
			acc = ((acc << fromBits) | data[i]) & maxacc;
			bits += fromBits;
			while (bits >= toBits)
			{
				if (blen <= max_size)
				{ //si esta fuera del rango de la llave mas larga (hashkey) genera un false
					bits -= toBits;
					bits_out[blen] = static_cast<uint8_t>((acc >> bits) & maxv);
					blen += 1;
				}
				else
				{
					return false;
				}
			}
		}
		if (bits >= fromBits || static_cast<uint8_t>((acc << (toBits - bits)) & maxv) != 0 || blen < 28) //si blen es menor a la llave mas corta (hashkey) genera un false
		{
			return false;
		}
		if (bits_out_len != nullptr)
		{
			*bits_out_len = blen;
		}

		return true;
	}
	static bool IsValidHrp(char const* const hrp, uint8_t* const hrp_len) noexcept
	{
		*hrp_len = 0;
		//comprueba si el largo de la cadena esta entre 1 a 83
		while (hrp[*hrp_len] != '\0')
		{
			*hrp_len += 1;
			if (*hrp_len > 83)
			{ // no debe pasarse de los 83 bytes
				return false;
			}
		}
		if (*hrp_len < 1)
		{
			return false;
		}

		//comprueba si el valor de cada byte esta en el rango de 33 a 126
		for (uint8_t a = 0; a < *hrp_len; a++)
		{
			if (static_cast<int>(hrp[a]) < 33 || static_cast<int>(hrp[a]) > 126)
			{
				return false;
			}
		}
		return true;
	}
	static bool IsValidStringBench32(char const* const bech32_code, uint16_t* const bech32_code_pos_separator, uint16_t* const bech32_code_lenght) noexcept
	{
		bool lower = false;
		bool upper = false;
		uint8_t c = 0;
		uint16_t len = 0;
		uint16_t pos = 0;

		while (bech32_code[len] != '\0')
		{
			if (bech32_code[len] == SEPARATOR_BECH32)
			{ // siempre detecta el ultimo separador ('1')
				pos = len;
			}
			len++;
			if (len > 65533)
			{  // evita el desbordamiento de memoria para len y pos
				return false;
			}
		}

		*bech32_code_pos_separator = pos;
		*bech32_code_lenght = len;

		for (uint16_t i = 0; i < len; ++i)
		{
			c = static_cast<uint8_t>(bech32_code[i]);
			if (c >= 'a' && c <= 'z') { lower = true; }
			else if (c >= 'A' && c <= 'Z') { upper = true; }
			else if (c < 33 || c > 126) { return false; }  //no es valido si contiene otros caracteres
		}
		if (lower && upper) { return false; }  //solo es valido si solo posee letras mayusculas o minusculas no ambas

		if (pos == len || pos == 0 || pos + 7 > len || (len - pos) < 6)
		{
			return false;
		}
		return true;
	}
	static void bech32_polymod(uint8_t const* const data, uint16_t const* const data_len, uint32_t* const polymod_out) noexcept
	{
		uint8_t b = 0;
		*polymod_out = 1;
		for (uint16_t i = 0; i < *data_len; i++)
		{
			b = *polymod_out >> 25;
			*polymod_out = ((*polymod_out & 0x1ffffff) << 5) ^ static_cast<uint32_t>(data[i]);

			if (b & 1) { *polymod_out ^= 0x3b6a57b2; };
			if (b & 2) { *polymod_out ^= 0x26508e6d; };
			if (b & 4) { *polymod_out ^= 0x1ea119fa; };
			if (b & 8) { *polymod_out ^= 0x3d4233dd; };
			if (b & 16) { *polymod_out ^= 0x2a1462b3; };
		}
	}
	static uint8_t* bech32_hrp_expand(char const* const hrp, uint8_t const* const hrp_len, uint16_t* const bech32_hrp_expand_len) noexcept
	{

		uint16_t len = ((*hrp_len) * 2) + 1;
		*bech32_hrp_expand_len = len;

		uint8_t* hrp_e = new (std::nothrow) uint8_t[len]();
		//uint8_t *hrp_e = static_cast<uint8_t*>(std::calloc(len, sizeof(uint8_t)));
		if (hrp_e != nullptr)
		{
			for (uint16_t i = 0; i < *hrp_len; ++i)
			{
				hrp_e[i] = static_cast<uint8_t>(hrp[i]) >> 5;
				hrp_e[i + *hrp_len + 1] = static_cast<uint8_t>(hrp[i]) & 0x1f;
			}
		}

		return hrp_e;
	}
	static bool bech32_verify_checksum(char const* const hrp, uint8_t const* const hrp_len, uint8_t const* const data, uint16_t const data_len) noexcept
	{
		uint16_t hrp_expand_len;
		uint16_t v_len = 0;
		uint32_t pmod;

		uint8_t* const hrp_expand = bech32_hrp_expand(hrp, hrp_len, &hrp_expand_len);
		if (hrp_expand == nullptr)
		{
			return false;
		}
		uint8_t* const v = concat_data(hrp_expand, &hrp_expand_len, data, &data_len, 0, &v_len);
		if (v == nullptr)
		{
			delete[] hrp_expand;
			//std::free(hrp_expand);
			return false;
		}

		bech32_polymod(v, &v_len, &pmod);

		//se borra v[] y hrp_expand[]
		sodium_memzero(v, v_len);
		delete[] hrp_expand;
		delete[] v;
		//std::free(hrp_expand);
		//std::free(v);

		if (pmod == 1)
		{
			return true;
		}
		return false;

	}
	static bool bech32_create_checksum(char const* const hrp, uint8_t const* const hrp_len, uint8_t const* const data, uint16_t const* const data_len, uint8_t* const checksum) noexcept
	{
		uint16_t hrp_expand_len;
		uint16_t v_len = 0;
		//uint16_t enc_len = 0;
		uint32_t polymod;

		uint8_t* const hrp_expand = bech32_hrp_expand(hrp, hrp_len, &hrp_expand_len);
		if (hrp_expand == nullptr)
		{
			return false;
		}
		uint8_t* const v = concat_data(hrp_expand, &hrp_expand_len, data, data_len, 6, &v_len); //se agregan 6 bytes adicionales al array para el calculo del checksum en bech32_polymod
		if (v == nullptr)
		{
			delete[] hrp_expand;
			//std::free(hrp_expand);
			return false;
		}

		bech32_polymod(v, &v_len, &polymod);
		polymod = polymod ^ 1;
		for (uint8_t i = 0; i < 6; i++)
		{
			checksum[i] = (polymod >> (5 * (5 - i))) & 0x1f;
		}

		//borrar hrp_expand[] y v[]
		sodium_memzero(v, v_len);
		delete[] hrp_expand;
		delete[] v;
		//std::free(hrp_expand);
		//std::free(v);

		return true;
	}
	bool bech32_encode(char const* const hrp, uint8_t const* const data, uint16_t const data_len, std::string& encode_out) noexcept
	{

		encode_out.clear();

		uint8_t hrp_len = 0;
		uint16_t c_bit_len = 0;
		uint16_t cdata_len = 0;
		const uint16_t chk_len = 6;
		uint8_t chk[chk_len];

		if (!IsValidHrp(hrp, &hrp_len))
		{
			return false;
		}

		uint8_t* const c_bit = convert_bits(data, &data_len, 8, 5, &c_bit_len);
		if (c_bit == nullptr)
		{
			return false;
		}

		if (!bech32_create_checksum(hrp, &hrp_len, c_bit, &c_bit_len, chk))
		{
			sodium_memzero(c_bit, c_bit_len);
			delete[] c_bit;
			//std::free(c_bit);
			return false;
		}

		uint8_t* const cdata = concat_data(c_bit, &c_bit_len, chk, &chk_len, 0, &cdata_len);
		if (cdata == nullptr)
		{
			sodium_memzero(c_bit, c_bit_len);
			delete[] c_bit;
			//std::free(c_bit);
			return false;
		}


		encode_out += hrp; //hrp
		encode_out += SEPARATOR_BECH32; //hrp + separador
		encode_out.reserve(encode_out.length() + cdata_len);

		for (uint16_t i = 0; i < cdata_len; i++)
		{
			encode_out += B32Chars_encode[cdata[i]]; //hrp + separador + data
		}

		//Borrar cdata c_bit
		sodium_memzero(c_bit, c_bit_len);
		sodium_memzero(cdata, cdata_len);
		delete[] cdata;
		delete[] c_bit;
		//std::free(cdata);
		//std::free(c_bit);

		return true;
	}
	bool bech32_decode(char const* const bech32_code, uint8_t* const data_out, uint16_t* const data_out_len) noexcept
	{
		uint16_t bech32_code_lenght = 0;
		uint16_t pos_separator = 0;
		uint8_t hrp_len = 0;

		if (!IsValidStringBench32(bech32_code, &pos_separator, &bech32_code_lenght))
		{
			return false;
		}

		char hrp[16];
		std::strncpy(hrp, bech32_code, pos_separator);
		hrp[pos_separator] = '\0';

		if (!IsValidHrp(hrp, &hrp_len))
		{
			return false;
		}

		uint16_t c_bit_len = bech32_code_lenght - (pos_separator + 1);
		uint8_t c_bit[2048];
		sodium_memzero(c_bit, c_bit_len);

		for (uint16_t i = 0; i < c_bit_len; i++)
		{
			c_bit[i] = B32Chars_decode[static_cast<uint8_t>(bech32_code[(pos_separator + 1) + i])];
		}

		if (!bech32_verify_checksum(hrp, &hrp_len, c_bit, c_bit_len))
		{
			sodium_memzero(c_bit, c_bit_len);
			return false;
		}

		if (!decode_bits(c_bit, (c_bit_len - 6), 5, 8, data_out, data_out_len, 57))
		{
			sodium_memzero(c_bit, c_bit_len);
			return false;
		}

		sodium_memzero(c_bit, c_bit_len);
		return true;

	}
	bool bech32_decode_extended(char const* const bech32_code, uint8_t* const data_out, uint16_t* const data_out_len, uint16_t max_size) noexcept
	{
		uint16_t bech32_code_lenght = 0;
		uint16_t pos_separator = 0;
		uint8_t hrp_len = 0;

		if (!IsValidStringBench32(bech32_code, &pos_separator, &bech32_code_lenght))
		{
			return false;
		}

		char hrp[16];
		std::strncpy(hrp, bech32_code, pos_separator);
		hrp[pos_separator] = '\0';

		if (!IsValidHrp(hrp, &hrp_len))
		{
			return false;
		}

		uint16_t c_bit_len = bech32_code_lenght - (pos_separator + 1);
		uint8_t c_bit[2048];
		sodium_memzero(c_bit, c_bit_len);

		for (uint16_t i = 0; i < c_bit_len; i++)
		{
			c_bit[i] = B32Chars_decode[static_cast<uint8_t>(bech32_code[(pos_separator + 1) + i])];
		}

		if (!bech32_verify_checksum(hrp, &hrp_len, c_bit, c_bit_len))
		{
			sodium_memzero(c_bit, c_bit_len);
			return false;
		}

		if (!decode_bits(c_bit, (c_bit_len - 6), 5, 8, data_out, data_out_len, max_size))
		{
			sodium_memzero(c_bit, c_bit_len);
			return false;
		}

		sodium_memzero(c_bit, c_bit_len);
		return true;

	}

	static bool from_masterkey(uint8_t const* const extended_master_secret_key, Wallet const* const wallet_type, OutputKey const* const output_key_type, Role const* const role_path, uint32_t const* const index_acc, int* const keysize, uint32_t const* const address_index_path, uint8_t* const buff_xsk) noexcept
	{

		switch (*wallet_type)
		{
			case Wallet::HD:
			{
				if (!raw_child_privatekey(extended_master_secret_key, H1852, buff_xsk))
				{  /// m/1852'
					return false;
				}
			}; break;
			case Wallet::MultiSignHD:
			{
				if (!raw_child_privatekey(extended_master_secret_key, H1854, buff_xsk))
				{  /// m/1854'
					return false;
				}
			}; break;
			default:
			{
				return false;
			}; break;
		}

		if (!raw_child_privatekey(buff_xsk, H1815, buff_xsk))
		{                        /// m/1852'/1815'
			return false;
		}

		if (!raw_child_privatekey(buff_xsk, *index_acc, buff_xsk))
		{                   /// m/1852'/1815'/account'
			return false;
		}

		switch (*output_key_type)
		{

			case OutputKey::Private:
			{
				*keysize = XSK_LENGTH;
				if (*role_path != Role::OnlyAccount)
				{

					switch (*wallet_type)
					{

						case Wallet::HD:
						{
							if (!raw_child_privatekey(buff_xsk, static_cast<uint32_t>(*role_path), buff_xsk))
							{      /// m/1852'/1815'/account'/role_path
								return false;
							}
						}; break;

						case Wallet::MultiSignHD:
						{
							if (*role_path != Role::Intern)
							{
								if (!raw_child_privatekey(buff_xsk, static_cast<uint32_t>(*role_path), buff_xsk))
								{  /// m/1852'/1815'/account'/role_path
									return false;
								}
							}
							else
							{
								return false;
							}
						}; break;

					}

					if (*address_index_path < 2147483648U)
					{

						if (!raw_child_privatekey(buff_xsk, *address_index_path, buff_xsk))
						{                         /// m/1852'/1815'/account'/role_path/address
							return false;
						}
						if (!valid_ed25519_sk(buff_xsk))
						{
							return false;
						}

					}
					else
					{
						return false;
					}
				}

			}; break;

			case OutputKey::Public:
			{
				*keysize = XVK_LENGTH;
				if (!rawprivatekey_to_rawpublickey(buff_xsk, buff_xsk))
				{
					return false;
				}

				if (*role_path != Role::OnlyAccount)
				{

					switch (*wallet_type)
					{

						case Wallet::HD:
						{
							if (!raw_child_publickey(buff_xsk, static_cast<uint32_t>(*role_path), buff_xsk))
							{       /// m/1852'/1815'/account'/role_path
								return false;
							}
						}; break;

						case Wallet::MultiSignHD:
						{
							if (*role_path != Role::Intern)
							{
								if (!raw_child_publickey(buff_xsk, static_cast<uint32_t>(*role_path), buff_xsk))
								{   /// m/1852'/1815'/account'/role_path
									return false;
								}
							}
							else
							{
								return false;
							}
						}; break;

					}

					if (*address_index_path < 2147483648U)
					{

						if (!raw_child_publickey(buff_xsk, *address_index_path, buff_xsk))
						{                          /// m/1852'/1815'/account'/role_path/address
							return false;
						}

					}
					else
					{
						return false;
					}
				}
			}; break;

			default:
			{
				return false;
			}; break;

		}

		return true;
	}
	static bool from_accountkey(uint8_t const* const account_key, InputKey const* const account_key_type, Wallet const* const wallet_type, OutputKey const* const output_key_type, Role const* const role_path, int* const keysize, uint32_t const* const address_index_path, uint8_t* const buff_xsk) noexcept
	{

		switch (*output_key_type)
		{

			case OutputKey::Private:
			{
				if (*account_key_type == InputKey::AccountKey_xsk)
				{
					*keysize = XSK_LENGTH;
					if (*role_path != Role::OnlyAccount)
					{

						switch (*wallet_type)
						{

							case Wallet::HD:
							{
								if (!raw_child_privatekey(account_key, static_cast<uint32_t>(*role_path), buff_xsk))
								{  /// m/1852'/1815'/account'/role_path
									return false;
								}
							}; break;

							case Wallet::MultiSignHD:
							{
								if (*role_path != Role::Intern)
								{
									if (!raw_child_privatekey(account_key, static_cast<uint32_t>(*role_path), buff_xsk))
									{  /// m/1852'/1815'/account'/role_path
										return false;
									}
								}
								else
								{
									return false;
								}
							}; break;

						}

						if (*address_index_path < 2147483648U)
						{

							if (!raw_child_privatekey(buff_xsk, *address_index_path, buff_xsk))
							{                     /// m/1852'/1815'/account'/role_path/address
								return false;
							}
							if (!valid_ed25519_sk(buff_xsk))
							{
								return false;
							}

						}
						else
						{
							return false;
						}
					}
					else
					{
						return false;
					}
				}
				else
				{
					return false;
				}
			}; break;

			case OutputKey::Public:
			{
				*keysize = XVK_LENGTH;

				if (*account_key_type == InputKey::AccountKey_xsk)
				{
					if (!rawprivatekey_to_rawpublickey(account_key, buff_xsk))
					{
						return false;
					}
				}
				else
				{
					std::memcpy(buff_xsk, account_key, XVK_LENGTH);
				}

				if (*role_path != Role::OnlyAccount)
				{

					switch (*wallet_type)
					{

						case Wallet::HD:
						{
							if (!raw_child_publickey(buff_xsk, static_cast<uint32_t>(*role_path), buff_xsk))
							{  /// m/1852'/1815'/account'/role_path
								return false;
							}
						}; break;

						case Wallet::MultiSignHD:
						{
							if (*role_path != Role::Intern)
							{
								if (!raw_child_publickey(buff_xsk, static_cast<uint32_t>(*role_path), buff_xsk))
								{  /// m/1852'/1815'/account'/role_path
									return false;
								}
							}
							else
							{
								return false;
							}
						}; break;

					}

					if (*address_index_path < 2147483648U)
					{

						if (!raw_child_publickey(buff_xsk, *address_index_path, buff_xsk))
						{                  /// m/1852'/1815'/account'/role_path/address
							return false;
						}

					}
					else
					{
						return false;
					}
				}
				else
				{
					return false;
				}
			}; break;

			default:
			{
				return false;
			}; break;

		}

		return true;
	}
	bool getRawKey(InputKey input_key_type, uint8_t const* const input_key, Wallet wallet_type, OutputKey output_key_type, uint32_t const account_path, Role role_path, uint32_t const address_index_path, uint8_t* const output_key) noexcept
	{

		sodium_memzero(output_key, XVK_LENGTH); //se deja a cero los primeros 64 bytes, asi en caso de un error su sk o xvk seran cero

		int keysize = 0;
		uint32_t index_acc = 0;
		uint8_t buff_xsk[XSK_LENGTH];  //Se crea un buffer que pueda contener los dos tipos de llaves

		//------ Derivacion----

		switch (input_key_type)
		{
			case InputKey::MasterKey:
			{
				if (account_path > 2147483647U)
				{ // y si no excede el limite maximo ((2^32) - 1) - 2^31 = (2^31) - 1 = 2147483647
					return false;
				}
				index_acc = account_path + H0;
				if (!from_masterkey(input_key, &wallet_type, &output_key_type, &role_path,
					&index_acc, &keysize, &address_index_path, buff_xsk))
				{
					sodium_memzero(buff_xsk, XSK_LENGTH);
					return false;
				}
			}; break;
			default:
			{
				if (!from_accountkey(input_key, &input_key_type, &wallet_type, &output_key_type, &role_path,
					&keysize, &address_index_path, buff_xsk))
				{
					sodium_memzero(buff_xsk, XSK_LENGTH);
					return false;
				}
			}; break;
		}

		//----------------

		for (uint8_t i = 0; i < keysize; i++)
		{
			output_key[i] = buff_xsk[i];
		}
		sodium_memzero(buff_xsk, XSK_LENGTH);

		return true;
	}
	//for generate only account
	bool getRawKey(InputKey input_key_type, uint8_t const* const input_key, Wallet wallet_type, OutputKey output_key_type, uint32_t const account_path, Role role_path, uint8_t* const output_key) noexcept
	{

		sodium_memzero(output_key, XVK_LENGTH); //se deja a cero los primeros 64 bytes, asi en caso de un error su sk o xvk seran cero

		int keysize = 0;
		uint32_t index_acc = 0;
		uint32_t address_index_path = 0;
		uint8_t buff_xsk[XSK_LENGTH];  //Se crea un buffer que pueda contener los dos tipos de llaves

		//------ Derivacion----
		if (role_path == Role::OnlyAccount)
		{
			if (input_key_type == InputKey::MasterKey)
			{
				if (account_path > 2147483647U)
				{ // y si no excede el limite maximo ((2^32) - 1) - 2^31 = (2^31) - 1 = 2147483647
					return false;
				}
				index_acc = account_path + H0;
				if (from_masterkey(input_key, &wallet_type, &output_key_type, &role_path,
					&index_acc, &keysize, &address_index_path, buff_xsk))
				{

					for (uint8_t i = 0; i < keysize; i++)
					{
						output_key[i] = buff_xsk[i];
					}
					sodium_memzero(buff_xsk, XSK_LENGTH);

				}
				else
				{
					sodium_memzero(buff_xsk, XSK_LENGTH);
					return false;
				}
			}
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}
		//----------------

		for (uint8_t i = 0; i < keysize; i++)
		{
			output_key[i] = buff_xsk[i];
		}
		sodium_memzero(buff_xsk, XSK_LENGTH);

		return true;
	}
	bool getBech32key(InputKey input_key_type, uint8_t const* const input_key, Wallet wallet_type, OutputKey output_key_type, uint32_t const account_path, Role role_path, uint32_t const address_index_path, std::string& bech32_output_key) noexcept
	{

		bech32_output_key.clear(); //se vacia el string

		int keysize = 0;
		uint32_t index_acc = 0;
		char hrp[17]; //soporta el prefijo mas largo
		uint8_t buff_xsk[XSK_LENGTH];  //Se crea un buffer que pueda contener los dos tipos de llaves

		//------ Derivacion----

		switch (input_key_type)
		{
			case InputKey::MasterKey:
			{
				if (account_path > 2147483647U)
				{ // y si no excede el limite maximo ((2^32) - 1) - 2^31 = (2^31) - 1 = 2147483647
					return false;
				}
				index_acc = account_path + H0;
				if (!from_masterkey(input_key, &wallet_type, &output_key_type, &role_path,
					&index_acc, &keysize, &address_index_path, buff_xsk))
				{
					sodium_memzero(buff_xsk, XSK_LENGTH);
					return false;
				}
			}; break;
			default:
			{
				if (!from_accountkey(input_key, &input_key_type, &wallet_type, &output_key_type, &role_path,
					&keysize, &address_index_path, buff_xsk))
				{
					sodium_memzero(buff_xsk, XSK_LENGTH);
					return false;
				}
			}; break;
		}

		//------- Hrp ------
		if (role_path != Role::OnlyAccount)
		{
			if (role_path != Role::Staking)
			{
				std::strcpy(hrp, "addr");   ///prefix
			}
			else
			{
				std::strcpy(hrp, "stake");  ///prefix
			}
		}
		else
		{
			std::strcpy(hrp, "acct");       ///prefix
		}
		if (wallet_type == Wallet::MultiSignHD)
		{
			std::strcat(hrp, "_shared");    ///prefix
		}
		if (keysize == XVK_LENGTH)
		{
			std::strcat(hrp, "_xvk");       ///prefix

		}
		else
		{
			std::strcat(hrp, "_xsk");       ///prefix
		}
		//---------------

		bech32_encode(hrp, buff_xsk, keysize, bech32_output_key);
		sodium_memzero(buff_xsk, XSK_LENGTH);

		return true;
	}
	//for generate only account
	bool getBech32key(InputKey input_key_type, uint8_t const* const input_key, Wallet wallet_type, OutputKey output_key_type, uint32_t const account_path, Role role_path, std::string& bech32_output_key) noexcept
	{

		bech32_output_key.clear(); //se deja en cero el string

		int keysize = 0;
		uint32_t index_acc = 0;
		uint32_t address_index_path = 0;
		char hrp[17]; //soporta el prefijo mas largo
		uint8_t buff_xsk[XSK_LENGTH];  //Se crea un buffer que pueda contener los dos tipos de llaves

		//------ Derivacion----

		if (role_path == Role::OnlyAccount)
		{
			if (input_key_type == InputKey::MasterKey)
			{
				if (account_path > 2147483647U)
				{ // y si no excede el limite maximo ((2^32) - 1) - 2^31 = (2^31) - 1 = 2147483647
					return false;
				}
				index_acc = account_path + H0;
				if (!from_masterkey(input_key, &wallet_type, &output_key_type, &role_path,
					&index_acc, &keysize, &address_index_path, buff_xsk))
				{
					sodium_memzero(buff_xsk, XSK_LENGTH);
					return false;
				}
			}
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}

		//------- Hrp ------
		std::strcpy(hrp, "acct");             ///prefix

		if (wallet_type == Wallet::MultiSignHD)
		{
			std::strcat(hrp, "_shared");      ///prefix
		}
		if (keysize == XVK_LENGTH)
		{
			std::strcat(hrp, "_xvk");         ///prefix

		}
		else
		{
			std::strcat(hrp, "_xsk");         ///prefix
		}
		//---------------

		bech32_encode(hrp, buff_xsk, keysize, bech32_output_key);
		sodium_memzero(buff_xsk, XSK_LENGTH);

		return true;
	}

	static void hmac512_sodium(uint8_t const* const key, std::size_t const key_len, uint8_t const* const data, std::size_t const data_len, uint8_t* const out) noexcept //out[64]
	{
		crypto_auth_hmacsha512_state hctx;
		crypto_auth_hmacsha512_init(&hctx, key, key_len);
		crypto_auth_hmacsha512_update(&hctx, data, data_len);
		crypto_auth_hmacsha512_final(&hctx, out);
	};
	static inline void normalize_bytes_icarusmethod(uint8_t* const kl) noexcept
	{
		kl[0] &= 0xf8;  //0b1111_1000;
		kl[31] &= 0x1f; //0b0001_1111;
		kl[31] |= 0x40; //0b0100_0000;

	}
	///store32 litleendian
	static inline void store32_le(uint32_t const index, uint8_t* const out) noexcept
	{
		out[0] = static_cast<uint8_t>(index);
		out[1] = static_cast<uint8_t>(index >> 8);
		out[2] = static_cast<uint8_t>(index >> 16);
		out[3] = static_cast<uint8_t>(index >> 24);
	}
	/// kl_out = kparentl + 8 * trunc28(zl)
	static void add_28_mul8(uint8_t const* const kparentl, uint8_t const* const zl, uint8_t* const kl_out) noexcept
	{

		uint16_t carry = 0;
		uint16_t entero = 0;

		for (uint8_t i = 0; i < 28; i++)
		{
			entero = static_cast<uint16_t>(kparentl[i]) + (static_cast<uint16_t>(zl[i]) << 3) + carry;
			kl_out[i] = static_cast<uint8_t>(entero & 0xff);
			carry = entero >> 8;
		}
		for (uint8_t i = 28; i < 32; i++)
		{
			entero = static_cast<uint16_t>(kparentl[i]) + carry;
			kl_out[i] = static_cast<uint8_t>(entero & 0xff);
			carry = entero >> 8;
		}
	}
	/// kr_out = zr + kparentr
	static void add_256bits(uint8_t const* const kparentr, uint8_t const* const zr, uint8_t* const kr_out) noexcept
	{
		uint16_t carry = 0;
		uint16_t entero = 0;

		for (uint8_t i = 0; i < 32; i++)
		{
			entero = static_cast<uint16_t>(kparentr[i]) + static_cast<uint16_t>(zr[i]) + carry;
			kr_out[i] = static_cast<uint8_t>(entero & 0xff);
			carry = entero >> 8;
		}
	}
	/// ai_out = aparent + (8*trunc28(zl))*B
	static bool point_plus(uint8_t const* const aparent, uint8_t* const zl, uint8_t* const ai_out) noexcept
	{
		uint8_t cero[32] { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
		uint8_t zl_8[32];
		uint8_t azl_8[32];

		//8 * trunc28(zl) -> zl_8
		add_28_mul8(cero, zl, zl_8);
		sodium_memzero(zl, 64);

		//zl_8(private key) ; verifica su ultimo byte
		if (zl_8[31] > 127)
		{
			return false;
		}

		//azl_8 = zl_8 * B
		if (crypto_scalarmult_ed25519_base_noclamp(azl_8, zl_8) != 0)
		{
			return false;
		}

		//ai_out = aparent + azl_8
		if (crypto_core_ed25519_add(ai_out, azl_8, aparent) != 0)
		{
			return false;
		}

		if (crypto_core_ed25519_is_valid_point(ai_out) == 0)
		{
			return false;
		}

		return true;
	}
	bool valid_ed25519_sk(uint8_t const* const raw_privatekey_sk) noexcept
	{ //si en a[0] sus tres bit mas bajos no son cero y a[31] su bit mas alto no es cero entonces la llave no es valida

		if (raw_privatekey_sk[31] <= 127 && ((raw_privatekey_sk[0] & 0x07) == 0x00))
		{
			return true;
		}

		return false;
	}
	/// root_privatekey/extended_mastersecretkey[96] = pbkdf2_hmac512(entropy)
	bool getRawMasterKey(uint8_t const* const entropy, std::size_t entropy_len, uint8_t const* const password, std::size_t password_len, uint8_t* const mastersecretkey_out) noexcept
	{
		if (entropy != nullptr)
		{
			if (pbkdf2_hmac512_libsodium(password, password_len, entropy, entropy_len, 4096, MASTERSECRETKEY_LENGTH, mastersecretkey_out))
			{
				normalize_bytes_icarusmethod(mastersecretkey_out); // se establecen los bits segun la norma icarus
				return true;
			}
		}
		return false;
	}
	/// (A/extended_publickey)[64] = kl[32] * B || k_chaincode[32]
	bool rawprivatekey_to_rawpublickey(uint8_t const* const raw_privatekey_xsk, uint8_t* const raw_publickey_xvk) noexcept
	{

		if (!valid_ed25519_sk(raw_privatekey_xsk) || crypto_scalarmult_ed25519_base_noclamp(raw_publickey_xvk, raw_privatekey_xsk) != 0)
		{
			sodium_memzero(raw_publickey_xvk, XVK_LENGTH);
			return false;
		}

		for (uint8_t i = 64; i < 96; i++)
		{  //Copia el chain code del privatekey
			raw_publickey_xvk[i - 32] = raw_privatekey_xsk[i];  // Public Key (32 bytes) || Chain Code (32 bytes) = Extended Verification Keys
		}

		return true;
	}
	/// extended_privatekey_child[96] = kli || kri || Ci
	bool raw_child_privatekey(uint8_t const* const raw_parent_privatekey_xsk, uint32_t const index, uint8_t* const raw_child_privatekey_xsk) noexcept
	{

		if (!valid_ed25519_sk(raw_parent_privatekey_xsk))
		{
			sodium_memzero(raw_child_privatekey_xsk, XSK_LENGTH);
			return false;
		}

		uint8_t buffer_xvk[XVK_LENGTH]; // buffer de 64bytes (almacena sha512 y llaves xvk)
		uint8_t data_ci[64];
		uint8_t data_raw[69];

		if (index < 2147483648U)
		{//de 0x00000000 a 0x7fffffff; de 0 a (2^31)-1
///data_raw[37]; //1byte(0x02)+32byte(parent publickey)+4byte(index)

//parent public key (Big-endian)
			if (crypto_scalarmult_ed25519_base_noclamp(&data_raw[1], raw_parent_privatekey_xsk) != 0)
			{ // se obtiene la llave publica
				sodium_memzero(raw_child_privatekey_xsk, XSK_LENGTH);
				return false;
			}

			//index (Little-endian)
			store32_le(index, &data_raw[33]);

			//Z = hmac512( parent chaincode, 0x02 || parent publickey || index )
			data_raw[0] = 0x02;
			hmac512_sodium(&raw_parent_privatekey_xsk[64], 32, data_raw, 37, buffer_xvk); //ahora hmac512=Z=raw_child_extended_private_key

			//Ci = hmac512( parent chaincode, 0x03 || parent publickey || index )
			data_raw[0] = 0x03;
			hmac512_sodium(&raw_parent_privatekey_xsk[64], 32, data_raw, 37, data_ci);

			//parent chain code
			for (uint8_t i = 32; i < 64; i++)
			{
				raw_child_privatekey_xsk[64 + (i - 32)] = data_ci[i];
			}
		}
		else
		{ // de 0x80000000 a 0xffffffff ; de 2^31 a (2^32)-1; como el uint32 es igual al maximo, no se usa condicion para delimitar a index
		///data_raw[69]; //1byte(0x00)+64byte(parent extended privatekey)+4byte(index)

		//raw_parent_privatekey_xsk[64] = k = kparent_l + kparent_r
			for (uint8_t i = 0; i < 64; i++)
			{
				data_raw[1 + i] = raw_parent_privatekey_xsk[i];
			}
			//index (Little-endian)
			store32_le(index, &data_raw[65]);

			//Z = hmac512( parent chaincode, 0x00 || parent privatekey || index )
			data_raw[0] = 0x00;
			hmac512_sodium(&raw_parent_privatekey_xsk[64], 32, data_raw, 69, buffer_xvk); //ahora hmac512=Z=raw_child_extended_private_key(64bytes)

			//Ci = hmac512( parent chaincode, 0x01 || parent privatekey || index )
			data_raw[0] = 0x01;
			hmac512_sodium(&raw_parent_privatekey_xsk[64], 32, data_raw, 69, data_ci);

			for (uint8_t i = 32; i < 64; i++)
			{
				raw_child_privatekey_xsk[64 + (i - 32)] = data_ci[i];
			}
		}

		uint8_t kl[32];
		uint8_t kr[32];


		add_28_mul8(&raw_parent_privatekey_xsk[0], &buffer_xvk[0], kl);
		add_256bits(&raw_parent_privatekey_xsk[32], &buffer_xvk[32], kr);

		for (uint8_t i = 0; i < 32; i++)
		{
			raw_child_privatekey_xsk[i] = kl[i];
			raw_child_privatekey_xsk[32 + i] = kr[i];
		}

		sodium_memzero(data_raw, 69);
		sodium_memzero(data_ci, 64);
		sodium_memzero(kl, 32);
		sodium_memzero(kr, 32);
		sodium_memzero(buffer_xvk, XVK_LENGTH);

		return true;
	};
	/// extended_publickey_child[64] = Ai[32] || Ci[32]
	bool raw_child_publickey(uint8_t const* const raw_parent_public_key_xvk, uint32_t const index, uint8_t* const raw_child_public_key_xvk) noexcept
	{

		if (index < 2147483648U)
		{//de 0x00000000 a 0x7fffffff; de 0 a (2^31)-1
			uint8_t data_raw[37]; //1byte(0x02)+32byte(raw_public_key_littleendian)+4byte(index)
			uint8_t data_ci[64];
			uint8_t data_z[64];

			//parent public key (Big-endian)
			for (uint8_t i = 0; i < 32; i++)
			{
				data_raw[1 + i] = raw_parent_public_key_xvk[i];
			}
			// index (Little-endian)
			store32_le(index, &data_raw[33]);

			//Z = hmac512( parent chaincode, 0x02 || parent publickey || index )
			data_raw[0] = 0x02;
			hmac512_sodium(&raw_parent_public_key_xvk[32], 32, data_raw, 37, data_z); // Z = data_z

			//Ci = hmac512( parent chaincode, 0x03 || parent publickey || index )
			data_raw[0] = 0x03;
			hmac512_sodium(&raw_parent_public_key_xvk[32], 32, data_raw, 37, data_ci);
			for (uint8_t i = 32; i < 64; i++)
			{
				raw_child_public_key_xvk[i] = data_ci[i];
			}

			///Por ser llaves Publicas no se realiza un borrado seguro
			//sodium_memzero(data_raw, 37);
			//sodium_memzero(data_ci, 64);

			//Ai = parent publickey + trunc28(Zl)B
			if (point_plus(raw_parent_public_key_xvk, data_z, raw_child_public_key_xvk) == false)
			{
				sodium_memzero(raw_child_public_key_xvk, XVK_LENGTH);
				return false;
			}
		}
		else
		{
			sodium_memzero(raw_child_public_key_xvk, XVK_LENGTH);
			return false;
		}

		return true;
	}
	/// signature_extended[64] = R[32] || S[32]
	bool signature_deprecated(uint8_t const* const raw_privatekey_xsk, uint8_t const* const message, std::size_t const message_len, uint8_t* const out) noexcept
	{

		sodium_memzero(out, 64);

		if (!valid_ed25519_sk(raw_privatekey_xsk))
		{
			return false;
		}

		uint8_t nonce[64];
		uint8_t hram[64];
		uint8_t raw_publickey[32];
		crypto_hash_sha512_state sha512_;

		// Public key
		if (crypto_scalarmult_ed25519_base_noclamp(raw_publickey, raw_privatekey_xsk) != 0)
		{ // se obtiene la llave publica
			return false;
		}

		// Nonce
		crypto_hash_sha512_init(&sha512_);
		crypto_hash_sha512_update(&sha512_, &raw_privatekey_xsk[32], 32);
		crypto_hash_sha512_update(&sha512_, message, message_len);
		crypto_hash_sha512_final(&sha512_, &nonce[0]);
		crypto_core_ed25519_scalar_reduce(nonce, nonce); // reduce nonce de 64 a 32 bytes

		if (nonce[31] > 127)
		{
			sodium_memzero(nonce, 64);
			return false;
		}

		if (crypto_scalarmult_ed25519_base_noclamp(out, nonce) != 0)
		{ // R = out[0..32] = nonce[32]*B
			sodium_memzero(nonce, 64);
			return false;
		}

		for (uint8_t i = 32; i < 64; i++)
		{      // public key[0..32] -> out[32..64]
			out[i] = raw_publickey[i - 32];
		}

		// Hram
		crypto_hash_sha512_init(&sha512_);
		crypto_hash_sha512_update(&sha512_, out, 64);
		crypto_hash_sha512_update(&sha512_, message, message_len);
		crypto_hash_sha512_final(&sha512_, hram);
		crypto_core_ed25519_scalar_reduce(hram, hram); //reduce hram de 64 a 32 bytes

		// sc_muladd = (nonce + hram * raw_privatekey_xsk[0..32])mod l = S = out[32..64]
		crypto_core_ed25519_scalar_mul(&out[32], hram, raw_privatekey_xsk); // &out[32] = ( hram * raw_privatekey_xsk )mod l
		crypto_core_ed25519_scalar_add(&out[32], &out[32], nonce); // S = out[32..64] = ( &out[32] + nonce )mod l ;esta funcion guarda previamente las variables a sumar en un buffer

		// signature = R || S

		sodium_memzero(nonce, 64);
		sodium_memzero(hram, 64);
		return true;
	}
	bool signature(uint8_t const* const raw_privatekey_xsk, uint8_t const* const message, std::size_t const message_len, uint8_t* const out) noexcept
	{
		ed25519_sign_ext(message, message_len, raw_privatekey_xsk, raw_privatekey_xsk + 32, out);
		return true;
	}
	bool verify(uint8_t const* const raw_publickey, uint8_t const* const message, const uint8_t message_len, uint8_t const* const signature) noexcept
	{
		if (crypto_sign_verify_detached(signature, message, message_len, raw_publickey) != 0)
		{
			return false;
		}
		return true;
	}

	static int searchByteArraysofScript(ScriptType const script_type, uint8_t const* const input_script, std::size_t const* const input_script_len)
	{
		int a = 0;
		int b = 0;
		bool ciclo = true;
		do
		{
			switch (script_type)
			{
				case ScriptType::Native_Script:
				{
					switch (input_script[a])
					{

						case 0x98:
						{
							b = a;
							a += 2;
						}; break;
						case 0x99:
						{
							b = a;
							a += 3;
						}; break;
						case 0x9a:
						{
							b = a;
							a += 5;
						}; break;
						case 0x9b:
						{
							b = a;
							a += 9;
						}; break;
						default:
						{
							if (input_script[a] > 0x80 && input_script[a] < 0x97)
							{
								b = a;
								a += 1;
							}
							else if (a > 0)
							{
								ciclo = false;
							}
							else
							{
								throw std::invalid_argument("script error,  does not contain a array in cbor");
							}
						}; break;

					}
				}; break;
				case ScriptType::Plutus_Script_V1:
				case ScriptType::Plutus_Script_V2:
				{

					switch (input_script[a])
					{
						case 0x58:
						{
							b = a;
							a += 2;
						}; break;
						case 0x59:
						{
							b = a;
							a += 3;
						}; break;
						case 0x5a:
						{
							b = a;
							a += 5;
						}; break;
						case 0x5b:
						{
							b = a;
							a += 9;
						}; break;
						default:
						{
							if (input_script[a] > 0x40 && input_script[a] < 0x57)
							{
								b = a;
								a += 1;
							}
							else if (a > 0)
							{
								ciclo = false;
							}
							else
							{
								throw std::invalid_argument("script error,  does not contain a byte array in cbor");
							}
						}; break;

					}

				}; break;
				case ScriptType::None: { throw std::invalid_argument("script error, option ScriptType::None not valid"); }; break;
			}

		} while (ciclo);

		return b;
	}
	static void set_script(uint8_t const* const input_script, std::size_t const* const input_script_len, ScriptType const script_type, uint8_t* const output_scripthash)
	{
		int pos_arrayofscript = searchByteArraysofScript(script_type, input_script, input_script_len);
		int script_a_len = (int)*input_script_len - pos_arrayofscript + 1;
		uint8_t* script_a = (uint8_t*)malloc(sizeof(uint8_t) * script_a_len);
		if (!script_a)
			return;

		script_a[0] = static_cast<uint8_t>(script_type);
		std::memcpy(&script_a[1], &input_script[pos_arrayofscript], (*input_script_len - pos_arrayofscript));
		crypto_generichash_blake2b(output_scripthash, BLAKE224_LENGTH, script_a, script_a_len, nullptr, 0);
		std::memset(script_a, 0x00, script_a_len);
		free(script_a);
	}
	static void set_address(Address const* const address_type, uint8_t const* const input_key, InputKey const input_key_type, Wallet const wallet_type, uint32_t const* const account_path, uint32_t const* const address_index_path, uint8_t* const header, uint8_t* const payload_left, uint8_t* const payload_right, uint8_t* const buff_xvk)
	{

		///Set Address
		switch (*address_type)
		{             ///bech32(hrp, (header || payload_left || payload_right) )

			case Address::Base_Extern:
			{              /// Role = External Address

				if (!getRawKey(input_key_type, input_key, wallet_type, OutputKey::Public,
					*account_path, Role::Extern, *address_index_path, buff_xvk))
				{
					throw std::invalid_argument("setting address error,  could not get a valid public key");
					//return false;
				}

				crypto_generichash_blake2b(payload_left, BLAKE224_LENGTH, buff_xvk, 32, nullptr, 0);

				if (!getRawKey(input_key_type, input_key, wallet_type, OutputKey::Public,
					*account_path, Role::Staking, STAKE_INDEX, buff_xvk))
				{
					throw std::invalid_argument("setting address error,  could not get a valid public stake key");
					//return false;
				}

				crypto_generichash_blake2b(payload_right, BLAKE224_LENGTH, buff_xvk, 32, nullptr, 0);

			}; break;

			case Address::Base_Intern:
			{       /// Role = Internal Address

				if (!getRawKey(input_key_type, input_key, wallet_type, OutputKey::Public,
					*account_path, Role::Intern, *address_index_path, buff_xvk))
				{
					throw std::invalid_argument("setting address error, could not get a valid public key");
					//return false;
				}

				crypto_generichash_blake2b(payload_left, BLAKE224_LENGTH, buff_xvk, 32, nullptr, 0);

				if (!getRawKey(input_key_type, input_key, wallet_type, OutputKey::Public,
					*account_path, Role::Staking, STAKE_INDEX, buff_xvk))
				{
					throw std::invalid_argument("setting address error, could not get a valid public stake key");
					//return false;
				}

				crypto_generichash_blake2b(payload_right, BLAKE224_LENGTH, buff_xvk, 32, nullptr, 0);


			}; break;

			case Address::Enterprise_Extern:
			{        /// Role = External Address

				*header |= 0x60; //b0110_0000
				if (input_key_type != InputKey::AccountKey_xvk)
				{
					if (!getRawKey(input_key_type, input_key, wallet_type, OutputKey::Public,
						*account_path, Role::Extern, *address_index_path, buff_xvk))
					{
						throw std::invalid_argument("setting address error, could not get a valid public key");
						//return false;
					}
				}
				else
					memcpy(buff_xvk, input_key, XVK_LENGTH);

				crypto_generichash_blake2b(payload_left, BLAKE224_LENGTH, buff_xvk, 32, nullptr, 0);

			}; break;

			case Address::Enterprise_Intern:
			{ /// Role = Internal Address

				*header |= 0x60; //b0110_0000

				if (!getRawKey(input_key_type, input_key, wallet_type, OutputKey::Public,
					*account_path, Role::Intern, *address_index_path, buff_xvk))
				{
					throw std::invalid_argument("setting address error, could not get a valid public key");
					//return false;
				}

				crypto_generichash_blake2b(payload_left, BLAKE224_LENGTH, buff_xvk, 32, nullptr, 0);

			}; break;

			case Address::Stake:
			{             /// Role = Staking Address = External Address

				*header |= 0xE0; //b1110_0000

				if (!getRawKey(input_key_type, input_key, wallet_type, OutputKey::Public,
					*account_path, Role::Staking, *address_index_path, buff_xvk))
				{
					throw std::invalid_argument("setting address error, could not get a valid public stake key");
					//return false;
				}

				crypto_generichash_blake2b(payload_left, BLAKE224_LENGTH, buff_xvk, 32, nullptr, 0);

			}; break;

		}

		//return true;
	}
	void getBech32Address(InputKey const input_key_type, uint8_t const* const input_key, Network const network_id, Wallet const wallet_type, Address const address_type, uint32_t const account_path, uint32_t const address_index_path, std::string& address_output)
	{

		char hrp[11] {};
		uint8_t header;
		uint8_t buff_xvk[XVK_LENGTH];
		uint8_t payload_left[28];
		uint8_t payload_right[28];

		///Network::Mainnet=1, Network::Testnet=0
		header = static_cast<uint8_t>(network_id);

		///Set Human Readable Part
		if (address_type != Address::Stake)
		{
			std::strcpy(hrp, "addr");
		}
		else
		{
			std::strcpy(hrp, "stake");
		}
		if (network_id == Network::Testnet)
		{
			std::strcat(hrp, "_test");
		}


		///Set Address
		if (wallet_type == Wallet::MultiSignHD)
		{
			throw std::invalid_argument("getBech32Address error, Wallet::MultiSignHD not supported ");
			//return false;
		} // las direcciones de pago y stake multifirma (shared) se crean de dos o mas  direcciones keyhash

		set_address(&address_type, input_key, input_key_type, wallet_type,
					&account_path, &address_index_path, &header,
					payload_left, payload_right, buff_xvk);



		buff_xvk[0] = header;
		if (address_type == Address::Base_Extern || address_type == Address::Base_Intern)
		{
			for (uint8_t i = 0; i < 28; i++)
			{
				buff_xvk[1 + i] = payload_left[i];
				buff_xvk[29 + i] = payload_right[i];
			}
			bech32_encode(hrp, buff_xvk, 57, address_output);
		}
		else
		{
			for (uint8_t i = 0; i < 28; i++)
			{
				buff_xvk[1 + i] = payload_left[i];
			}
			bech32_encode(hrp, buff_xvk, 29, address_output);
		}

	}
	void getRawAddress(InputKey const input_key_type, uint8_t const* const input_key, Network const network_id, Wallet const wallet_type, Address const address_type, uint32_t const account_path, uint32_t const address_index_path, uint8_t* const output_raw, uint8_t* const output_raw_len)
	{

		uint8_t header;
		uint8_t buff_xvk[XVK_LENGTH] {};
		uint8_t payload_left[28] {};
		uint8_t payload_right[28] {};

		///Network::Mainnet=1, Network::Testnet=0
		header = static_cast<uint8_t>(network_id);


		///Set Address
		if (wallet_type == Wallet::MultiSignHD)
		{
			throw std::invalid_argument("getRawAddress error, Wallet::MultiSignHD not supported ");
			//return false;
		} // las direcciones de pago y stake multifirma (shared) se crean de dos o mas  direcciones keyhash

		set_address(&address_type, input_key, input_key_type, wallet_type,
					&account_path, &address_index_path, &header,
					payload_left, payload_right, buff_xvk);



		output_raw[0] = header;
		if (address_type == Address::Base_Extern || address_type == Address::Base_Intern)
		{
			for (uint8_t i = 0; i < 28; i++)
			{
				output_raw[1 + i] = payload_left[i];
				output_raw[29 + i] = payload_right[i];
				if (output_raw_len != nullptr)
				{
					*output_raw_len = 57;
				}
			}
		}
		else
		{
			for (uint8_t i = 0; i < 28; i++)
			{
				output_raw[1 + i] = payload_left[i];
			}
			if (output_raw_len != nullptr)
			{
				*output_raw_len = 29;
			}
		}

	}
	void getRawAddressKeyHash(InputKey const input_key_type, uint8_t const* const input_key, uint32_t const account_path, uint8_t* const addresskeyhash_output, uint8_t* const addresskeyhash_len)
	{

		uint8_t header = 0;
		uint8_t buff_xvk[XVK_LENGTH] {};
		uint8_t payload_left[28] {};
		uint8_t payload_right[28] {};

		uint32_t const address_index_path = 0;
		Address const address_type = Address::Stake;
		Wallet const wallet_type = Wallet::HD;

		set_address(&address_type, input_key, input_key_type, wallet_type,
					&account_path, &address_index_path, &header,
					payload_left, payload_right, buff_xvk);



		addresskeyhash_output[0] = header;

		for (uint8_t i = 0; i < 28; i++)
		{
			addresskeyhash_output[i] = payload_left[i];
		}
		if (addresskeyhash_len != nullptr)
		{
			*addresskeyhash_len = 28;
		}
	}
	void getBech32ScriptHash(ScriptType const script_type, std::string const& script, std::string& address_output)
	{

		std::size_t script_uint8_t_len = 0;
		uint8_t const* const script_uint8_t = (script_type != ScriptType::None) ? hexchararray2uint8array(script, &script_uint8_t_len) : nullptr;

		if (script_uint8_t != nullptr)
		{
			uint8_t blake_28bytes[BLAKE224_LENGTH] {};
			set_script(script_uint8_t, &script_uint8_t_len, script_type, blake_28bytes);
			delete[] script_uint8_t;
			char hrp[11] {};
			std::strcpy(hrp, "script");
			if (!bech32_encode(hrp, blake_28bytes, BLAKE224_LENGTH, address_output))
			{
				throw std::invalid_argument("getBech32ScriptHash error , could not encode in bech32 ");
			}

		}
		else
		{
			throw std::invalid_argument("getBech32ScriptHash error , ScriptType not supported ");
		}

	}
	// hash 28 bytes
	void getRawScriptHash(ScriptType const script_type, std::string const& script, uint8_t* const scripthash_output, uint8_t* const scripthash_len)
	{

		std::size_t script_uint8_t_len = 0;
		uint8_t const* const script_uint8_t = (script_type != ScriptType::None) ? hexchararray2uint8array(script, &script_uint8_t_len) : nullptr;

		if (script_uint8_t != nullptr)
		{
			set_script(script_uint8_t, &script_uint8_t_len, script_type, scripthash_output);
			if (scripthash_len != nullptr)
			{
				*scripthash_len = BLAKE224_LENGTH;
			}
			delete[] script_uint8_t;
		}
		else
		{
			throw std::invalid_argument("getRawScriptHash error , ScriptType not supported ");
		}

	}
	void getBech32AddressfromScript(ScriptType const script_type, std::string const& script, Network const network_id, ScriptAddress const address_output_type, std::string& address_output)
	{
		char hrp[11] {};
		uint8_t payload[29] {};
		uint8_t output_28bytesraw[BLAKE224_LENGTH] {};
		std::size_t script_uint8_t_len = 0;
		uint8_t const* const script_uint8_t = (script_type != ScriptType::None) ? hexchararray2uint8array(script, &script_uint8_t_len) : nullptr;

		if (script_uint8_t != nullptr)
		{
			set_script(script_uint8_t, &script_uint8_t_len, script_type, output_28bytesraw);
			delete[] script_uint8_t;
		}
		else
		{
			throw std::invalid_argument("getBech32AddressfromScript error , ScriptType not supported ");
		}

		switch (address_output_type)
		{
			case ScriptAddress::Payment:
			{
				std::strcpy(hrp, "addr");
				payload[0] = 0x70 | static_cast<uint8_t>(network_id);; // enterprise address
			}; break;
			case ScriptAddress::Stake:
			{
				std::strcpy(hrp, "stake");
				payload[0] = 0xf0 | static_cast<uint8_t>(network_id);; // stake address
			}; break;
		}

		if (network_id == Network::Testnet)
		{
			std::strcat(hrp, "_test");
		}

		std::memcpy(&payload[1], output_28bytesraw, 28);
		bech32_encode(hrp, payload, 29, address_output);
	}
	void getBech32AddressfromAddresses(std::string const& payment_address, std::string const& stake_address, std::string& address_output)
	{

		uint8_t payload_payment[BECH32_MAX_LENGTH] {};
		uint8_t payload_stake[BECH32_MAX_LENGTH] {};
		uint8_t payload[57] {};
		char hrp[11] {};

		uint16_t payload_payment_len = 0;
		uint16_t payload_stake_len = 0;

		if (payment_address.find("addr"))
		{
			throw std::invalid_argument("getBech32AddressfromAddresses error , payment address does not contain a valid address");
		}
		if (stake_address.find("stake"))
		{
			throw std::invalid_argument("getBech32AddressfromAddresses error , stake address does not contain a valid address");
		}

		if (!bech32_decode(payment_address.c_str(), payload_payment, &payload_payment_len))
		{
			throw std::invalid_argument("getBech32AddressfromAddresses error , could not decode payment address");
		}

		if (!bech32_decode(stake_address.c_str(), payload_stake, &payload_stake_len))
		{
			throw std::invalid_argument("getBech32AddressfromAddresses error , could not decode stake address");
		}

		//verifica las cabezeras de las direcciones
		if (payload_payment[0] >> 7)
		{
			throw std::invalid_argument("getBech32AddressfromAddresses error , payment address does not contain a valid payment header");
		}

		if (!(payload_stake[0] >> 7))
		{
			throw std::invalid_argument("getBech32AddressfromAddresses error , stake address does not contain a valid payment header");
		}

		// se usa la direccion de pago para obtener la red en la que se trabaja mainnet/testnet
		payload[0] = payload_payment[0] & 0x0f;
		switch (payload[0])
		{
			case 0x01:
			{
				std::strcpy(hrp, "addr");
			}; break;
			case 0x00:
			{
				std::strcpy(hrp, "addr_test");
			}; break;
		}

		// Se crea el nuevo header a partir de las dos direcciones pago y stake
		payload[0] |= (payload_payment[0] & 0x10);
		payload[0] |= ((payload_stake[0] & 0x10) << 1);

		for (uint8_t i = 0; i < 28; i++)
		{
			payload[1 + i] = payload_payment[i + 1];
			payload[29 + i] = payload_stake[i + 1];
		}

		bech32_encode(hrp, payload, 57, address_output);

	}
}