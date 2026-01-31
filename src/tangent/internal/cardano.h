#ifndef CARDANO_H
#define CARDANO_H
#include <stdexcept>
#include <vector>
#include <inttypes.h>
#include <sodium.h>
#define H1815 2147485463U
#define H1852 2147485500U
#define H1854 2147485502U
#define H0 2147483648U
#define SEPARATOR_BECH32 '1' //Bech32
#define BECH32_MAX_LENGTH 57U
#define BLAKE224_LENGTH 28U
#define BLAKE256_LENGTH 32U
#define STAKE_INDEX 0
#define RAWADDRESS_LENGTH_MAX 57U
#define XSK_LENGTH 96U                                 // Extended Private Key (64 bytes) || Chain Code (32 bytes)
#define XVK_LENGTH 64U                                 // Public Key (32 bytes) || Chain Code (32 bytes)
#define MASTERSECRETKEY_LENGTH 96U                     // Extended Private Key (64 bytes) || Chain Code (32 bytes)
#define SIGNATURE_LENGTH 64U
#define PROTOCOL_FEE_FIXED 155381
#define PROTOCOL_FEE_PER_BYTE 44
#define PROTOCOL_UTXO_VALUE_PER_WORD 34482

namespace Cardano
{
	enum class Wallet : uint8_t
	{
		HD,
		MultiSignHD
	};

	enum class Role : uint8_t
	{
		Extern,
		Intern,
		Staking,
		OnlyAccount
	};

	enum class OutputKey : uint8_t
	{
		Private,
		Public
	};

	enum class InputKey : uint8_t
	{
		MasterKey,  // is a Extended MasterKey
		AccountKey_xvk,
		AccountKey_xsk
	};

	enum class Network : uint8_t
	{
		Testnet,
		Mainnet
	};

	enum class Address : uint8_t
	{
		Base_Extern,  // normal
		Base_Intern,  //change
		Enterprise_Extern, //normal
		Enterprise_Intern, //change
		Stake
	};

	enum class ScriptType
	{
		Native_Script = 0,
		Plutus_Script_V1,
		Plutus_Script_V2,
		None,
	};

	enum class ScriptAddress : uint8_t
	{
		Payment,
		Stake
	};

	enum class ScriptReference : uint8_t
	{
		Spending,
		Certificate,
		Withdrawal
	};

	enum class Credential
	{
		RawAddressKeyHash = 0,
		RawScriptHash
	};

	class CborSerialize
	{
	public:
		explicit CborSerialize();
		virtual ~CborSerialize();

		CborSerialize& createArray(uint64_t const size_array);
		CborSerialize& createArrayUndefined();  // stop whith addBreak()
		CborSerialize& createMap(uint64_t const size_array);
		CborSerialize& addIndexMap(uint64_t const index);
		CborSerialize& addIndexMap(std::string const& text);
		CborSerialize& addIndexMap(uint8_t const* const bytesarray, uint64_t bytesarray_length);
		CborSerialize& addIndexMap(uint8_t const* const arraynumbe8byteshex);
		CborSerialize& addBool(bool const b);
		CborSerialize& addNull();
		CborSerialize& addBreak();
		CborSerialize& addUint(uint64_t const number);
		CborSerialize& addUint(uint8_t const* const arraynumbe8byteshex);
		CborSerialize& addNint_withoutzero(uint64_t number); // toma un uint64_t y lo serializa como un numero negativo de 64bytes, se excluye el cero
		CborSerialize& addNint_zero_equal_1(uint64_t number); //considera cero = -1
		CborSerialize& addTag(uint64_t const number); //funcion addTag incompleta,los primeros 23 numeros estan reservados a funciones especiales
		CborSerialize& addBytesArray(uint8_t const* const bytes, uint64_t const bytes_length);
		CborSerialize& addBytesArray(std::vector<uint8_t> const& bytes);
		CborSerialize& addBytesArray();
		CborSerialize& addUint2BytesArray(uint64_t const number);
		CborSerialize& addString(std::string const& text);
		CborSerialize& bypassVectorCbor(std::vector<uint8_t> const& vectorCbor);
		CborSerialize& bypassIteratorVectorCbor(std::vector<uint8_t>::const_iterator it_begin, std::vector<uint8_t>::const_iterator it_end);
		CborSerialize& bypassPtrUint8Cbor(uint8_t const* const ptrArrayCbor, uint64_t const ptrArrayCbor_len);
		void clearCbor();
		std::vector<uint8_t> const& getCbor() const;

	private:
		enum class Pos_hex
		{
			hff,
			hff2,
			hff4,
			hff8,
		};
		std::vector<uint8_t> bytes_cbor_data {};
		void AddNumber2Vector(uint64_t const& size_array, Pos_hex const& pos);
		void AddNumber2Vector(uint64_t const& size_array, Pos_hex const& pos, std::vector<uint8_t>& Vector_);
	};

	class PlutusJsonSchema
	{
	public:
		explicit PlutusJsonSchema();
		virtual ~PlutusJsonSchema();
		void addSchemaJson(std::string json);
		std::vector<uint8_t> const& getCborSchemaJson() const;
		uint8_t* getHash32CborSchemaJson();


	private:
		enum class tipo_t
		{
			tipo_int,
			tipo_bytes,
			tipo_map,
			tipo_list,
			tipo_constructor,
			tipo_constructor_field,
			tipo_error
		};

		std::vector<uint8_t> cborschema;
		uint8_t datum_hash[32] {};
		std::size_t find_caracter_it(char const caracter, std::string::const_iterator it, std::string::const_iterator it_end);
		std::size_t pos_primer_caracter_it(char const caracter, std::string::const_iterator it, std::string::const_iterator it_end);
		std::size_t pos_ultimo_caracter_it(char const caracter, std::string::const_iterator it, std::string::const_iterator it_end);
		std::size_t posfinal_primer_string_it(std::string frase, std::string::const_iterator it, std::string::const_iterator it_end);
		uint64_t obtener_int_str(std::string::iterator& it, std::string::const_iterator const& it_end, bool& npositivo);
		uint64_t obtener_int_constructor_str(std::string::iterator& it, std::string::const_iterator const& it_end);
		bool es_igual_ydesplazaIt(std::string const frase, std::string::iterator& it, std::string::const_iterator const& it_end);
		bool obtener_bytes_str(std::string::iterator& it, std::string::const_iterator const& it_end, std::vector<uint8_t>& bytes_vector);
		bool obtener_key_value_map(std::string::iterator& it, std::string::const_iterator& it_end, std::vector<uint8_t>& key_cbor, std::vector<uint8_t>& value_cbor);
		std::vector<uint8_t> obtener_list_cbor(std::string::iterator& it, std::string::const_iterator& it_end);
		std::vector<uint8_t> obtener_tipo(std::string::iterator& it, std::string::const_iterator& it_end);
		tipo_t detectar_tipo(std::string::iterator& it, std::string::const_iterator const& it_end);
	};

	class Metadatas
	{
	public:
		explicit Metadatas();
		void addMetadata(uint64_t const keytag, std::vector<uint8_t> const& CborMetadata);
		bool arethereMetadatas() const;
		std::vector<uint8_t> const& getCborMetadatas();
	private:
		uint8_t* ptrvec;
		uint16_t metadata_count;
		std::vector <uint8_t> metadata;
		CborSerialize cbor;
	};

	class AuxiliaryData : public Metadatas
	{
	public:
		explicit AuxiliaryData();
		bool arethereAuxiliaryData() const;
		std::vector<uint8_t> const& Build();

	private:
		uint8_t auxiliarymapcountbit;
		CborSerialize cbor;
	};

	class NativeScripts
	{
	public:
		explicit NativeScripts();
		NativeScripts& SignatureOf(uint8_t const* const vk_hash);                // Argumento
		NativeScripts& SignatureOf(std::string const payment_address);                // Argumento
		NativeScripts& requireAllOf();                                                // Condicionales
		NativeScripts& requireAnyOf();                                                // Condicionales
		NativeScripts& requireAtLeastNOf(uint64_t const n);                      // Condicionales
		NativeScripts& Endrequire();
		NativeScripts& thisIsValidBeforeSlot(uint64_t const slot); //antes del tiempo  // Condicionales
		NativeScripts& thisIsValidAfterSlot(uint64_t const slot); //despues del tiempo // Condicionales
		std::vector<uint8_t> const& getCborNativeScripts();
		std::string const& getJsonNativeScripts();

	private:
		uint8_t eoc; //espacio ocupado en capsula
		uint8_t pec; // posicion en capsula
		uint8_t bufferbech32[BECH32_MAX_LENGTH] {};
		std::vector< std::vector<uint8_t> > capsula; // guarda el contenido de las firmas y tiempo
		std::vector<uint8_t> condiciones {}; //Guarda las condicionantes como All, Any, N de K. Endrequire
		std::vector<uint8_t> ppec {}; // posicion previa en capsula
		CborSerialize cbor;
		//std::vector<uint8_t> cbornativescript;  // recibe los datos serializados en Cbor
		//std::vector<uint8_t> vector_buffer;
	};

	class Multiassets
	{
	public:
		explicit Multiassets();
		virtual ~Multiassets();
		Multiassets& addAsset(uint8_t const* const policyID, uint8_t const* const assetname, std::size_t const& assetname_len, uint64_t const amount);
		Multiassets& addAsset(uint8_t const* const policyID, std::string assetname, uint64_t const amount);
		//uint8_t const &minUTXORequired();
		std::vector<uint8_t> const& getCborMultiassets();
	private:

		//std::vector<uint8_t> buffer_cbor;
		std::vector< std::vector<uint8_t> > capsula;
		//CborSerialize *cbor; //se usa buffer_cbor para serializar en cbor
		CborSerialize cbor;
	};

	class Withdrawals
	{
	public:
		explicit Withdrawals();
		virtual ~Withdrawals();
		Withdrawals& addWithdrawals(uint8_t const* const raw_stake_address, uint64_t const amount);
		Withdrawals& addWithdrawals(std::string& stake_address, uint64_t const amount);
		void addRedeemer(std::string& json_redeemer, uint64_t const cpusteps, uint64_t const memoryunits); // FOR WITHDRAWAL

		void alphanumeric_organization();
		uint16_t const& getWithdrawalRedeemersCount() const;
		uint32_t const& getBodyMapcountbit() const;
		uint16_t const& getWitnessMapcountbit() const;
		uint16_t const& getWithdrawalsCount() const;
		std::vector<uint8_t> const& getWithdrawals() const;
		std::vector<uint8_t> const& getWithdrawalRedeemers() const;

	private:
		std::size_t buff_sizet;
		uint32_t bodymap_countbit;
		uint16_t  witnessmap_countbit;
		uint16_t withdrawals_count; //maximo 65534
		uint16_t redeemer_withdrawals_count;
		uint8_t buffbech32[BECH32_MAX_LENGTH] {};
		std::vector <uint8_t>withdrawals {};
		std::vector <uint8_t> redeemer_withdrawals {};

	};

	class Certificates
	{

	public:
		explicit Certificates();
		virtual ~Certificates();



		void addStakeRegistration(Credential const ckey, uint8_t const* const stake_credential);
		void addStakeDeregistration(Credential const ckey, uint8_t const* const stake_credential);
		void addStakeDelegation(Credential const ckey, uint8_t const* const stake_credential, uint8_t const* const pool_keyhash);
		void addStakeDelegation(Credential const ckey, uint8_t const* const stake_credential, std::string const& pool_bech32);
		void addRedeemer(std::string& json_redeemer, uint64_t const cpusteps, uint64_t const memoryunits); // FOR CERTIFICATE
		std::vector<uint8_t> const& getCertificateRedeemers() const;

		uint16_t const& getCertificateRedeemersCount() const;
		uint32_t const& getBodyMapcountbit() const;
		uint16_t const& getWitnessMapcountbit() const;
		uint16_t const& getCborCertificatesCount() const;  //serializa en cbor los certificados
		std::vector<uint8_t> const& getCborCertificates() const;  //serializa en cbor los certificados
	private:

		uint16_t redeemer_cert_count;
		uint16_t cbor_certificates_count;
		uint8_t blake224[28] {};
		std::vector <uint8_t> redeemer_cert {};
		std::vector <uint8_t> cbor_certificates {};
		CborSerialize cert_cbor;
		uint32_t bodymap_countbit;      ///  0x0001 , Tiene que iniciar con cero
		uint16_t witnessmap_countbit;      ///  0x0001 , Tiene que iniciar con cero

	};

	class TransactionWitness
	{

	public:
		explicit TransactionWitness();
		virtual ~TransactionWitness();
		TransactionWitness& addVkeyWitness(uint8_t const* const public_key, uint8_t const* const signature_transactionbody);
		//TransactionWitness & addNativeScript( uint8_t const * const cborNativeScript, std::size_t const cborNativeScript_len );
		TransactionWitness& addNativeScript(std::vector<uint8_t> const& cborNativeScript);
		TransactionWitness& addRedeemer(std::vector <uint8_t> const& cborRedeemers);
		TransactionWitness& addDatum(std::vector <uint8_t> const& cborDatums);
		TransactionWitness& addPlutusV1Script(std::vector <uint8_t> const& cborPlutusV1Scripts);
		TransactionWitness& addPlutusV2Script(std::vector <uint8_t> const& cborPlutusV2Scripts);
		std::vector<uint8_t> const& Build();

	private:
		uint8_t* ptrvec;
		std::size_t buff_sizet;
		uint8_t witnessmapcountbit;
		uint16_t vkeywitness_count; //maximo 65534
		uint16_t cbor_plutusv1scripts_count { 0 };
		uint16_t cbor_plutusv2scripts_count { 0 };
		uint16_t cbor_native_script_count { 0 };
		CborSerialize cbor;
		std::vector <uint8_t> vkeywitness {};
		std::vector <uint8_t> cbor_datums {};
		std::vector <uint8_t> cbor_redeemers {};
		std::vector <uint8_t> const* cbor_plutusv1scripts {};
		std::vector <uint8_t> const* cbor_plutusv2scripts {};
		std::vector <uint8_t> const* cbor_native_script {};

	};

	class TransactionsInputs
	{
	public:
		explicit TransactionsInputs();


		/// Agregar un bloqueo para que solo acepte un datum y un redeemer por direccion
		TransactionsInputs& addInput(std::string const& TxHash, uint64_t const TxIx);  // -> addScript() || addReferenceInput -> addDatum() -> addRedeemer()
		TransactionsInputs& addInlineScript(ScriptType const script_type, std::string const& TxHash, uint64_t const TxIx);
		TransactionsInputs& setGlobalReferencesStriptsType(ScriptType const script_type); // necesario para el calculo del scriptdatahash , se debe especificar por obligacion
		TransactionsInputs& addCollateral(std::string const& TxHash, uint64_t const TxIx);
		TransactionsInputs& addDatum(std::string& json_datum);  // FOR SPENDING      ;Se usa para el witness y el scriptdatahash
		//TransactionsInputs & addSpendingDatum( std::string & json_datum );  // Se usa para el witness y el scriptdatahash
		TransactionsInputs& addRedeemer(std::string& json_redeemer, uint64_t const cpusteps, uint64_t const memoryunits);  // FOR SPENDING   ;Se usa para el witness y el scriptdatahash
		TransactionsInputs& addScript(ScriptType const script_type, uint8_t const* const& script, std::size_t& script_len); // Se usa para el witness y el scriptdatahash (solo el script_type)
		TransactionsInputs& addScript(ScriptType const script_type, std::string const& script);

		uint32_t const& getBodyMapcountbit() const;
		uint16_t const& getWitnessMapcountbit() const;

		void alphanumeric_organization();  // ordena los index  de los utxos, redeemer y datum de manera alfanumerica
		uint16_t const& getInputsCount() const;
		uint16_t const& getInputsReferencesCount() const;
		uint16_t const& getCollateralCount() const;
		uint16_t const& getDatumsCount() const;
		uint16_t const& getSpendingRedeemersCount() const;
		uint16_t const& getPlutusV1ScriptsCount() const;
		uint16_t const& getPlutusV2ScriptsCount() const;
		uint16_t const& getNativeScriptsCount() const;


		ScriptType getGlobalReferencesScriptsType() const;

		std::vector<uint8_t> const& getInputs() const;
		std::vector<uint8_t> const& getInputsReferences() const;
		std::vector<uint8_t> const& getCollateral() const;
		std::vector<uint8_t> const& getDatums() const;
		std::vector<uint8_t> const& getSpendingRedeemers() const;
		std::vector<uint8_t> const& getPlutusV1Scripts();
		std::vector<uint8_t> const& getgetPlutusV2Scripts();
		std::vector<uint8_t> const& getNativeScripts();

	private:
		bool addUtxoInput(uint8_t const t_selector, uint8_t const* const& TxHash, uint64_t const& TxIx);
		ScriptType globalreferencescript;
		uint16_t tx_input_count;              //maximo 65534
		uint16_t reference_input_count;       //maximo 65534
		uint16_t collateral_input_count;      //maximo 65534
		uint16_t datum_input_count;           //maximo 65534
		uint16_t redeemer_input_count;        //maximo 65534
		uint16_t plutusscript1_input_count;   //maximo 65534
		uint16_t plutusscript2_input_count;   //maximo 65534
		uint16_t nativescript_input_count;    //maximo 65534
		std::vector<uint8_t> tx_input {};
		std::vector<uint8_t> reference_input {};
		std::vector<uint8_t> collateral_input {};
		std::vector<uint8_t> datum_input {};
		std::vector<uint8_t> redeemer_input {};
		std::vector<uint8_t> plutusscript1_input {};
		std::vector<uint8_t> plutusscript2_input {};
		std::vector<uint8_t> nativescript_input {};
		std::size_t buff_sizet;
		uint32_t bodymap_countbit;      ///  0x0001 , Tiene que iniciar con cero
		uint16_t witnessmap_countbit;      ///  0x0001 , Tiene que iniciar con cero
	};

	class TransactionsOutputs
	{
	public:
		explicit TransactionsOutputs();
		//TransactionsOutputs ~TransactionsOutputs();

		TransactionsOutputs& addOutput(uint8_t const* const address_keyhash, std::size_t const& address_keyhash_len, uint64_t const& amount);
		TransactionsOutputs& addColateralReturn(uint8_t const* const address_keyhash, std::size_t const& address_keyhash_len, uint64_t const& amount);

		TransactionsOutputs& addColateralReturn(std::string const payment_address, uint64_t const amount);
		TransactionsOutputs& addOutput(std::string const payment_address, uint64_t const amount);

		TransactionsOutputs& addAsset(uint8_t const* const policyID, uint8_t const* const assetname, std::size_t const& assetname_len, uint64_t const amount);
		TransactionsOutputs& addAsset(std::string policyID, std::string assetname, uint64_t const amount);
		TransactionsOutputs& addDatumHash(uint8_t const* const datum_hash, std::size_t const& datum_hash_len);
		TransactionsOutputs& addDatumHashcreatedfromJson(std::string& json_datum);
		TransactionsOutputs& addInlineScript(ScriptType const script_type, uint8_t const* const script_, std::size_t& script_len); //native, plutus script
		TransactionsOutputs& addInlineScript(ScriptType const script_type, std::string& script_);
		TransactionsOutputs& addInlineDatumIntValue(uint64_t const integer_datum);
		TransactionsOutputs& addInlineDatum(std::string& json_datum);
		uint32_t const& getBodyMapcountbit() const;
		std::vector<uint8_t> const& getTransactionsOutputs();
		uint16_t const& getAmountTransactionsOutputs() const;

	private:
		uint8_t outputmap_countbit;  // 0x01 = address , 0x02 = asset , 0x04 = datum , 0x08 = script , 0x10 = colateralreturn
		uint32_t pos_registro_elementos; // maximo 4294967295 , indica en que posicion del vector se deben registrar la cantidad de elementos
		uint32_t bodymap_countbit; ///  0x0002 , Tiene que iniciar con cero
		uint16_t tx_output_count;      // maximo 65535
		uint8_t addr_keyhash_buffer[BECH32_MAX_LENGTH] {};
		uint16_t addr_keyhash_buffer_len;
		std::size_t buff_sizet;
		std::vector<uint8_t> tx_output;
		std::vector<uint8_t> datum_hash;
		// cbor_datum_array : Almacena los datum en un array, para luego usarlos en transaction witness (index 4)
		// esquema [cantidad de datum  | largo valor1 | valor1 | largo valor2 | valor2 | largo valor3 | valor3 ]
		//std::vector<uint8_t> cbor_datum_array; /// VER SI ACTIVAR ESTA FUNCION O REALIZARLA DESDE EL BODY
		std::vector< std::vector<uint8_t> > capsula;
		//std::vector<uint8_t> cbor_array;
		CborSerialize cbor;
		std::vector<uint8_t> const& getCborMultiassets();

	};

	class TransactionBody : private  Multiassets
	{

	public:

		explicit TransactionBody();
		virtual ~TransactionBody();
		TransactionsOutputs TransactionOutput;
		TransactionsInputs TransactionInput;
		Certificates Certificate;
		Withdrawals Withdrawal;
		TransactionBody& addFee(uint64_t const amount);
		TransactionBody& addInvalidAfter(uint64_t const number);
		TransactionBody& addInvalidBefore(uint64_t const number);
		TransactionBody& addAuxiliaryDataHash(uint8_t const* const hash_32bytes);
		TransactionBody& addTotalCollateral(uint64_t const amount);
		std::vector<uint8_t> const& Build();
		std::vector<uint8_t> const& getcbor_afterBuild() const;
		std::vector<uint8_t> const& getcborDatums_afterBuild() const;
		std::vector<uint8_t> const& getcborRedeemers_afterBuild() const;
		uint16_t const& getWitnessMapcountbit() const;

	private:

		uint8_t const* ptrvec;
		std::size_t buff_sizet;
		uint32_t buff_uint32t;
		uint8_t addr_keyhash_buffer[BECH32_MAX_LENGTH] {};
		uint16_t addr_keyhash_buffer_len;
		uint32_t bodymapcountbit; // pone un bits a 1 si existe la variable, en la posisicion correspondiente al map de el transaccion body
		uint16_t witnessmapcountbit; // pone un bits a 1 si existe la variable, en la posisicion correspondiente al map de el transaccion witness
		uint64_t fee;
		uint64_t ttl;  // time to alive
		uint64_t vis;  // validity interval start
		uint64_t totalcollateral;  // validity interval start
		CborSerialize cbor;
		std::vector <uint8_t>cbor_redeemers {};
		std::vector <uint8_t>cbor_datums {};
		std::vector <uint8_t>update {};
		std::vector <uint8_t>auxiliary_data_hash {};
		std::vector <uint8_t>validity_interval_start {};
		std::vector <uint8_t>mint {};
		std::vector <uint8_t>collateral_inputs {};
		std::vector <uint8_t>required_signers {};
		std::vector <uint8_t>network_id {};
		std::vector <uint8_t>collateral_return {};
		std::vector <uint8_t>total_collatera {};
		std::vector <uint8_t>reference_inputs {};
		uint8_t V1language_views[444];
		uint8_t V2language_views[467];
	};

	class Transaction
	{
	public:
		struct Digest
		{
			uint8_t Hash[32];
		};

	public:
		explicit Transaction();
		explicit Transaction(uint64_t txfeefixed, uint64_t txfeeperbytes);
		virtual ~Transaction();
		TransactionBody Body;
		AuxiliaryData Auxiliarydata;
		Transaction& addExtendedSigningKey(uint8_t const* const xsk);
		Transaction& addExtendedVerifyingKey(uint8_t const* const xvk, uint8_t const* const signature);
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
		std::vector<const uint8_t*> xskeys_ptr;
		std::vector <uint8_t> cborTransaction;
	};

	unsigned int bytes_structure_cbornumber(uint64_t number) noexcept;
	void addUint64toVector(std::vector <uint8_t>& bytesvector, uint64_t const& numero);
	void addUint16toVector(std::vector <uint8_t>& bytesvector, uint16_t const& numero);
	void addUint16toVector(std::vector <uint8_t>*& bytesvector, uint16_t*& numero);
	void replaceUint16toVector(uint8_t* bytesvector, uint16_t const& numero) noexcept;
	uint64_t extract8bytestoUint64(uint8_t  const* const array8bytes) noexcept;
	uint16_t extract2bytestoUint16(uint8_t  const* const array2bytes) noexcept;
	bool existen_coincidencias(uint8_t const* data1, uint8_t const* data2, uint16_t const data_len, uint16_t const ciclos, uint16_t const salto) noexcept;
	bool existen_coincidencias_output(uint8_t const* data, uint8_t const* output, uint16_t const data_len, uint16_t const ciclos, uint16_t const salto) noexcept;
	uint8_t* hexchararray2uint8array(std::string const& string_hex, std::size_t* hexchararray2uint8array_len) noexcept; // free memory with delete[]

	bool bech32_encode(char const* const hrp, uint8_t const* const data, uint16_t const data_len, std::string& encode_out) noexcept;
	///  bech32_decode { (char)bech32_code } = (uint8_t)data[data_len] ; data_len puede ser nullprt, data_len <= 57 bytes
	bool bech32_decode(char const* const bech32_code, uint8_t* const data_out, uint16_t* const data_out_len) noexcept;
	///  bech32_decode { (char)bech32_code } = (uint8_t)data[data_len] ; data_len puede ser nullprt
	bool bech32_decode_extended(char const* const bech32_code, uint8_t* const data_out, uint16_t* const data_out_len, uint16_t max_size) noexcept;

	//for generate all key
	bool getRawKey(InputKey input_key_type, uint8_t const* const input_key, Wallet wallet_type, OutputKey output_key_type, uint32_t const account_path, Role role_path, uint32_t const address_index_path, uint8_t* const output_key) noexcept;
	//for generate only key account
	//mandatory, role_path = Role::OnlyAccount
	bool getRawKey(InputKey input_key_type, uint8_t const* const input_key, Wallet wallet_type, OutputKey output_key_type, uint32_t const account_path, Role role_path, uint8_t* const output_key) noexcept;
	//for generate all key
	bool getBech32key(InputKey input_key_type, uint8_t const* const input_key, Wallet wallet_type, OutputKey output_key_type, uint32_t const account_path, Role role_path, uint32_t const address_index_path, std::string& bech32_output_key) noexcept;
	//for generate only key account
	//mandatory, role_path = Role::OnlyAccount
	bool getBech32key(InputKey input_key_type, uint8_t const* const input_key, Wallet wallet_type, OutputKey output_key_type, uint32_t const account_path, Role role_path, std::string& bech32_output_key) noexcept;

	bool getRawMasterKey(uint8_t const* const entropy, std::size_t const entropy_len, uint8_t const* const password, std::size_t const password_len, uint8_t* const mastersecretkey_out) noexcept;
	bool rawprivatekey_to_rawpublickey(uint8_t const* const raw_privatekey_xsk, uint8_t* const raw_publickey_xvk) noexcept;
	bool raw_child_privatekey(uint8_t const* const raw_parent_privatekey_xsk, uint32_t const index, uint8_t* const raw_child_privatekey_xsk) noexcept;
	bool raw_child_publickey(uint8_t const* const raw_parent_public_key_xvk, uint32_t const index, uint8_t* const raw_child_public_key_xvk) noexcept;
	bool signature(uint8_t const* const raw_privatekey_xsk, uint8_t const* const message, std::size_t const message_len, uint8_t* const out) noexcept;
	bool verify(uint8_t const* const raw_publickey, uint8_t const* const message, const uint8_t message_len, uint8_t const* const signature) noexcept;
	bool valid_ed25519_sk(uint8_t const* const raw_privatekey_sk) noexcept;

	// Both functions throw exceptions of type std::invalid_argument
	// get a addresses serialized in bech32, for example addr1v8....
	void getBech32Address(InputKey const input_key_type, uint8_t const* const input_key, Network const network_id, Wallet const wallet_type, Address const address_type, uint32_t const account_path, uint32_t const address_index_path, std::string& address_output);
	// get unserialized addresses
	void getRawAddress(InputKey const input_key_type, uint8_t const* const input_key, Network const network_id, Wallet const wallet_type, Address const address_type, uint32_t const account_path, uint32_t const address_index_path, uint8_t* const output_raw, uint8_t* const output_raw_len);
	// get a stake addr_keyhash
	void getRawAddressKeyHash(InputKey const input_key_type, uint8_t const* const input_key, Network const network_id, uint32_t const account_path, uint8_t* const addresskeyhash_output, uint8_t* const addresskeyhash_len);
	void getBech32ScriptHash(ScriptType const script_type, std::string const& script, std::string& address_output);
	void getRawScriptHash(ScriptType const script_type, std::string const& script, uint8_t* const scripthash_output, uint8_t* const scripthash_len);
	// Create an address (Bech32) from a script
	void getBech32AddressfromScript(ScriptType const script_type, std::string const& script, Network const network_id, ScriptAddress const address_output_type, std::string& address_output);
	void getBech32AddressfromAddresses(std::string const& payment_address, std::string const& stake_address, std::string& address_output);
}

#endif