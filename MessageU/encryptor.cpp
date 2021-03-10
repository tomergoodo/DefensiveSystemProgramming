/**
 * @author Tomer Goodovitch 213213838
 */
#include "encryptor.h"

#include <immintrin.h>
#include <cstddef>

#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"
#include "cryptopp/base64.h"
#include "cryptopp/files.h"

#include "cryptopp/modes.h"
#include "cryptopp/aes.h"
#include "cryptopp/filters.h"


namespace MessageU {

	RSAPubKey::RSAPubKey(const uint8_t(&public_key)[key_size])
	{
		CryptoPP::ArraySource as(public_key, key_size, true);
		_public_key.Load(as);
	}
	RSAPubKey::RSAPubKey(const std::string& base64) { Base64s2PublicKey(base64); }
	RSAPubKey::RSAPubKey(const CryptoPP::RSA::PublicKey& public_key) : _public_key(public_key) {}

	std::string RSAPubKey::encrypt(const std::string& plain) {
		std::string cipher_text;
		CryptoPP::RSAES_OAEP_SHA_Encryptor e(_public_key);
		CryptoPP::StringSource ss(plain, true, new CryptoPP::PK_EncryptorFilter(rng, e, new CryptoPP::StringSink(cipher_text)));

		return cipher_text;
	}

	std::string RSAPubKey::encryptKey(uint8_t(&key)[CryptoPP::AES::DEFAULT_KEYLENGTH])
	{
		std::string encrypted_key;
		CryptoPP::RSAES_OAEP_SHA_Encryptor e(_public_key);
		try
		{
			CryptoPP::ArraySource as(key, CryptoPP::AES::DEFAULT_KEYLENGTH, true,
				new CryptoPP::PK_EncryptorFilter(rng, e, new CryptoPP::StringSink(encrypted_key)));
		} catch (const CryptoPP::InvalidArgument& ex)
		{
			std::cout << ex.what() << std::endl;
		}
		return encrypted_key;
	}

	void RSAPubKey::Base64s2PublicKey(const std::string& base64)
	{
		CryptoPP::ByteQueue bytes;
		CryptoPP::StringSource source(base64, true, new CryptoPP::Base64Decoder);
		source.TransferTo(bytes);
		bytes.MessageEnd();
		_public_key.Load(bytes);
	}

	void RSAPubKey::GetPublicKey(CryptoPP::byte(&buf)[key_size]) const {
		CryptoPP::ArraySink as(buf, key_size);
		_public_key.Save(as);
	}

	CryptoPP::RSA::PublicKey RSAPubKey::GetPublicKey() const
	{
		return _public_key;
	}
	
	void RSAPubKey::SetPublicKey(const uint8_t(&public_key)[key_size])
	{
		CryptoPP::ArraySource as(&public_key[0], key_size, true);
		_public_key.Load(as);
	}
	template<typename T>
	void RSAPubKey::SetPublicKey(const T& public_key)
	{
		CryptoPP::ArraySource as(&public_key[0], public_key.size(), true /*pumpAll*/);
		_public_key.Load(as);
	}
	void RSAPubKey::SetPublicKey(const std::string& key)
	{
		CryptoPP::StringSource ss(key, true);
		_public_key.Load(ss);
	}
	void RSAPubKey::SetPublicKey(const CryptoPP::RSA::PublicKey& public_key)
	{
		_public_key = public_key;
	}


	EncryptorRSA::EncryptorRSA() {
		GenerateKeyPair();
	}
	EncryptorRSA::EncryptorRSA(const CryptoPP::RSA::PrivateKey& private_key) : RSAPubKey(CryptoPP::RSA::PublicKey(private_key)), _private_key(private_key) {}

	std::string EncryptorRSA::decrypt(const std::string& cipher) {
		std::string decrypted;
		CryptoPP::RSAES_OAEP_SHA_Decryptor d(_private_key);
		CryptoPP::StringSource ss(cipher, true, new CryptoPP::PK_DecryptorFilter(rng, d, new CryptoPP::StringSink(decrypted)));

		return decrypted;
	}

	void EncryptorRSA::LoadPrivateKey(std::ifstream& stream) {
		CryptoPP::ByteQueue bytes;
		CryptoPP::FileSource file(stream, true, new CryptoPP::Base64Decoder);
		file.TransferTo(bytes);
		bytes.MessageEnd();
		_private_key.Load(bytes);
		_public_key = CryptoPP::RSA::PublicKey(_private_key);
	}
	void EncryptorRSA::SavePrivateKey(std::ofstream& stream) const {
		CryptoPP::Base64Encoder private_key_sink(new CryptoPP::FileSink(stream));
		_private_key.DEREncode(private_key_sink);
		private_key_sink.MessageEnd();
	}

	std::string EncryptorRSA::PrivateKey2Base64s() const {
		std::string out;
		CryptoPP::Base64Encoder sink(new CryptoPP::StringSink(out));
		_private_key.DEREncode(sink);
		sink.MessageEnd();
		return out;
	}
	void EncryptorRSA::Base64s2PrivateKey(const std::string& base64) {
		CryptoPP::ByteQueue bytes;
		CryptoPP::StringSource source(base64, true, new CryptoPP::Base64Decoder);
		source.TransferTo(bytes);
		bytes.MessageEnd();
		_private_key.Load(bytes);
		_public_key = CryptoPP::RSA::PublicKey(_private_key);
	}
	void EncryptorRSA::GenerateKeyPair() {
		_private_key.Initialize(rng, key_size_bits);
		_public_key = CryptoPP::RSA::PublicKey(_private_key);
	}



	EncryptorAES::EncryptorAES() {
		memset(_key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
		memset(_iv, 0x00, CryptoPP::AES::BLOCKSIZE);

		GenerateKey(reinterpret_cast<char*>(_key), CryptoPP::AES::DEFAULT_KEYLENGTH);
	}
	char* EncryptorAES::GenerateKey(char* buff, size_t size) {
		for (size_t i = 0; i < size; i += 4)
			_rdrand32_step(reinterpret_cast<unsigned int*>(&buff[i]));
		return buff;
	}

	std::string EncryptorAES::encrypt(const std::string& plain) {
		std::string cipher;
		CryptoPP::AES::Encryption aesEncryption(_key, CryptoPP::AES::DEFAULT_KEYLENGTH);
		CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, _iv);

		CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher));
		stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plain.c_str()), plain.length());
		stfEncryptor.MessageEnd();
		return cipher;
	}
	
	std::string EncryptorAES::decrypt(const std::string& cipher) {
		std::string decrypted;
		CryptoPP::AES::Decryption aesDecryption(_key, CryptoPP::AES::DEFAULT_KEYLENGTH);
		CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, _iv);
		CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
		stfDecryptor.Put(reinterpret_cast<const unsigned char*>(cipher.c_str()), cipher.size());
		stfDecryptor.MessageEnd();

		return decrypted;
	}


	void EncryptorAES::SetKey(const uint8_t(&key)[key_size]) {
		std::memcpy(_key, key, CryptoPP::AES::DEFAULT_KEYLENGTH);
	}
	void EncryptorAES::GetKey(CryptoPP::byte buf[key_size]) const
	{
		std::memcpy(buf, _key, CryptoPP::AES::DEFAULT_KEYLENGTH);
	}

} //namespace MessageU
