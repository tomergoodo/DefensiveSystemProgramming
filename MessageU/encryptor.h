/**
 * @author Tomer Goodovitch 213213838
 */
#pragma once

#include <string>
#include <cstddef>

#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"


#include "cryptopp/modes.h"
#include "cryptopp/aes.h"

namespace MessageU {
	class RSAPubKey
	{
	public:
		static constexpr int key_size_bits = 1024;
		static constexpr int key_size = 160;
	protected:
		CryptoPP::AutoSeededRandomPool rng;
		CryptoPP::RSA::PublicKey _public_key;
	public:
		RSAPubKey() = default;
		RSAPubKey(const uint8_t (&public_key)[key_size]);
		RSAPubKey(const std::string& base64);
		RSAPubKey(const CryptoPP::RSA::PublicKey& public_key);
		std::string encrypt(const std::string& plain);
		
		std::string encryptKey(uint8_t(&key)[CryptoPP::AES::DEFAULT_KEYLENGTH]);

		void GetPublicKey(CryptoPP::byte (&buf)[key_size]) const;
		CryptoPP::RSA::PublicKey GetPublicKey() const;
		void SetPublicKey(const uint8_t (&public_key)[key_size]);
		template<typename T>
		void SetPublicKey(const T& public_key);
		void SetPublicKey(const std::string& key);
		void SetPublicKey(const CryptoPP::RSA::PublicKey& public_key);
	private:
		void Base64s2PublicKey(const std::string& base64);
	};

	class EncryptorRSA : public RSAPubKey {
	private:
		CryptoPP::RSA::PrivateKey _private_key;
	public:
		EncryptorRSA();
		EncryptorRSA(const CryptoPP::RSA::PrivateKey& private_key);


		std::string decrypt(const std::string& cipher);

		std::string PrivateKey2Base64s() const;
		void Base64s2PrivateKey(const std::string& base64);

		void LoadPrivateKey(std::ifstream& file);
		void SavePrivateKey(std::ofstream& stream) const;
		
	private:
		void GenerateKeyPair();
	};


	class EncryptorAES {
	public:
		static constexpr int key_size = CryptoPP::AES::DEFAULT_KEYLENGTH;
	private:
		CryptoPP::byte _key[CryptoPP::AES::DEFAULT_KEYLENGTH];
		CryptoPP::byte _iv[CryptoPP::AES::BLOCKSIZE];

	public:
		EncryptorAES();
		
		std::string encrypt(const std::string& plain);
		std::string decrypt(const std::string& cipher);

		void GetKey(CryptoPP::byte buf[key_size]) const;
		void SetKey(const uint8_t (&key)[key_size]);
		
	private:
		char* GenerateKey(char* buff, size_t size);
	};
} // namespace MessageU
