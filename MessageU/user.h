#pragma once

#include <cstdint>
#include <string>
#include <array>

#include "encryptor.h"

namespace std {
	enum class byte : unsigned char;
}


namespace MessageU {

	class User {
	public:
		static constexpr int uid_size = 16;
		static constexpr int name_size = 255;
		static constexpr int pub_key_size = 160;
		static constexpr int sym_key_size = 128 / 8;
	private:
		std::array<uint8_t, uid_size> _uid;
		std::string _name;

		RSAPubKey _RSA_pub_key;
		EncryptorAES _AES_encryptor;
		bool _key_exchanged;
		bool _valid_public_key;
	public:
		User();
		User(const std::string& name);
		User(const std::string& name, const RSAPubKey& rsa_pub_key);
		User(const std::array<uint8_t, uid_size>& uid, const std::string& name);

		void SetName(const std::string& name);
		void SetUid(const std::array<uint8_t, uid_size>& uid);
		template<typename T> void SetRSAPublicKey(const T& public_key) {
			_RSA_pub_key.SetPublicKey(public_key);
			_valid_public_key = true;
		}
		void SetSymmKey(const uint8_t (&key)[sym_key_size]);
		void SetKeyExchange(bool exchanged);
		std::array<uint8_t, uid_size> GetUid() const;
		std::string GetName() const;
		void GetPublicKey(uint8_t (&buf)[pub_key_size]) const;
		std::string GetSymmKey();
		bool GetKeyExchanged() const;
		bool isValidPublicKey() const;
		std::string decrypt(const std::string& cipher);
		std::string encrypt(const std::string& text);
		std::string EncryptKey(uint8_t(&key)[sym_key_size]);

	};
} // namespace MessageU