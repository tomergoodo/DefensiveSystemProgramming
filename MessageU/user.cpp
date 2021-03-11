#include "user.h"

#include <cstdint>
#include <string>

#include "client.h"

namespace MessageU {
	User::User() : _uid{ 0 }, _key_exchanged(false), _valid_public_key(false) {}

	User::User(const std::string& name) : _uid{ 0 }, _name(name), _key_exchanged(false), _valid_public_key(false) {
		_name.resize(name_size, 0);
		_name.back() = 0; //null terminated
	}
	User::User(const std::string& name, const RSAPubKey& rsa_pub_key) : _uid{0}, _name(name), _RSA_pub_key(rsa_pub_key.GetPublicKey()), _key_exchanged(false), _valid_public_key(true)
	{
		_name.resize(name_size, 0);
		_name.back() = 0; //null terminated
	}
	User::User(const std::array<uint8_t, uid_size>& uid, const std::string& name) : _uid(uid), _name(name), _key_exchanged(false), _valid_public_key(false)
	{
		_name.resize(name_size, 0);
		_name.back() = 0; //null terminated
	}

	void User::SetUid(const std::array<uint8_t, uid_size>& uid) { _uid = uid; }
	void User::SetName(const std::string& name)
	{
		_name = name;
		_name.resize(name_size, 0);
		_name.back() = 0;
	}
	void User::SetSymmKey(const uint8_t (&key)[16]) {
		_key_exchanged = true;
		_AES_encryptor.SetKey(key);
	}
	void User::SetKeyExchange(bool exchanged)
	{
		_key_exchanged = exchanged;
	}
	std::array<uint8_t, User::uid_size> User::GetUid() const {
		return _uid;
	}
	std::string User::GetName() const {
		return _name;
	}


	void User::GetPublicKey(uint8_t (&buf)[pub_key_size]) const
	{
		_RSA_pub_key.GetPublicKey(buf);
	}
	

	std::string User::GetSymmKey()
	{
		uint8_t buf[sym_key_size];
		_AES_encryptor.GetKey(buf);
		return EncryptKey(buf);
	}
	bool User::GetKeyExchanged() const
	{
		return _key_exchanged;
	}
	bool User::isValidPublicKey() const
	{
		return _valid_public_key;
	}
	std::string User::decrypt(const std::string& cipher)
	{
		return _AES_encryptor.decrypt(cipher);
	}
	std::string User::encrypt(const std::string& text)
	{
		return _AES_encryptor.encrypt(text);
	}
	std::string User::EncryptKey(uint8_t(&key)[sym_key_size])
	{
		return _RSA_pub_key.encryptKey(key);
	}


} // namespace MessageU