#include "client.h"
#include "menu.h"
#include "protocol.h"

#include <iostream>
#include <vector>
#include <algorithm>
#include <fstream>
#include <array>
#include <memory>

#include "boost/asio.hpp"
#include "boost/algorithm/hex.hpp"
#include "boost/uuid/uuid.hpp"
#include "boost/uuid/uuid_io.hpp"
#include "boost/system/error_code.hpp"

namespace MessageU {

	Client::Client(const std::string& filename) :
		_version(version), io_context(1) ,_socket(std::make_shared<tcp::socket>(io_context)), _user(std::make_shared<User>())
	{
		std::tuple<std::string, int> ip_port = LoadAddr(filename);
		std::string host = std::get<0>(ip_port);
		int port = std::get<1>(ip_port);
		try {
			_socket->connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(host), port));
			this->ip = host;
			this->port = port;
		}
		catch (const boost::system::system_error& e) {
			std::cerr << "boost::asio::ip::tcp::socket::connect failed with " << e.what() << std::endl;
			exit(1);
		}

		LoadUserInfo();
		_user->SetRSAPublicKey(_encryptorRSA.GetPublicKey());
		_users.push_back(_user);
	}
	Client::Client(const std::string& host, int port) :
		_version(version), io_context(1), _socket(std::make_shared<tcp::socket>(io_context)), ip(host), port(port), _user(std::make_shared<User>()) {
		try {
			_socket->connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(host), port));
		}
		catch (const boost::system::system_error& e) {
			std::cerr << "boost::asio::ip::tcp::socket::connect failed with " << e.what() << std::endl;
			exit(1);
		}

		LoadUserInfo();
		_user->SetRSAPublicKey(_encryptorRSA.GetPublicKey());
		_users.push_back(_user);
	}

	void Client::Start() {
		Menu::Option option;
		do {
			Menu::PrintMenu();
			option = Menu::RecvOption();
			HandleOption(option);
		} while (option != Menu::Option::Exit);
	}

	void Client::Reconnect()
	{
		std::cout << "attempting to reconnect..." << std::endl;
		try
		{
			_socket->close();
			_socket.reset(new tcp::socket(io_context));
			_socket->connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(ip), port));
		}
		catch (const boost::system::system_error& ex)
		{
			std::cerr << "failed to reconnect " << ex.what() << std::endl;
		}
	}
	Client::~Client() {
		try {
			_socket->close();
		}
		catch (const boost::system::system_error& e) {
			std::cerr << "boost::asio::ip::tcp::socket::close failed with " << e.what() << std::endl;
		}
	}


	std::tuple<std::string, int> Client::LoadAddr(const std::string& filename)
	{
		std::ifstream file(filename, std::ifstream::in);
		if (file)
		{
			std::string data;
			std::getline(file, data);
			std::string ip = data.substr(0, data.find(':'));
			int port = atoi(data.substr(data.find(':') + 1, data.size()).c_str());
			file.close();
			return std::tuple<std::string, int>{ip, port};
		}
		else {
			std::cout << "Error opening " << filename << std::endl;
			exit(1);
		}

	}

	void Client::LoadUserInfo() {
		std::ifstream info("me.info", std::ifstream::in);
		if (info)
		{
			std::string input;
			std::getline(info, input);
			_user->SetName(input);
			std::getline(info, input);
			std::array<uint8_t, User::uid_size> uid;
			std::string decoded = boost::algorithm::unhex(input);
			std::copy(decoded.begin(), decoded.end(), uid.data());
			_user->SetUid(uid);
			_encryptorRSA.LoadPrivateKey(info);
		}
	}

	void Client::HandleOption(const Menu::Option option) {
		switch (option) {
		case Menu::Option::Register:
			Register();
			break;
		case Menu::Option::ClientList:
			ClientList();
			break;
		case Menu::Option::PubKey:
			PubKey();
			break;
		case Menu::Option::GetMsg:
			GetMsg();
			break;
		case Menu::Option::SendMsg:
			SendMsg();
			break;
		case Menu::Option::SendFile:
			SendFile();
			break;
		case Menu::Option::GetSymKey:
			GetSymKey();
			break;
		case Menu::Option::SendSymKey:
			SendSymKey();
			break;
		case Menu::Option::Exit:
			break;
		}
	}


	void Client::Register() {
		if (std::ifstream("me.info"))
		{
			std::cout << "user already exists" << std::endl;
			return;
		}
		std::string name;
		std::cout << "Enter your username" << std::endl;
		getline(std::cin, name);

		_user->SetName(name);


		protocol::request::Header header(protocol::request::Type::Register, User::name_size + EncryptorRSA::key_size);

		auto uinifiedbuffer = std::make_unique<uint8_t[]>(sizeof(header) + User::name_size + User::pub_key_size);
		std::memcpy(uinifiedbuffer.get(), &header, sizeof(header));
		std::memcpy(uinifiedbuffer.get() + sizeof(header), &_user->GetName()[0], User::name_size);
		uint8_t pub_key_buf[User::pub_key_size];
		_user->GetPublicKey(pub_key_buf);
		std::memcpy(uinifiedbuffer.get() + sizeof(header) + User::name_size, pub_key_buf, User::pub_key_size);

		Send(uinifiedbuffer.get(), sizeof(header) + User::name_size + User::pub_key_size);
		HandleRecv();
	}
	void Client::ClientList() {
		protocol::request::Header header(_user->GetUid().data(), protocol::request::Type::ClientList, 0);
		Send(header, "", 0);
		HandleRecv();
	}
	void Client::PubKey() {
		std::string name;
		std::cout << "Enter requested user" << std::endl;
		getline(std::cin, name);
		std::shared_ptr<User> user = FindUserByName(name);
		if (!user) {
			std::cout << "User " << name << " Not found" << std::endl;
			return;
		}

		protocol::request::Header header(_user->GetUid().data(), protocol::request::Type::PubKey, protocol::uid_size);
		Send(header, user->GetUid());
		HandleRecv();
	}
	void Client::GetMsg() {
		protocol::request::Header header(_user->GetUid().data(), protocol::request::Type::GetMsg, 0);
		Send(header, "", 0);
		HandleRecv();
	}
	void Client::SendMsg() {
		std::string name;
		std::cout << "Enter requested user" << std::endl;
		getline(std::cin, name);
		std::shared_ptr<User> user = FindUserByName(name);
		if (!user) {
			std::cout << "User " << name << " Not found" << std::endl;
			return;
		}
		if (!user->GetKeyExchanged())
		{
			std::cout << "Key was not exchanged with user " << name << std::endl;
			return;
		}
		std::string content;
		std::cout << "Enter message" << std::endl;
		getline(std::cin, content);
		std::string encrypted = user->encrypt(content);
		protocol::message::Header msg(user->GetUid().data(), protocol::message::Type::Text, encrypted.size());

		protocol::request::Header header(_user->GetUid().data(), protocol::request::Type::SendMsg, sizeof(msg) + msg._size);

		Send(header, msg, encrypted);
		HandleRecv();
	}
	void Client::SendFile()
	{
		std::string name;
		std::cout << "Enter requested user" << std::endl;
		getline(std::cin, name);
		std::shared_ptr<User> user = FindUserByName(name);
		if (!user) {
			std::cout << "User " << name << " Not found" << std::endl;
			return;
		}
		if (!user->GetKeyExchanged())
		{
			std::cout << "Key was not exchanged with user " << name << std::endl;
			return;
		}
		std::string filename;
		std::cout << "Enter full path to the file" << std::endl;
		getline(std::cin, filename);
		std::ifstream file(filename, std::ifstream::in | std::ifstream::binary);
		if (!file)
		{
			std::cout << "file not found" << std::endl;
			return;
		}
		std::string content;
		file.seekg(0, std::ifstream::end);
		content.reserve(file.tellg());
		file.seekg(0, std::ifstream::beg);
		content.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
		content = user->encrypt(content);
		protocol::message::Header msg(user->GetUid().data(), protocol::message::Type::File, content.size());
		protocol::request::Header header(_user->GetUid().data(), protocol::request::Type::SendMsg, sizeof(msg) + msg._size);
		Send(header, msg, content);
		HandleRecv();

	}
	void Client::GetSymKey() {
		std::string name;
		std::cout << "Enter requested user" << std::endl;
		getline(std::cin, name);
		std::shared_ptr<User> user = FindUserByName(name);
		if (!user) {
			std::cout << "User " << name << " Not found" << std::endl;
			return;
		}
		protocol::message::Header msg(user->GetUid().data(), protocol::message::Type::Get_sym_key, 0);

		protocol::request::Header header(_user->GetUid().data(), protocol::request::Type::SendMsg, sizeof(msg));

		Send(header, reinterpret_cast<char*>(&msg), sizeof(msg));
		HandleRecv();
	}
	void Client::SendSymKey() {
		std::string name;
		std::cout << "Enter requested user" << std::endl;
		getline(std::cin, name);
		std::shared_ptr<User> user = FindUserByName(name);
		if (!user) {
			std::cout << "User " << name << " Not found" << std::endl;
			return;
		}
		if (!user->isValidPublicKey())
		{
			std::cout << "We don't have " << name << " public key" << std::endl;
			return;
		}
		std::string key = user->GetSymmKey();
		protocol::message::Header msg(user->GetUid().data(), protocol::message::Type::Send_sym_key, key.size());
		protocol::request::Header header(_user->GetUid().data(), protocol::request::Type::SendMsg, sizeof(msg) + key.size());

		auto uinifiedbuffer = std::make_unique<uint8_t[]>(sizeof(header) + sizeof(msg) + key.size());
		std::memcpy(uinifiedbuffer.get(), &header, sizeof(header));
		std::memcpy(uinifiedbuffer.get() + sizeof(header), &msg, sizeof(msg));

		std::memcpy(uinifiedbuffer.get() + sizeof(header) + sizeof(msg), key.data(), key.size());

		Send(uinifiedbuffer.get(), sizeof(header) + sizeof(msg) + key.size()); //sizeof(unifiedbuffer.get())
		user->SetKeyExchange(true);
		HandleRecv();
	}


	void Client::Send(const uint8_t* payload, int size)
	{
		try
		{
			_socket->send(boost::asio::buffer(payload, size));
		}
		catch (const boost::system::system_error& e) {
			std::cerr << "boost::asio::ip::tcp::socket::send failed with " << e.what() << std::endl;
			Reconnect();
			try
			{
				_socket->send(boost::asio::buffer(payload, size));
			}
			catch (const boost::system::system_error& e) {
				std::cerr << "boost::asio::ip::tcp::socket::send failed with " << e.what() << std::endl;
			}
		}
	}
	void Client::Send(const protocol::request::Header& header, const char* payload, const int payload_size) {
		const char* buffer = reinterpret_cast<const char*>(&header);
		try {
			_socket->send(boost::asio::buffer(buffer, sizeof(header)));
			_socket->send(boost::asio::buffer(payload, payload_size));
		}
		catch (const boost::system::system_error& e) {
			std::cerr << "boost::asio::ip::tcp::socket::send failed with " << e.what() << std::endl;
			Reconnect();
			try {
				_socket->send(boost::asio::buffer(buffer, sizeof(header)));
				_socket->send(boost::asio::buffer(payload, payload_size));
			}
			catch (const boost::system::system_error& e) {
				std::cerr << "boost::asio::ip::tcp::socket::send failed with " << e.what() << std::endl;
			}
		}
	}

	template<typename T>
	void Client::Send(const protocol::request::Header& header, const T& payload) {
		const char* cHeader = reinterpret_cast<const char*>(&header);
		const char* cPayload = reinterpret_cast<const char*>(&payload);
		try
		{
			_socket->send(boost::asio::buffer(cHeader, sizeof(header)));
			_socket->send(boost::asio::buffer(cPayload, sizeof(payload)));
		}
		catch (const boost::system::system_error& e) {
			std::cerr << "boost::asio::ip::tcp::socket::send failed with " << e.what() << std::endl;
			Reconnect();
			try
			{
				_socket->send(boost::asio::buffer(cHeader, sizeof(header)));
				_socket->send(boost::asio::buffer(cPayload, sizeof(payload)));
			}
			catch (const boost::system::system_error& e) {
				std::cerr << "boost::asio::ip::tcp::socket::send failed with " << e.what() << std::endl;
			}
		}

	}
	template<typename T>
	void Client::Send(const protocol::request::Header& header, const T& payload, const std::string& content) {
		const char* cHeader = reinterpret_cast<const char*>(&header);
		const char* cPayload = reinterpret_cast<const char*>(&payload);
		try
		{
			_socket->send(boost::asio::buffer(cHeader, sizeof(header)));
			_socket->send(boost::asio::buffer(cPayload, sizeof(payload)));
			_socket->send(boost::asio::buffer(content, content.size()));
		}
		catch (const boost::system::system_error& e) {
			std::cerr << "boost::asio::ip::tcp::socket::send failed with " << e.what() << std::endl;
			Reconnect();
			try{
				_socket->send(boost::asio::buffer(cHeader, sizeof(header)));
				_socket->send(boost::asio::buffer(cPayload, sizeof(payload)));
				_socket->send(boost::asio::buffer(content, content.size()));
			}
			catch (const boost::system::system_error& e) {
				std::cerr << "boost::asio::ip::tcp::socket::send failed with " << e.what() << std::endl;
			}
		}
	}
	std::shared_ptr<User> Client::FindUserByName(std::string name)
	{
		name.resize(255, 0);
		for (std::shared_ptr<User> user : _users) {
			if (user->GetName() == name)
				return user;
		}
		return nullptr;
	}
	std::shared_ptr<User> Client::FindUserByUid(const std::array<uint8_t, User::uid_size>& uid)
	{
		for (std::shared_ptr<User> user : _users) {
			if (user->GetUid() == uid)
				return user;
		}
		return nullptr;
	}

	void Client::HandleRecv() {
		std::string data = Recv(sizeof(protocol::response::Header));
		protocol::response::Header header(data);

		switch (static_cast<protocol::response::Type>(header._opcode)) {
		case protocol::response::Type::Register:
			RecvRegister(header);
			WriteInfoFile();
			break;
		case protocol::response::Type::ClinetList:
			RecvClientList(header);
			break;
		case protocol::response::Type::PubKey:
			RecvPubKey(header);
			break;
		case protocol::response::Type::SendMsg:
			RecvSendMsg(header);
			break;
		case protocol::response::Type::GetMsg:
			RecvGetMsg(header);
			break;
		case protocol::response::Type::Error:
			std::cout << "server responded with an error" << std::endl;
			break;
		default:
			break;
		}
	}

	void Client::RecvRegister(const protocol::response::Header& header)
	{
		std::string data = Recv(header._size);
		std::array<uint8_t, User::uid_size> uid;
		std::copy_n(data.begin(), User::uid_size, uid.data());
		_user->SetUid(uid);
	}
	void Client::RecvClientList(const protocol::response::Header& header) {
		struct buffer
		{
			uint8_t uid[User::uid_size];
			uint8_t name[User::name_size];
		};

		std::string data = Recv(header._size);
		buffer* buf = reinterpret_cast<buffer*>(&data[0]);
		std::cout << "Client list:" << std::endl;
		for (int i = 0; i < data.size() / sizeof(buffer); i++)
		{
			if (FindUserByName(std::string(reinterpret_cast<char*>(buf[i].name))) == nullptr)
			{
				std::shared_ptr<User> user = std::make_shared<User>(ToArray(buf[i].uid), std::string(reinterpret_cast<char*>(buf[i].name)));
				_users.push_back(user);
			}
			std::cout << std::string(reinterpret_cast<char*>(buf[i].name)) << std::endl;
		}
		std::cout << std::endl;
	}
	void Client::RecvPubKey(const protocol::response::Header& header) {
		struct buffer
		{
			uint8_t uid[User::uid_size];
			uint8_t pubkey[EncryptorRSA::key_size];
		};
		std::string data = Recv(header._size);
		buffer* buf = reinterpret_cast<buffer*>(&data[0]);
		std::shared_ptr<User> user = FindUserByUid(ToArray(buf->uid));
		if (user != nullptr)
			user->SetRSAPublicKey(buf->pubkey);
	}
	void Client::RecvSendMsg(const protocol::response::Header& header)
	{
		std::string data = Recv(header._size);
	}
	void Client::RecvGetMsg(const protocol::response::Header& header)
	{
		std::string data = Recv(header._size);
		int size = data.size();
		char* p;
		auto* buf = reinterpret_cast<protocol::response::Message*>(&data[0]);
		if (!size) std::cout << "No waiting messages." << std::endl << std::endl;
		while (size)
		{
			std::string content(std::string(reinterpret_cast<char*>(buf->content), buf->size));
			HandleMessage(buf);
			size -= sizeof(protocol::response::Message);
			size -= buf->size;
			p = reinterpret_cast<char*>(buf);
			p += sizeof(protocol::response::Message);
			p += buf->size;
			buf = reinterpret_cast<protocol::response::Message*>(p);
		}
	}

	void Client::HandleMessage(protocol::response::Message* msg)
	{
		std::shared_ptr<User> user = FindUserByUid(ToArray(msg->uid));
		if (user != nullptr) {
			std::cout << "From: " << user->GetName() << std::endl;
		}
		else {
			std::cout << "From: " << "unknown" << std::endl;
		}
		std::cout << "Content:" << std::endl;
		std::string text;
		switch (static_cast<protocol::message::Type>(msg->type))
		{
		case protocol::message::Type::Text:
			if(user == nullptr)
			{
				std::cout << "Key was not exchanged with user unknown" << std::endl;
				break;
			}
			if (!user->GetKeyExchanged())
			{
				std::cout << "Key was not exchanged with user " << user->GetName() << std::endl;
				break;
			}
			text = std::string(reinterpret_cast<const char*>(msg->content), msg->size);
			try
			{
				std::cout << user->decrypt(text) << std::endl;
			}
			catch (const CryptoPP::InvalidCiphertext& ex) {
				std::cout << "couldn't decrypt message, most likely because it was wrongly encrypted (e.g with improper symmetric key)." << std::endl;
				break;
			}
			break;
		case protocol::message::Type::Get_sym_key:
			std::cout << "request for symmetric key" << std::endl;
			break;
		case protocol::message::Type::Send_sym_key:
			if (user == nullptr)
				break;
			try
			{
				std::string decrypted_key = DecryptKey(std::string(msg->content, msg->content + msg->size));
				uint8_t buf[User::sym_key_size];
				std::memcpy(buf, decrypted_key.data(), User::sym_key_size);
				user->SetSymmKey(buf);
			}
			catch (const CryptoPP::InvalidCiphertext& ex) {
				std::cout << "couldn't decrypt symmetric key, most likely because it was wrongly encrypted (e.g not with our public key)." << std::endl;
				break;
			}
			std::cout << "symmetric key received" << std::endl;
			break;
		case protocol::message::Type::File:
			if(user != nullptr)
				RecvFile(msg, user);
			break;
		default:
			std::cout << "message type error" << std::endl;
			break;
		}
		std::cout << "-----<EOM>-----" << std::endl;

	}
	void Client::RecvFile(protocol::response::Message* msg, std::shared_ptr<User> user)
	{
		constexpr int MAXBUFFER = 4096;
		CreateDirectoryA("receivedfiles", 0);
		std::string folder = "receivedfiles\\";
		boost::uuids::uuid u;
		std::memcpy(&u, msg->uid, User::uid_size);
		const std::string tmp = to_string(u);
		std::string filename = folder + tmp + "_" + std::to_string(msg->mid) + ".txt";
		std::ofstream file(filename, std::ofstream::out | std::ofstream::binary | std::ofstream::trunc);
		try
		{
			std::string content = user->decrypt(std::string(msg->content, msg->content + msg->size));
			if (file) {
				file << content;
			}
			else {
				std::cout << "failed to write file" << std::endl;
			}
			char fullname[MAXBUFFER];
			GetFullPathNameA(filename.c_str(), MAXBUFFER, fullname, NULL);
			std::cout << fullname << std::endl;
		}
		catch (const CryptoPP::InvalidCiphertext& ex) {
			std::cout << "couldn't decrypt content, most likely because it was wrongly encrypted (e.g with improper symmetric key)." << std::endl;
		}
		file.close();
	}


	std::string Client::Recv(const int size) {
		std::string data;
		data.resize(size, 0);
		try {
			_socket->receive(boost::asio::buffer(data, size));
		}
		catch (const boost::system::system_error& e) {
			std::cerr << "boost::asio::ip::tcp::socket::receive failed with " << e.what() << std::endl;
			Reconnect();
			try
			{
				_socket->receive(boost::asio::buffer(data, size));
			}
			catch (const boost::system::system_error& e) {
				std::cerr << "boost::asio::ip::tcp::socket::receive failed with " << e.what() << std::endl;
			}
		}
		return data;
	}

	std::string Client::DecryptKey(const std::string& key)
	{
		return _encryptorRSA.decrypt(key);
	}

	std::array<uint8_t, User::uid_size> Client::ToArray(const uint8_t(&uid)[User::uid_size])
	{
		std::array<uint8_t, User::uid_size> arr;
		std::copy_n(uid, User::uid_size, arr.data());
		return arr;
	}

	void Client::WriteInfoFile() const {
		std::ofstream file("me.info", std::ofstream::out | std::ofstream::trunc);

		file << _user->GetName() << std::endl;

		boost::algorithm::hex(_user->GetUid(), std::ostream_iterator<char>(file));

		file << std::endl;
		_encryptorRSA.SavePrivateKey(file);
		file.close();
	}

} // namespace MessageU



int main(int argc, char** argv) {
	
	MessageU::Client client("server.info");
	client.Start();
	return 0;
}
