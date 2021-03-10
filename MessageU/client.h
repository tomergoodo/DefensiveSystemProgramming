/**
 * @author Tomer Goodovitch 213213838
 */
#pragma once

#include <vector>
#include <memory>

#include "boost/asio.hpp"

#include "menu.h"
#include "protocol.h"
#include "user.h"
#include "encryptor.h"

namespace MessageU {
	using boost::asio::ip::tcp;

	class Client {
	public:
		static constexpr int version = 2;
		static constexpr int private_key_size = 160;

	private:
		int _version;
		tcp::socket _socket;

		std::shared_ptr<User> _user; //self
		std::vector<std::shared_ptr<User>> _users;

		EncryptorRSA _encryptorRSA;
	
	public:
		Client(boost::asio::io_context& io_context, const std::string& filename);
		Client(boost::asio::io_context& io_context, const std::string& host, int port);

		void Start();
		~Client();
	private:
		static std::tuple<std::string, int> LoadAddr(const std::string& filename);
		void LoadUserInfo();
		
		void HandleOption(Menu::Option option);

		void Register();
		void ClientList();
		void PubKey();
		void GetMsg();
		void SendMsg();
		void SendFile();
		void GetSymKey();
		void SendSymKey();

		std::shared_ptr<User> FindUserByName(std::string name);
		std::shared_ptr<User> FindUserByUid(const std::array<uint8_t, User::uid_size>& uid);
		
		void Send(const uint8_t* payload, int size);
		void Send(const protocol::request::Header& header, const char* payload, int payload_size);
		template<typename T> void Send(const protocol::request::Header& header, const T& payload);
		template<typename T> void Send(const protocol::request::Header& header, const T& payload, const std::string& content);

		void HandleRecv();

		void RecvRegister(const protocol::response::Header& header);
		void RecvClientList(const protocol::response::Header& header);
		void RecvPubKey(const protocol::response::Header& header);
		void RecvGetMsg(const protocol::response::Header& header);
		void RecvSendMsg(const protocol::response::Header& header);
		void HandleMessage(protocol::response::Message* msg);
		void RecvFile(protocol::response::Message* msg, std::shared_ptr<User> user);

		std::string Recv(int size);

		static std::array<uint8_t, User::uid_size> ToArray(const uint8_t (&uid)[User::uid_size]);

		void WriteInfoFile() const;
		

		std::string DecryptKey(const std::string& key);
		
	};

} // namespace MessageU