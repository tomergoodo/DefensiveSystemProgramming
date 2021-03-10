/**
 * @author Tomer Goodovitch 213213838
 */
#pragma once
#include <cstdint>

namespace MessageU {
	namespace protocol {
		constexpr int uid_size = 16;

		namespace request {
			enum class Type { Register = 100, ClientList = 101, PubKey = 102, SendMsg = 103, GetMsg = 104 };

			#pragma pack(push, 1)
			struct Header {
				uint8_t _uid[uid_size];
				uint8_t _version;
				uint8_t _opcode;
				uint32_t _size;

				Header(Type opcode, const int32_t size) : _uid{ 0 }, _version(1), _opcode(static_cast<uint8_t>(opcode)), _size(size) {}
				Header(const uint8_t uid[uid_size], const Type opcode, const int32_t size) : _uid{ 0 }, _version(1), _opcode(static_cast<uint8_t>(opcode)), _size(size) {
					std::copy_n(uid, uid_size, _uid);
				}
			};
			#pragma pack(pop)
		} // namespace request

		namespace message {
			enum class Type : uint8_t{ Get_sym_key = 1, Send_sym_key = 2, Text = 3 , File = 4};

			#pragma pack(push, 1)
			struct Header {
				uint8_t _uid[uid_size];
				uint8_t _msg_type;
				uint32_t _size;
				uint8_t _content[0];
				
				Header(uint8_t uid[uid_size], Type msg_type, uint32_t size) :
					_uid{ 0 }, _msg_type(static_cast<uint8_t>(msg_type)), _size(size) {
					std::copy_n(uid, uid_size, _uid);
				}
			};
			#pragma pack(pop)
		} // namespace message

		namespace response {
			enum class Type : uint16_t { Register = 1000, ClinetList = 1001, PubKey = 1002, SendMsg = 1003, GetMsg = 1004, Error = 9000};

			#pragma pack(push, 1)
			struct Header {
				uint8_t _version;
				uint16_t _opcode;
				uint32_t _size;
				
				Header(const std::string& header) : _version(1), _opcode(0), _size(0) {
					std::memcpy(this, header.c_str(), sizeof(*this));
				}
			};
			#pragma pack(pop)
			
			#pragma pack(push, 1)
			struct Message
			{
				uint8_t uid[uid_size];
				uint32_t mid;
				uint8_t type;
				uint32_t size;
				uint8_t content[0];
			};
			#pragma pack(pop)
		} // namespace response

	} // namespace protocol

} // namespace MessageU