/**
 * @author Tomer Goodovitch 213213838
 */
#pragma once

namespace MessageU {

	namespace Menu {
		enum class Option { Exit = 0, Register = 1, ClientList = 2, PubKey = 3, GetMsg = 4, SendMsg = 5, SendFile = 50, GetSymKey = 51, SendSymKey = 52 };

		void PrintMenu();
		Option RecvOption();
	} // namespace Menu
} // namespace MessageU