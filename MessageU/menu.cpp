#include "menu.h"

#include <iostream>
#include <string>
#include <sstream>


namespace MessageU {
	namespace Menu {
		void PrintMenu() {
			std::cout << "MessageU client at your service." << std::endl;
			std::cout << "1) Register" << std::endl;
			std::cout << "2) Request for clients list" << std::endl;
			std::cout << "3) Request for public key" << std::endl;
			std::cout << "4) Request for waiting messages" << std::endl;
			std::cout << "5) Send a text message" << std::endl;
			std::cout << "51) Send a request for symmetric key" << std::endl;
			std::cout << "52) Send your symmetric key" << std::endl;
			std::cout << "0) Exit client" << std::endl;
			std::cout << "?" << std::endl;
		}

		Option RecvOption() {
			int n;
			std::string input;
			while (true) {
				getline(std::cin, input);
				std::stringstream stream(input);
				if (stream >> n)
					return static_cast<Option>(n);
				std::cout << "Invalid number, please try again" << std::endl;
			}
		}
	} // namespace Menu
} // namespace MessageU