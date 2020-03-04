// BlockChain.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

#include "SchoolboyCipher.h"

int main()
{
   constexpr auto initialMessage = "Hello World!";
   std::cout << "Input message: \"" << initialMessage << '\"' << std::endl;

   // Crypt message
   const auto&[cryptedMessage, privateKey] = CryptMessage(initialMessage);

   // output crypted
   std::cout << "Crypted message: \"" << cryptedMessage << '\"' << std::endl;

   // output key
   std::cout << "Private key: ";
   for (auto ch : privateKey)
   {
      std::cout << static_cast<std::uint16_t>(ch) << ' ';
   }
   std::cout << std::endl;

   // Decrypt and output
   std::cout << "Decrypted: \"" <<  DecryptMessage(cryptedMessage, privateKey) << '\"' << std::endl;
}
