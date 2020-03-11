#pragma once

#include <array>
#include <string>

#include <cryptopp/config.h>

namespace BitcoinAddress
{
   inline constexpr auto PublicKeySize = 33; ///< Size of public key in bytes.
   using PublicKey = std::array<CryptoPP::byte, PublicKeySize>; ///< Type for public key.

   /// @brief Generates string with bitcoin address.
   /// @param i_publicKey in, Byte array with public-key.
   /// @return Generated Bitcoin-address string.
   std::string Generate(const PublicKey& i_publicKey);
}
