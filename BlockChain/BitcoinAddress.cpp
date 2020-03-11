#include "BitcoinAddress.h"

#include <cryptopp/sha.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/integer.h>

namespace
{
   constexpr CryptoPP::word base = 58; ///< base value for base58 encoding
   constexpr char alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; ///< alphabet of base-58

   static_assert(base <= sizeof(alphabet));

   /// @brief Encodes byte array to char string by Satoshi's base58 algorithm
   std::string base58Encode(const CryptoPP::byte* i_string, const size_t i_stringLenght)
   {
      using namespace CryptoPP;
      // Reserve string with 32 chars, it is possible that encoding will take more symbols,
      // but lets assume that in most cases it will not.
      std::string output;
      output.reserve(32);

      // get big int
      Integer bigInt(i_string, i_stringLenght);

      while (!bigInt.IsZero())
      {
         const auto reminder = bigInt.Modulo(base);
         bigInt = bigInt.DividedBy(base);
         output += alphabet[reminder];
      }

      // leading zero byte
      output += alphabet[0];

      std::reverse(output.begin(), output.end());

      return output;
   }
}

///////////////////////////////////////////////////////////////////////////////////////////////////
std::string BitcoinAddress::Generate(const PublicKey & i_publicKey)
{
   using namespace CryptoPP;

   // Make first sha-256 hash
   byte digest[SHA256::DIGESTSIZE];
   SHA256().CalculateDigest(digest, &i_publicKey[0], PublicKeySize);

   // We will allocate more space: 1 is for leading zero byte, 4 extra bytes to concatenate check-sum later.
   constexpr auto checkSumSize = 4;
   constexpr auto ripe160DigestArraySize = RIPEMD160::DIGESTSIZE + 1 + checkSumSize;
   byte ripe160Digest[ripe160DigestArraySize];
   // Hash with RIPEMD160, pass address with offset (first byte is for leading byte)
   RIPEMD160().CalculateDigest(ripe160Digest + 1, digest, SHA256::DIGESTSIZE);

   // Add leading zero byte
   ripe160Digest[0] = static_cast<byte>(0);

   // Hash result of RIPEMD160 by sha-256
   SHA256().CalculateDigest(digest, ripe160Digest, RIPEMD160::DIGESTSIZE + 1);

   // Hash one more time
   CryptoPP::byte digest2[SHA256::DIGESTSIZE];
   CryptoPP::SHA256().CalculateDigest(digest2, digest, SHA256::DIGESTSIZE);

   // concatenate first 4 bytes (check-sum) of last hash to ripe160 hash (with leading symbol one)
   // i is end-index to concatenate checksum in our ripe160 digest, j - beginning of our latest sha-256 digest 
   for (auto i = RIPEMD160::DIGESTSIZE + 1, j = 0; j < checkSumSize; ++i, ++j)
   {
      ripe160Digest[i] = digest2[j];
   }

   // return result of base58 encoding
   return base58Encode(ripe160Digest, RIPEMD160::DIGESTSIZE + 1 + 4);
}
