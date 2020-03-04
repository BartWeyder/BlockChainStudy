#include "SchoolboyCipher.h"

#include <algorithm>
#include <cctype>

namespace
{
   constexpr auto sc_bits = 26; ///< Symbols in out encoding.
   constexpr auto sc_aSymbolNumeric = 'a'; ///< Numeric value fror 'a' symbol
   constexpr auto sc_zSymbolNumeric = 'z'; ///< Numeric value for 'z' symbol
   constexpr auto sc_messageChunkSize = 4; ///< For convinience of cipher user we divide message by 4-symbol chunks

   /// @brief Returns random number between 0 and 25.
   unsigned char getRandomOffset()
   {
      return rand() % sc_bits;
   }

   /// @brief Transforms string to acceptable view for crypting.
   /// @param i_humanMessage in, String that user entered.
   /// @return String with only lower case English letters, other symbols converted to 'x'.
   std::string getMessageCode(std::string i_humanMessage)
   {
      std::transform(i_humanMessage.begin(), i_humanMessage.end(), i_humanMessage.begin(),
         [](unsigned char c)
         {
            const auto lower = std::tolower(c);
            return (lower < sc_aSymbolNumeric || lower > sc_zSymbolNumeric) ? 'x' : lower;
         });

      return i_humanMessage;
   }

   /// @brief Offsets symbol.
   /// @param i_symbol in, Symbol to offset.
   /// @param i_offset in, Offset.
   /// @return Offsetted (cycle-offsetted) symbol.
   char offsetSymbol(char i_symbol, unsigned char i_offset)
   {
      const auto offsetToZ = sc_zSymbolNumeric - i_symbol;
      return offsetToZ >= i_offset ? (i_symbol + i_offset) : (sc_aSymbolNumeric + (i_offset - offsetToZ));
   }

   /// @brief Reverses offset and returns human-entered symbol.
   /// @param i_symbol in, Symbol to unoffset.
   /// @param i_offset in, Offset.
   char unoffsetSymbol(char i_offsettedSymbol, unsigned char i_offset)
   {
      const auto offsetToA = i_offsettedSymbol - sc_aSymbolNumeric;
      return offsetToA >= i_offset ? (i_offsettedSymbol - i_offset) : (sc_zSymbolNumeric - (i_offset - offsetToA));
   }
} // namespace

///////////////////////////////////////////////////////////////////////////////////////////////////
std::pair<std::string, PrivateKey> CryptMessage(const std::string & i_message)
{
   // align message
   const auto modResult = i_message.size() % sc_messageChunkSize;
   const auto& message = getMessageCode(modResult == 0 ? i_message : i_message + std::string(modResult, 'x'));

   // crypt
   PrivateKey privateKey;
   std::string cryptedMessage;
   cryptedMessage.reserve(message.size());
   for (auto symbol : message)
   {
      const auto offset = getRandomOffset();
      privateKey.emplace_back(offset);
      cryptedMessage += offsetSymbol(symbol, offset);
   }

   return { cryptedMessage, privateKey };
}

///////////////////////////////////////////////////////////////////////////////////////////////////
std::string DecryptMessage(const std::string & i_cryptedMessage, const PrivateKey & i_key)
{
   std::string decryptedMessage;
   _ASSERT(i_cryptedMessage.size() == i_key.size());
   for (size_t i = 0; i < i_cryptedMessage.size(); ++i)
   {
      decryptedMessage += unoffsetSymbol(i_cryptedMessage[i], i_key[i]);
   }

   return decryptedMessage;
}
