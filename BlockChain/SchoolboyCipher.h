#pragma once
#include <string>
#include <vector>

using PrivateKey = std::vector<unsigned char>; ///< We store private key as vector of offsets

/// @brief Crypts message string by 26 bit encoding
/// @param i_message in, Message to crypt.
/// @return Crypted string and private key.
std::pair<std::string, PrivateKey> CryptMessage(const std::string& i_message);

/// @brief Decrypts message by provided private key.
/// @param i_cryptedMessage in, Crypted message.
/// @param i_key in, Key to decrypt message.
/// @return Original message.
std::string DecryptMessage(const std::string& i_cryptedMessage, const PrivateKey& i_key);
