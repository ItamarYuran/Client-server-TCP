#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include <string>
#include <cryptopp/rsa.h> // Include Crypto++ RSA header
#include <cryptopp/oaep.h> // Include Crypto++ OAEP header
#include <cryptopp/sha.h>  // Include Crypto++ SHA header
#include "cryptlib.h"

class Encryption {
public:

    static std::string generateRandomKey();
    static CryptoPP::RSA::PrivateKey generateRSAKeyPair(int keyLength);
    static std::string rsaEncrypt(const std::string& plaintext, const CryptoPP::RSA::PublicKey& publicKey);
    static std::string rsaDecrypt(const std::string& ciphertext, const CryptoPP::RSA::PrivateKey& privateKey);
    static std::string aesEncrypt(const std::string& plaintext, const std::string& keyHex);
    static std::string aesDecrypt(const std::string& ciphertext, const std::string& keyHex);
    static std::string extractPublicKeyBytes(const std::string& publicKeyStr);
    static std::string hexToBinary(const std::string& hexString);
    static CryptoPP::SecByteBlock hexToSecByteBlock(const std::string& hexKey);



};
    static std::string base64_decode(const std::string& encoded_text);

#endif // ENCRYPTION_HPP
