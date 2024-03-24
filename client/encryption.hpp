#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include <string>
#include <cryptopp/rsa.h>
#include <cryptopp/aes.h>

class Encryption {
public:
    static CryptoPP::RSA::PrivateKey generateRSAKeyPair(int keyLength);
    static std::string rsaEncrypt(const std::string& plaintext, const CryptoPP::RSA::PublicKey& publicKey);
    static std::string rsaDecrypt(const std::string& ciphertext, const CryptoPP::RSA::PrivateKey& privateKey);
    static std::string aesEncrypt(const std::string& plaintext, const std::string& key, const std::string& iv);
    static std::string aesDecrypt(const std::string& ciphertext, const std::string& key, const std::string& iv);
};

#endif // ENCRYPTION_HPP
