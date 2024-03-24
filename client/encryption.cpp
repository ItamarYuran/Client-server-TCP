#include "encryption.hpp"
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>

using namespace CryptoPP;

RSA::PrivateKey Encryption::generateRSAKeyPair(int keyLength) {
    AutoSeededRandomPool rng;
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, keyLength);
    return privateKey;
}

std::string Encryption::rsaEncrypt(const std::string& plaintext, const RSA::PublicKey& publicKey) {
    std::string encryptedData;

    AutoSeededRandomPool rng; // Create a random number generator
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    StringSource(plaintext, true, new PK_EncryptorFilter(rng, encryptor, new StringSink(encryptedData)));

    return encryptedData;
}

std::string Encryption::rsaDecrypt(const std::string& ciphertext, const RSA::PrivateKey& privateKey) {
    std::string decryptedData;

    AutoSeededRandomPool rng; // Create a random number generator
    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    StringSource(ciphertext, true, new PK_DecryptorFilter(rng, decryptor, new StringSink(decryptedData)));

    return decryptedData;
}

std::string Encryption::aesEncrypt(const std::string& plaintext, const std::string& key, const std::string& iv) {
    std::string encryptedData;

    CBC_Mode<AES>::Encryption encryptor((byte *)key.c_str(), key.length(), (byte *)iv.c_str());
    StringSource(plaintext, true, new StreamTransformationFilter(encryptor, new StringSink(encryptedData)));

    return encryptedData;
}

std::string Encryption::aesDecrypt(const std::string& ciphertext, const std::string& key, const std::string& iv) {
    std::string decryptedData;

    CBC_Mode<AES>::Decryption decryptor((byte *)key.c_str(), key.length(), (byte *)iv.c_str());
    StringSource(ciphertext, true, new StreamTransformationFilter(decryptor, new StringSink(decryptedData)));

    return decryptedData;
}
