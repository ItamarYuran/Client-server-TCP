#include "encryption.hpp"
#include <cryptopp/rsa.h>
#include <cryptopp/oaep.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/base64.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <iostream>
#include <string>
#include <iomanip>  // For std::hex and std::setw
#include <sstream>  // For std::ostringstream
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include "hex.h"
#include "filters.h"



using namespace CryptoPP;

std::string base64_decode(const std::string& encoded_text) {
    std::string decoded_text;
    CryptoPP::StringSource(encoded_text, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(decoded_text)
        )
    );
    return decoded_text;
}


RSA::PrivateKey Encryption::generateRSAKeyPair(int keyLength) {
    AutoSeededRandomPool rng;
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, keyLength);
    return privateKey;
}

std::string Encryption::rsaEncrypt(const std::string& plaintext, const RSA::PublicKey& publicKey) {
    std::string encryptedData;

    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    StringSource(plaintext, true, new PK_EncryptorFilter(rng, encryptor, new StringSink(encryptedData)));

    return encryptedData;
}



std::string Encryption::rsaDecrypt(const std::string& ciphertext, const RSA::PrivateKey& privateKey) {
    std::string decryptedData;

    try {
        // Decode the base64-encoded ciphertext
        std::string decodedCiphertext;
        StringSource(ciphertext, true, new Base64Decoder(new StringSink(decodedCiphertext)));

        // Create a decryption cipher
        RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

        // Initialize the random number generator
        AutoSeededRandomPool rng;

        // Decrypt the ciphertext
        StringSource(decodedCiphertext, true, new PK_DecryptorFilter(rng, decryptor, new StringSink(decryptedData)));
    } catch (const Exception& ex) {
        std::cerr << "Error occurred during decryption: " << ex.what() << std::endl;
        return "";
    }

    // Convert decrypted data to hexadecimal string format
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : decryptedData) {
        oss << std::setw(2) << static_cast<unsigned>(c);
    }

    return oss.str();
}
std::string Encryption::aesEncrypt(const std::string& plaintext, const std::string& keyHex) {
    // Check if the key length is correct (AES-256 requires a 32-byte key)
    if (keyHex.size() != AES::MAX_KEYLENGTH * 2) {
        std::cerr << "Invalid key length" << std::endl;
        exit(1);
    }

    SecByteBlock key, iv;
    HexDecoder decoder;

    // Convert key from hex to SecByteBlock
    decoder.Put((byte*)keyHex.data(), keyHex.size());
    decoder.MessageEnd();
    key.resize(AES::MAX_KEYLENGTH); // Resize key to correct length
    decoder.Get(key, key.size());
    
    // Initialize IV to zeros
    iv.resize(AES::BLOCKSIZE);
    memset(iv, 0x00, AES::BLOCKSIZE);

    std::string ciphertext;

    try {
        CBC_Mode< AES >::Encryption encryptor;
        encryptor.SetKeyWithIV(key, key.size(), iv);

        StringSource(plaintext, true, 
            new StreamTransformationFilter(encryptor,
                new HexEncoder(new StringSink(ciphertext)),
                StreamTransformationFilter::PKCS_PADDING
            )
        );
    } catch(const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    return ciphertext;
}
std::string Encryption::aesDecrypt(const std::string& ciphertext, const std::string& keyHex) {
    // Check if the key length is correct (AES-256 requires a 32-byte key)
    if (keyHex.size() != 2 * AES::MAX_KEYLENGTH) {
        std::cerr << "Invalid key length" << std::endl;
        exit(1);
    }

    SecByteBlock key, iv;
    HexDecoder decoder;

    // Convert key from hex to SecByteBlock
    decoder.Put((byte*)keyHex.data(), keyHex.size());
    decoder.MessageEnd();
    key.resize(AES::MAX_KEYLENGTH); // Resize key to correct length
    decoder.Get(key, key.size());

    // Initialize IV to zeros
    iv.resize(AES::BLOCKSIZE);
    memset(iv, 0x00, AES::BLOCKSIZE);

    std::string recovered;

    try {
        CBC_Mode< AES >::Decryption decryptor;
        decryptor.SetKeyWithIV(key, key.size(), iv);

        StringSource(ciphertext, true, 
            new HexDecoder(
                new StreamTransformationFilter(decryptor,
                    new StringSink(recovered)
                )
            )
        );
    } catch(const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    return recovered;
}


std::string Encryption::extractPublicKeyBytes(const std::string& publicKeyStr) {
    ByteQueue publicKeyQueue;
    publicKeyQueue.Put((const byte*)publicKeyStr.data(), publicKeyStr.size());

    Base64Decoder base64Decoder;
    base64Decoder.Attach(new Redirector(publicKeyQueue));
    base64Decoder.MessageEnd();

    RSA::PublicKey publicKey;
    publicKey.Load(publicKeyQueue);

    ByteQueue serializedKey;
    publicKey.DEREncode(serializedKey);

    RSAES<OAEP<SHA1>>::PublicKey rsaPubKey; // Changed SHA to SHA1
    rsaPubKey.BERDecodePublicKey(serializedKey, false, serializedKey.MaxRetrievable());

    Integer modulus = rsaPubKey.GetModulus();
    Integer exponent = rsaPubKey.GetPublicExponent();

    size_t modulusSize = modulus.MinEncodedSize();
    size_t exponentSize = exponent.MinEncodedSize();
    std::string modulusBytes(modulusSize, 0);
    std::string exponentBytes(exponentSize, 0);
    modulus.Encode((byte*)modulusBytes.data(), modulusSize);
    exponent.Encode((byte*)exponentBytes.data(), exponentSize);

    modulusBytes += exponentBytes;

    return modulusBytes;
}

SecByteBlock Encryption::hexToSecByteBlock(const std::string& hexKey) {
    HexDecoder decoder;
    SecByteBlock key;

    // Convert hex key to SecByteBlock
    decoder.Put((byte*)hexKey.data(), hexKey.size());
    decoder.MessageEnd();
    decoder.Get(key, key.size());

    return key;
}

std::string Encryption::hexToBinary(const std::string& hexString) {
    std::string result;
    CryptoPP::HexDecoder decoder;
    decoder.Put((CryptoPP::byte*)hexString.data(), hexString.size());
    decoder.MessageEnd();

    size_t size = decoder.MaxRetrievable();
    if(size)
    {
        result.resize(size);
        decoder.Get((CryptoPP::byte*)result.data(), result.size());
    }
    return result;
}
std::string Encryption::generateRandomKey() {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::SecByteBlock key(32); // 256 bits key
    rng.GenerateBlock(key, key.size());
    std::string encoded;
    CryptoPP::HexEncoder encoder;
    encoder.Attach(new CryptoPP::StringSink(encoded));
    encoder.Put(key, key.size());
    encoder.MessageEnd();
    return encoded;
}