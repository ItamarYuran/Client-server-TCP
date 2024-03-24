#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <fstream>
#include "client.hpp"
#include "encryption.hpp"
#include <cryptopp/rsa.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h> 



using namespace std;
using namespace CryptoPP;

void displayMenu() {
    cout << "Menu:" << endl;
    cout << "[1] Sign up" << endl;
    cout << "[2] Send server public key" << endl;
    cout << "[3] Reconnect" << endl;
    cout << "[4] Send server file" << endl;
    cout << "[5] Exit" << endl;
    cout << "Enter your choice: ";
}

int main() {
    try {
        // Your existing code for connecting to the server
        boost::asio::io_context io_context;
        std::string server_ip = "127.0.0.1"; // Replace with the actual server IP
        int port = 1299; // Replace with the actual port
        Client client(io_context, server_ip, port);
        client.connect();

        int choice;
        bool signedUp = false; // Flag to track if the user has signed up

        while (true) {
            displayMenu();
            cin >> choice;

            switch (choice) {
                case 1:
                    if (!signedUp) {
                        // Your existing code for signing up
                        client.signUp("user_details.txt"); // Assuming the file name is "user_details.txt"
                        signedUp = true;
                    } else {
                        cout << "You have already signed up." << endl;
                    }
                    break;
                    case 2:
                    {
                        // Generate RSA key pair
                        RSA::PrivateKey rsaPrivateKey;
                        RSA::PublicKey rsaPublicKey;
                        AutoSeededRandomPool rng;

                        rsaPrivateKey.GenerateRandomWithKeySize(rng, 2048);
                        rsaPublicKey = RSA::PublicKey(rsaPrivateKey);

                        // Serialize and send public key to the server
                        std::string publicKeyStr;
                        StringSink sink(publicKeyStr);
                        rsaPublicKey.DEREncode(sink);

                        // Print the public key
                        std::cout << "Public Key: " << publicKeyStr << std::endl;

                        // Serialize and send private key to the server (if needed)
                        std::string privateKeyStr;
                        StringSink sinkPrivate(privateKeyStr);
                        rsaPrivateKey.DEREncode(sinkPrivate);

                        // Print the private key
                        std::cout << "Private Key: " << privateKeyStr << std::endl;

                        // Your code to send publicKeyStr and privateKeyStr to the server
                    }
                    break; // Don't forget to add a break statement after each case block
                    case 3:
                    {
                        // Message to encrypt
                        std::string message = "This is a secret message for encryption and decryption.";

                        // AES key and IV (Initialization Vector)
                        std::string aesKey = "0123456789abcdef"; // 128-bit key
                        std::string iv = "abcdef9876543210";     // 128-bit IV

                        // Encrypt the message using AES
                        std::string encryptedMessage = Encryption::aesEncrypt(message, aesKey, iv);

                        // Print the encrypted message
                        std::cout << "Encrypted Message: " << encryptedMessage << std::endl;

                        // Decrypt the message using AES
                        std::string decryptedMessage = Encryption::aesDecrypt(encryptedMessage, aesKey, iv);

                        // Print the decrypted message
                        std::cout << "Decrypted Message: " << decryptedMessage << std::endl;
                    }
                    break; // Don't forget to add a break statement after each case block

                case 4:
                    // Implement sending server file
                    break;
                case 5:
                    cout << "Exiting program." << endl;
                    return 0;
                default:
                    cout << "Invalid choice. Please enter a number between 1 and 5." << endl;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    return 0;
}
