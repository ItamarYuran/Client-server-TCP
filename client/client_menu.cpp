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
#include <vector>




using namespace std;
using namespace CryptoPP;

void displayMenu() {
    cout << "Menu:" << endl;
    cout << "[1] Send server public key" << endl;
    cout << "[2] Reconnect" << endl;
    cout << "[3] Send server file" << endl;
    cout << "[4] Exit" << endl;
    cout << "Enter your choice: ";
}

int main() {
    try {
        boost::asio::io_context io_context;
        
        Client client(io_context);
        client.readInstructions("transfer.info");
        client.connect(client.getServerIP(),client.getPort());

        if (client.readUserInfoFromFile("me.info") == false){
            client.readInstructions("transfer.info");
            uint16_t code = 1025;
            std::cout<<"usr"<<client.getUsername()<<std::endl;
            client.sendRequest(code, client.getUsername());
            std::string res;
            std::cout<<"here"<<std::endl;
            res = client.receiveResponse();
            std::cout<<"here"<<std::endl;
            Response response = client.parseResponse(res);
            std::cout<<"here"<<response.uuid<<std::endl;
            client.setUuid(bytesToHexString(std::vector<uint8_t>(response.uuid.begin(), response.uuid.end())));
            client.writeUuidToFile(client.getUuid());
            std::cout<< "Client signd up"<<endl;

        }
        std::cout<< "uuid: "<<client.getUuid()<<endl;
        std::cout<< "username : "<<client.getUsername()<<endl;
        std::cout<< "privaate key: "<<client.getPrivateKey()<<endl;

        int choice;
        bool signedUp = client.userInfoIsEmpty();

        while (true) {
            displayMenu();
            cin >> choice;

            switch (choice) {
                    case 1:
                    {
uint16_t code = 1026;
// Generate RSA key pair
RSA::PrivateKey rsaPrivateKey;
RSA::PublicKey rsaPublicKey;
AutoSeededRandomPool rng;

rsaPrivateKey.GenerateRandomWithKeySize(rng, 1024);
rsaPublicKey = RSA::PublicKey(rsaPrivateKey);

std::cout << "RSA Key Pair Generated" << std::endl;


// Serialize the public key into a string
std::string publicKeyStr;
StringSink sink(publicKeyStr);
rsaPublicKey.DEREncode(sink);
#include <cryptopp/base64.h>

std::string publicKeyBase64;
StringSource(publicKeyStr, true,new CryptoPP::Base64Encoder(new StringSink(publicKeyBase64),false )
);

std::cout << "Public Key Serialized (Base64): " << publicKeyBase64 << std::endl;

//std::cout << "Public Key Serialized: " << publicKeyStr << std::endl;

std::string privateKeyStr;
StringSink sinkPrivate(privateKeyStr);
rsaPrivateKey.DEREncode(sinkPrivate);

std::string privateKeyBase64;
StringSource(privateKeyStr, true, new CryptoPP::Base64Encoder(new StringSink(privateKeyBase64),false)
);

std::cout << "Praivate Key Serialized (Base64): " << privateKeyBase64 << std::endl;


//std::cout << "Private Key Serialized: " << privateKeyStr << std::endl;

client.writePrivateKeyToFile(privateKeyBase64);
std::cout << "Private Key Written to File" << std::endl;

client.setPrivateKey(privateKeyBase64);
std::cout << "Private Key Set in Client" << std::endl;

std::string padname = padString(client.getUsername(), 255);
std::cout << "Padded Username: " << padname << std::endl;

std::vector<std::string> inputData = {padname, publicKeyStr};
std::string req = client.concatenateData(inputData);

client.sendRequest(code, req);
std::cout << "Request Sent" << std::endl;

std::string responseData = client.receiveResponse();
std::cout<< "responseData: "<<responseData<<endl;
Response response = client.parseResponse(responseData);

// Step 3: Access the fields of the Response object
std::cout << "Version: " << static_cast<int>(response.version) << std::endl;
std::cout << "Code: " << response.code << std::endl;
std::cout << "payloadsize: " << response.payloadSize << std::endl;



std::cout << "encryptedkey: " << client.getPrivateKey() << std::endl;

std::string decrypted_symetric = Encryption::rsaDecrypt(response.encryptedKey, rsaPrivateKey);
std::cout << "un encryptedkey: " << decrypted_symetric << std::endl;
client.setSymetricKey(decrypted_symetric);


std::cout << std::endl;

                    }
                    break; // Don't forget to add a break statement after each case block
                    case 2:
                    {
                    uint16_t code = 1028;
                    std::string req = "heyyyyyy itamar ata hamelech i love you cen yas allllllo";
                    std::cout<<"key   "<<client.getPrivateKey()<<endl;
                    std::string enc = Encryption::aesEncrypt(req,client.getSymetricKey());
                    std::string dec = Encryption::aesDecrypt(enc,client.getSymetricKey());
                    std::cout<<"encrypted message "<<enc<<endl;
                    //std::cout<<"dec "<<dec<<endl;
                    client.sendRequest(code, enc);
                    std::cout<<"symetric key "<<client.getSymetricKey()<<endl;

                    std::string responseData = client.receiveResponse();
                    std::cout<<"responseData"<<std::endl;

                    // Step 2: Parse the response data
                    Response response = client.parseResponse(responseData);
                    std::cout<<"response.uuid"<<std::endl;





                    }
                    break; // Don't forget to add a break statement after each case block

                case 3:
                    {
                    client.sendFileToServer();
                    std::string responseData = client.receiveResponse();
                    Response response = client.parseResponse(responseData);
                    std::cout<<"file Name: " <<response.fileName<<std::endl;
                    std::cout<<"check sum: " <<response.checksum<<std::endl;

                    }
                    break;

                case 4:
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
