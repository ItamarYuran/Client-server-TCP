#ifndef CLIENT_H
#define CLIENT_H

#include "encryption.hpp"
#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <fstream> 
#include <vector>
#include <cstring>
#include <cstdint>
#include <sstream>
#include <map>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <fstream>
#include <cmath>
#include <zlib.h>

constexpr uint32_t MAX_PAYLOAD_SIZE = 1024; 


struct Response {
    uint8_t version;
    uint16_t code;
    uint32_t payloadSize; // Add payload size
    std::vector<uint8_t> payloadData; // Store payload as raw bytes

    // Method to parse payload data into specific types
    template <typename T>
    T parsePayload(size_t offset = 0) const {
        T value;
        std::memcpy(&value, payloadData.data() + offset, sizeof(T));
        return value;
    }

    // Add fields for specific response codes
    std::string uuid;
    std::string encryptedKey;
    std::string fileName;
    uint32_t contentSize;
    uint32_t checksum;
};



class Client {
public:
    Client(boost::asio::io_context& io_context);

    void connect(const std::string& server_ip,int port);
    void sendRequest1025(const std::string& name);
    std::string receiveResponse();

    // Method to read user details from the file
    bool readUserInfoFromFile(const std::string& filename);
    void readInstructions(const std::string& filename);

    void signUp(const std::string& filename);
    void sendRequest(int requestCode, const std::string& requestData);

    bool userInfoIsEmpty() const;
    Response parseResponse(const std::string& responseData);
    std::string concatenateData(const std::vector<std::string>& data);

    void writeUsernameToFile(const std::string& username);
    void writeUuidToFile(const std::string& uuid);
    void writePrivateKeyToFile(const std::string& privateKey);


    std::string getUsername() const { return username_; }
    std::string getUuid() const { return uuid_; }
    std::string getPrivateKey() const { return privateKey_; }
    std::string getSymetricKey() const { return symetricKey_; }

    std::string getServerIP() const { return server_ip_; }
    int getPort() const { return port_; }
    std::string getFileToSend() const { return file_to_send_; }

    void setUsername(const std::string& username) { username_ = username; }
    void setUuid(const std::string& uuid) { uuid_ = uuid; }
    void setPrivateKey(const std::string& privateKey) { privateKey_ = privateKey; }
    void setSymetricKey(const std::string& symetricKey) { symetricKey_ = symetricKey; }
    void setServerIP(const std::string& server_ip) { server_ip_ = server_ip; }
    void setPort(int port) { port_ = port; }
    void setFileToSend(const std::string& file_to_send) { file_to_send_ = file_to_send; }
        
    void sendFileToServer();
    uint32_t compute_checksum(const std::string& data);




private:
    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::tcp::resolver resolver_;
    std::string server_ip_;
    int port_;

    // User details
    std::string file_to_send_;
    std::string username_;
    std::string uuid_;
    std::string privateKey_;
    std::string symetricKey_;


};
std::vector<uint8_t> hexToBytes(const std::string& hex);
std::string padString(const std::string& str, size_t desiredLength);
std::string unpadString(const std::string& str);
std::string bytesToHexString(const std::vector<uint8_t>& bytes);

#endif // CLIENT_H
