#ifndef CLIENT_H
#define CLIENT_H

#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <fstream> // Include this for file I/O

class Client {
public:
    Client(boost::asio::io_context& io_context, const std::string& server_ip, int port)
        : socket_(io_context), resolver_(io_context), server_ip_(server_ip), port_(port) {}

    void connect();
    void sendRequest1025(const std::string& name);
    std::string receiveResponse();

    // Method to read user details from the file
    void readUserInfoFromFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            throw std::runtime_error("File not found: " + filename);
        }
        std::getline(file, username_);
        std::getline(file, uuid_);
        std::getline(file, privateKey_);
    }

    // Method to prompt user to sign up and write details to the file
    void signUp(const std::string& filename) {
        std::ofstream file(filename);
        if (!file.is_open()) {
            throw std::runtime_error("Unable to create file: " + filename);
        }
        std::cout << "Enter username: ";
        std::getline(std::cin >> std::ws, username_);
        std::cout << "Enter UUID: ";
        std::getline(std::cin >> std::ws, uuid_);
        std::cout << "Enter private key: ";
        std::getline(std::cin >> std::ws, privateKey_);
        file << username_ << '\n' << uuid_ << '\n' << privateKey_ << '\n';
        std::cout << "Signed up successfully!" << std::endl;
    }

private:
    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::tcp::resolver resolver_;
    std::string server_ip_;
    int port_;

    // User details
    std::string username_;
    std::string uuid_;
    std::string privateKey_;
};

#endif // CLIENT_H
