#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <fstream> 

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

void Client::connect() {
    boost::asio::ip::tcp::resolver::results_type endpoints = resolver_.resolve(server_ip_, std::to_string(port_));
    boost::asio::connect(socket_, endpoints);
}

void Client::sendRequest1025(const std::string& name) {
    std::string header;
    header.resize(23);
    std::fill(header.begin(), header.end(), 0); 
    header[16] = 24; 
    header[17] = 0; 
    header[18] = 4; 
    header[19] = 1; 
    header[20] = 0; 
    header[21] = 0; 
    header[22] = 0; 
    header[23] = 0; 
    
    std::string payload;
    payload.resize(255);
    std::fill(payload.begin(), payload.end(), 0); 
    std::copy(name.begin(), name.end(), payload.begin()); 

    uint32_t payload_size = payload.size();
    std::string payload_size_bytes(reinterpret_cast<const char*>(&payload_size), sizeof(payload_size));

    std::string packet = header + payload_size_bytes + payload;

    boost::asio::write(socket_, boost::asio::buffer(packet));
}

std::string Client::receiveResponse() {
    boost::array<char, 1024> buffer;
    boost::system::error_code error;
    size_t length = socket_.read_some(boost::asio::buffer(buffer), error);
    if (error == boost::asio::error::eof) {
        return ""; 
    } else if (error) {
        throw boost::system::system_error(error); 
    }
    return std::string(buffer.data(), length);
}


// int main() {
//     try {
//         boost::asio::io_context io_context;
//         std::string server_ip = "127.0.0.1"; // Replace with the actual server IP
//         int port = 1299; // Replace with the actual port
//         Client client(io_context, server_ip, port);
//         client.connect();

//         std::string name;
//         std::cout << "Enter your name: ";
//         std::cin >> name;

//         client.sendRequest1025(name);

//         std::string response = client.receiveResponse();
//         std::cout << "Response from server: " << response << std::endl;
//     } catch (const std::exception& e) {
//         std::cerr << "Exception: " << e.what() << std::endl;
//     }
//     return 0;
// }
