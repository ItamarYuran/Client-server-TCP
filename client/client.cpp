#include "client.hpp" 
using namespace std;
using namespace CryptoPP;

Client::Client(boost::asio::io_context& io_context)
    : socket_(io_context), resolver_(io_context) {
}

void Client::readInstructions(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return;
    }

    std::string line;
    if (std::getline(file, line)) {
        std::stringstream ss(line);
        std::getline(ss, server_ip_, ':');
        ss >> port_;
    }

    std::getline(file, username_);
    std::getline(file, file_to_send_);

    file.close();
}

void Client::connect(const std::string& server_ip,int port) {
    boost::asio::ip::tcp::resolver::results_type endpoints = resolver_.resolve(server_ip, std::to_string(port));
    boost::asio::connect(socket_, endpoints);
}

void Client::sendRequest(int requestCode, const std::string& requestData) {

    std::string header(23, 0); // 23 bytes header
    std::memcpy(&header[0], uuid_.c_str(), std::min(uuid_.size(), static_cast<size_t>(16)));
    header[16] = 24; // Version
    header[17] = requestCode & 0xFF; 
    header[18] = (requestCode >> 8) & 0xFF; 
    uint32_t payloadSize = requestData.size();

    // Fill payload size bytes in the header (big-endian)
    header[19] = payloadSize & 0xFF;
    header[20] = (payloadSize >> 8) & 0xFF;
    header[21] = (payloadSize >> 16) & 0xFF;
    header[22] = (payloadSize >> 24) & 0xFF;

    std::string packet = header + requestData;
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

std::string Client::concatenateData(const std::vector<std::string>& data) {
    std::ostringstream oss;
    for (const std::string& str : data) {
        oss << str; 
    }
    return oss.str();
}

bool Client::readUserInfoFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return false;
    }

    std::string line;
    if (!std::getline(file, username_) ||
        !std::getline(file, uuid_) ||
        !std::getline(file, privateKey_)) {
        // If any of the lines are missing, set all fields to empty
        username_ = "";
        uuid_ = "";
        privateKey_ = "";
        file.close();
        return false;
    }

    file.close();
    return true;
}


bool Client::userInfoIsEmpty() const {
    return !(username_.empty() || uuid_.empty() || privateKey_.empty());
}


Response Client::parseResponse(const std::string& responseData) {
    Response response;

    // Parse the response data and populate the struct fields
    response.version = responseData[0];
    response.code = (responseData[2] << 8) | responseData[1];

response.payloadSize = (static_cast<uint8_t>(responseData[6]) << 24) |
                        (static_cast<uint8_t>(responseData[5]) << 16) |
                        (static_cast<uint8_t>(responseData[4]) << 8) |
                        static_cast<uint8_t>(responseData[3]);

    response.payloadData.assign(responseData.begin() + 7, responseData.end());
    
    response.payloadData.assign(responseData.begin() + 7, responseData.end());

    // Parse payload data based on response code
    if (response.code == 1600) {
        response.uuid = std::string(response.payloadData.begin(), response.payloadData.begin() + response.payloadSize);
    }
    if (response.code == 1601) {
    }
    if (response.code == 1602) {
        response.uuid = std::string(response.payloadData.begin(), response.payloadData.begin() + 15);
        response.encryptedKey = std::string(response.payloadData.begin() + 16, response.payloadData.end());   
    }
    if (response.code == 1603) {
        response.uuid = std::string(response.payloadData.begin(), response.payloadData.begin() + 15);
        try {
        response.contentSize = response.parsePayload<uint32_t>(16);
        } catch(const std::exception& e) {

    }
        response.fileName = std::string(response.payloadData.begin()+20, response.payloadData.begin() + 274);
        try{
        response.checksum = response.parsePayload<uint32_t>(275);
        } catch(const std::exception& e) {

    }    }

    if (response.code == 1604) {
            response.uuid = std::string(response.payloadData.begin(), response.payloadData.begin() + 15);
    }
    if (response.code == 1605) {
        response.uuid = std::string(response.payloadData.begin(), response.payloadData.begin() + 15);
        response.encryptedKey = std::string(response.payloadData.begin() + 16, response.payloadData.end());   
    }
    if (response.code == 1606) {
            response.uuid = std::string(response.payloadData.begin(), response.payloadData.begin() + 15);
    }
    if (response.code == 1607) {

    }

    return response;
}

std::string padString(const std::string& str, size_t desiredLength) {
    if (str.length() >= desiredLength) {
        return str.substr(0, desiredLength); 
    } else {
        return str + std::string(desiredLength - str.length(), '\0');  
    }
}

std::string unpadString(const std::string& str) {
    size_t nullPos = str.find_first_of('\0');
    if (nullPos != std::string::npos) {
        return str.substr(0, nullPos);  // Return the string up to the null character
    } else {
        return str;  // No padding found, return the original string
    }
}

std::string bytesToHexString(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

void Client::writeMeFile(const std::string& stringz) {
    std::ofstream outFile("me.info", std::ios::app);  // Open in append mode

    if (!outFile) {
        std::cerr << "Failed to open file for writing: me.info" << std::endl;
        return;
    }
    
    outFile << stringz << std::endl;
    outFile.close();
}


void Client::caseOne(){

uint16_t code = 1026;
// Generate RSA key pair
RSA::PrivateKey rsaPrivateKey;
RSA::PublicKey rsaPublicKey;
AutoSeededRandomPool rng;

rsaPrivateKey.GenerateRandomWithKeySize(rng, 1024);
rsaPublicKey = RSA::PublicKey(rsaPrivateKey);

// Serialize the public key into a string
std::string publicKeyStr;
StringSink sink(publicKeyStr);
rsaPublicKey.DEREncode(sink);


std::string publicKeyBase64;
StringSource(publicKeyStr, true,new CryptoPP::Base64Encoder(new StringSink(publicKeyBase64),false ));


std::string privateKeyStr;
StringSink sinkPrivate(privateKeyStr);
rsaPrivateKey.DEREncode(sinkPrivate);

std::string privateKeyBase64;
StringSource(privateKeyStr, true, new CryptoPP::Base64Encoder(new StringSink(privateKeyBase64),false));
writeMeFile(privateKeyBase64);

setPrivateKey(privateKeyBase64);
std::string padname = padString(getUsername(), 255);
std::vector<std::string> inputData = {padname, publicKeyStr};
std::string req = concatenateData(inputData);
sendRequest(code, req);

std::string responseData = receiveResponse();
Response response = parseResponse(responseData);


std::string decrypted_symetric = Encryption::rsaDecrypt(response.encryptedKey, rsaPrivateKey);

setSymetricKey(decrypted_symetric);
std::cout << std::endl;

}


void Client::caseTwo(){

    uint16_t code = 1027;
    sendRequest(code,getUsername());

    std::string responseData = receiveResponse();
    Response response = parseResponse(responseData);
    if (response.code== 1605){
        setSymetricKey(response.encryptedKey);
        std::cout<<"reconnected"<<std::endl;
    }
    else{
        std::cout<<"reconnection faild"<<std::endl;
    }

}

void Client::displayMenu() {
    cout << "Menu:" << endl;
    cout << "[1] Send server public key" << endl;
    cout << "[2] Reconnect" << endl;
    cout << "[3] Send server file" << endl;
    cout << "[4] Exit" << endl;
    cout << "Enter your choice: ";
}

int Client::sendFileToServer() {
    std::ifstream file(getFileToSend(), std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << getFileToSend() << std::endl;
        return 0;
    }

    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    const uint32_t maxChunkSize = MAX_PAYLOAD_SIZE - sizeof(uint16_t) - sizeof(uint16_t) - sizeof(uint32_t) - 255;

    uint16_t totalChunks = static_cast<uint16_t>(std::ceil(static_cast<double>(fileSize) / maxChunkSize));

    std::string fileContent;
    uint32_t totalChecksum = 0;

    for (uint16_t chunkNumber = 0; chunkNumber < totalChunks; ++chunkNumber) {
        
        std::vector<char> chunk(maxChunkSize);
        file.read(chunk.data(), maxChunkSize);
        uint32_t chunkSize = static_cast<uint32_t>(file.gcount());

        fileContent.append(chunk.data(), chunkSize);

        uint32_t computedChecksum = Client::computeChecksum(std::string(chunk.data(), chunkSize));
        totalChecksum += computedChecksum;

        std::string encryptedChunk = Encryption::aesEncrypt(std::string(chunk.data(), chunkSize), getSymetricKey());

        uint32_t contentSize = encryptedChunk.size();
        uint32_t originalFileSize = fileSize;
        uint16_t packetNumber = chunkNumber + 1;
        std::string fileName = getFileToSend();
        std::string requestData;

        requestData.append(reinterpret_cast<const char*>(&contentSize), sizeof(contentSize));
        requestData.append(reinterpret_cast<const char*>(&originalFileSize), sizeof(originalFileSize));
        requestData.append(reinterpret_cast<const char*>(&packetNumber), sizeof(packetNumber));
        requestData.append(reinterpret_cast<const char*>(&totalChunks), sizeof(totalChunks));
        fileName.resize(255, '\0');
        requestData.append(fileName);
        requestData.append(encryptedChunk);

        // Send the request to the server
        sendRequest(1028, requestData);
    }

    // Close the file
    file.close();

    // Calculate checksum for the whole file
    std::string fileChecksumData = readfile(getFileToSend());
    std::size_t delimiterPos = fileChecksumData.find('\t');
    uint32_t totalFileChecksum = std::stoul(fileChecksumData.substr(0, delimiterPos));

    std::string responseData = receiveResponse();
    Response response = parseResponse(responseData);

    if (response.checksum != totalFileChecksum) {
        std::cerr << "Checksum mismatch for the whole file" << std::endl;
        return 0;
    } else {
        std::cout << "Checksum matched for the whole file" << std::endl;
        return 1;
    }
}


uint32_t Client::computeChecksum(const std::string& data) {
    return crc32(0L, reinterpret_cast<const Bytef*>(data.c_str()), static_cast<uInt>(data.size()));
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
            client.writeMeFile(client.getUsername());
            client.sendRequest(code, client.getUsername());
            std::string res;
            res = client.receiveResponse();
            Response response = client.parseResponse(res);
            client.setUuid(bytesToHexString(std::vector<uint8_t>(response.uuid.begin(), response.uuid.end())));
            client.writeMeFile(client.getUuid());
            

        }

        int choice;
        bool signedUp = client.userInfoIsEmpty();

        while (true) {
            client.displayMenu();
            cin >> choice;

            switch (choice) {
                    case 1:
                    {
                    client.caseOne();
                    }
                    break; 
                    case 2:
                    {
                    client.caseTwo();
                    }
                    break; 

            case 3:
            {
                int attempts = 0;
                bool success = false;
                while (attempts < 4) {
                    int result = client.sendFileToServer();
                    if (result == 1) {
                        success = true;
                        break;
                    }
                    attempts++;
                }

                if (success) {
                    client.sendRequest(1029, client.getFileToSend());
                } else {
                    if (attempts == 3){
                    client.sendRequest(1031, client.getFileToSend());
                    }
                    else{
                    client.sendRequest(1030, client.getFileToSend());
                    }
                }

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
