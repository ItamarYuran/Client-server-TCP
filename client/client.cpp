#include "client.hpp"  // Include the client header file

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
    // Construct the header

    std::string header(23, 0); // 23 bytes header
    std::memcpy(&header[0], uuid_.c_str(), std::min(uuid_.size(), static_cast<size_t>(16)));
    header[16] = 24; // Version
    header[17] = requestCode & 0xFF; // Request code (low byte)
    header[18] = (requestCode >> 8) & 0xFF; // Request code (high byte)
    // Calculate payload size
    uint32_t payloadSize = requestData.size();

    // Fill payload size bytes in the header (big-endian)
    header[19] = payloadSize & 0xFF;
    header[20] = (payloadSize >> 8) & 0xFF;
    header[21] = (payloadSize >> 16) & 0xFF;
    header[22] = (payloadSize >> 24) & 0xFF;

    
    // Construct the packet
    std::string packet = header + requestData;

    // Send the packet to the server
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


void Client::signUp(const std::string& filename) {
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
        // Extract payload data
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

    std::cout << " response.contentSize" <<  response.contentSize << std::endl;
        std::cout << "response.uuid " << response.uuid << std::endl;
    std::cout << "response.fileName: " << response.fileName << std::endl;
    std::cout << "Checksum: " << response.checksum << std::endl;


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
    //     if (response.code == 1602) {
    //     // Assuming payload contains uuid followed by encrypted key
    //     if (response.payloadData.size() >= 16) {
    //         response.uuid = std::string(response.payloadData.begin(), response.payloadData.begin() + 15);
    //     }
    //     if (response.payloadData.size() >= 1) {////
    //         response.encryptedKey = std::string(response.payloadData.begin() + 16, response.payloadData.end());
    //     }
    // }
    // Add more conditions for other response codes if needed


    return response;
}

std::string padString(const std::string& str, size_t desiredLength) {
    if (str.length() >= desiredLength) {
        return str.substr(0, desiredLength);  // Truncate if longer than desired length
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


void Client::writeUsernameToFile(const std::string& username) {
    std::ifstream inFile("me.info");
    std::ofstream outFile("me.info.tmp");

    if (!inFile || !outFile) {
        std::cerr << "Failed to open file for writing: me.info" << std::endl;
        return;
    }

    // Write the new username to the first line
    outFile << username << std::endl;

    // Copy the rest of the lines from the input file to the temporary file
    std::string line;
    while (std::getline(inFile, line)) {
        if (!line.empty()) {  // Skip empty lines
            outFile << line << std::endl;
        }
    }

    // Close the files
    inFile.close();
    outFile.close();

    // Replace the original file with the temporary file
    std::remove("me.info");
    std::rename("me.info.tmp", "me.info");
}

void Client::writeUuidToFile(const std::string& uuid) {
    std::ifstream inFile("me.info");
    std::ofstream outFile("me.info.tmp");

    if (!inFile || !outFile) {
        std::cerr << "Failed to open file for writing: me.info" << std::endl;
        return;
    }

    // Write the new UUID to the second line
    std::string line;
    for (int i = 0; i < 2; ++i) {
        if (!std::getline(inFile, line)) {
            std::cerr << "File is not in the expected format" << std::endl;
            inFile.close();
            outFile.close();
            return;
        }
        outFile << line << std::endl;
    }
    outFile << uuid << std::endl;

    // Copy the rest of the lines from the input file to the temporary file
    while (std::getline(inFile, line)) {
        if (!line.empty()) {  // Skip empty lines
            outFile << line << std::endl;
        }
    }

    // Close the files
    inFile.close();
    outFile.close();

    // Replace the original file with the temporary file
    std::remove("me.info");
    std::rename("me.info.tmp", "me.info");
}

void Client::writePrivateKeyToFile(const std::string& privateKey) {
    std::ifstream inFile("me.info");
    std::ofstream outFile("me.info.tmp");

    if (!inFile || !outFile) {
        std::cerr << "Failed to open file for writing: me.info" << std::endl;
        return;
    }

    // Write the new private key to the third line
    std::string line;
    for (int i = 0; i < 3; ++i) {
        if (!std::getline(inFile, line)) {
            std::cerr << "File is not in the expected format" << std::endl;
            inFile.close();
            outFile.close();
            return;
        }
        outFile << line << std::endl;
    }
    outFile << privateKey << std::endl;

    // Copy the rest of the lines from the input file to the temporary file
    while (std::getline(inFile, line)) {
        if (!line.empty()) {  // Skip empty lines
            outFile << line << std::endl;
        }
    }

    // Close the files
    inFile.close();
    outFile.close();

    // Replace the original file with the temporary file
    std::remove("me.info");
    std::rename("me.info.tmp", "me.info");
}

void Client::sendFileToServer() {
    // Read the file content
    std::ifstream file(getFileToSend(), std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << getFileToSend() << std::endl;
        return;
    }

    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Set maximum chunk size to fit in one packet
    const uint32_t maxChunkSize = MAX_PAYLOAD_SIZE - sizeof(uint16_t) - sizeof(uint16_t) - sizeof(uint32_t) - 255;

    // Calculate total number of chunks needed
    uint16_t totalChunks = static_cast<uint16_t>(std::ceil(static_cast<double>(fileSize) / maxChunkSize));

    for (uint16_t chunkNumber = 0; chunkNumber < totalChunks; ++chunkNumber) {
        // Read chunk of file content
        std::vector<char> chunk(maxChunkSize);
        file.read(chunk.data(), maxChunkSize);
        uint32_t chunkSize = static_cast<uint32_t>(file.gcount());

        // Encrypt the chunk
        std::string encryptedChunk = Encryption::aesEncrypt(std::string(chunk.data(), chunkSize), getSymetricKey());

        // Prepare the request data for this chunk
        uint32_t contentSize = encryptedChunk.size();
        uint32_t originalFileSize = fileSize;
        uint16_t packetNumber = chunkNumber + 1;
        std::string fileName = getFileToSend();
        std::string requestData;

        // Add content size
        requestData.append(reinterpret_cast<const char*>(&contentSize), sizeof(contentSize));

        // Add original file size
        requestData.append(reinterpret_cast<const char*>(&originalFileSize), sizeof(originalFileSize));

        // Add packet number
        requestData.append(reinterpret_cast<const char*>(&packetNumber), sizeof(packetNumber));

        // Add total packets
        requestData.append(reinterpret_cast<const char*>(&totalChunks), sizeof(totalChunks));

        // Add file name with padding
        fileName.resize(255, '\0');
        requestData.append(fileName);

        // Add message content (encrypted file chunk)
        requestData.append(encryptedChunk);

        // Send the request to the server
        sendRequest(1028, requestData);
    }

    file.close();
}

uint32_t Client::compute_checksum(const std::string& data) {
    // Compute CRC32 checksum
    uLong crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, (const Bytef*)data.c_str(), data.length());
    return crc;
}