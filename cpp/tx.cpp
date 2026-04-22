/*
 * Compile (Linux/macOS):
 *   g++ -std=c++17 -o tx tx.cpp -lssl -lcrypto
 *
 * Compile (Windows with MinGW):
 *   g++ -std=c++17 -o tx.exe tx.cpp -lws2_32 -lssl -lcrypto
 *
 * Usage:
 *   ./tx <filepath | filename> [destination_ip] [port]
 *
 * Requires: OpenSSL (for MD5)
 * Linux:   sudo apt install libssl-dev
 * macOS:   brew install openssl
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <thread>
#include <chrono>
#include <random>

// platform-specific network headers
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR   -1
    #define closesocket    close
#endif

#include <openssl/md5.h>

constexpr size_t CHUNK_SIZE = 1400;

// writes big-endian uint16 to buffer
void write_u16(std::vector<uint8_t>& buf, uint16_t val) {
    buf.push_back((val >> 8) & 0xFF);
    buf.push_back(val & 0xFF);
}

// writes big-endian uint32 to buffer
void write_u32(std::vector<uint8_t>& buf, uint32_t val) {
    buf.push_back((val >> 24) & 0xFF);
    buf.push_back((val >> 16) & 0xFF);
    buf.push_back((val >>  8) & 0xFF);
    buf.push_back(val & 0xFF);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: ./tx <filepath> [destination_ip] [port]\n";
        return 1;
    }

    std::string filepath = argv[1];
    std::string host = (argc > 2) ? argv[2] : "127.0.0.1";
    int port = (argc > 3) ? std::stoi(argv[3]) : 5005;

    // validate filename & prepare chunks
    std::string filename = filepath;
    size_t pos = filename.find_last_of("/\\");
    if (pos != std::string::npos) filename = filename.substr(pos + 1);

    std::ifstream ifs(filepath, std::ios::binary | std::ios::ate);
    if (!ifs) {
        std::cerr << "[TX-CPP] ERROR: Cannot find file " << filepath << "\n";
        return 1;
    }
    std::streamsize size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);
    std::vector<uint8_t> file_data(size);
    if (!ifs.read((char*)file_data.data(), size)) {
        std::cerr << "[TX-CPP] ERROR: Failed to read file data.\n";
        return 1;
    }

    uint32_t max_seq = (size + CHUNK_SIZE - 1) / CHUNK_SIZE;

    // compute MD5
    std::vector<uint8_t> md5_digest(16);
    MD5(file_data.data(), file_data.size(), md5_digest.data());

    // random TransmissionID (16 bit - 0..65535)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint16_t> dis(1, 65535);
    uint16_t trans_id = dis(gen);

// Windows socket
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
#endif

    // setup UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &dest.sin_addr);

    std::cout << "[TX-CPP] Sending '" << filename << "' (" << size << " bytes) to " << host << ":" << port << "\n";
    std::cout << std::string(60, '-') << "\n";

    // FIRST PACKET (SeqNr = 0)
    std::vector<uint8_t> pkt0;
    write_u16(pkt0, trans_id);
    write_u32(pkt0, 0);
    write_u32(pkt0, max_seq);
    for (char c : filename) pkt0.push_back(c);

    sendto(sock, (char*)pkt0.data(), pkt0.size(), 0, (sockaddr*)&dest, sizeof(dest));
    std::cout << "[TX-CPP] INIT packet sent | MaxSeq=" << max_seq << " | File='" << filename << "'\n";

    // DATA PACKETS (SeqNr = 1 .. max_seq)
    size_t offset = 0;
    for (uint32_t seq = 1; seq <= max_seq; ++seq) {
        std::vector<uint8_t> pdata;
        write_u16(pdata, trans_id);
        write_u32(pdata, seq);

        size_t chunk_len = std::min(CHUNK_SIZE, file_data.size() - offset);
        pdata.insert(pdata.end(), file_data.begin() + offset, file_data.begin() + offset + chunk_len);
        offset += chunk_len;

        sendto(sock, (char*)pdata.data(), pdata.size(), 0, (sockaddr*)&dest, sizeof(dest));
        std::cout << "[TX-CPP] DATA packet sent | SeqNr=" << seq << "/" << max_seq << "\n";

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // LAST PACKET
    std::vector<uint8_t> pkt_last;
    write_u16(pkt_last, trans_id);
    write_u32(pkt_last, max_seq + 1);
    pkt_last.insert(pkt_last.end(), md5_digest.begin(), md5_digest.end());

    sendto(sock, (char*)pkt_last.data(), pkt_last.size(), 0, (sockaddr*)&dest, sizeof(dest));
    std::cout << "[TX-CPP] FINAL packet sent | MD5 attached.\n";
    std::cout << std::string(60, '-') << "\n";
    std::cout << "[TX-CPP] Transmission complete.\n";

    closesocket(sock);
    return 0;
}