/*
 * Compile (Linux/macOS):
 *   g++ -o rx rx.cpp -lssl -lcrypto
 *
 * Compile (Windows with MinGW):
 *   g++ -o rx.exe rx.cpp -lws2_32 -lssl -lcrypto
 *
 * Usage:
 *   ./rx [port]
 *   ./rx 5005
 *
 * Requires: OpenSSL (for MD5)
 *   Linux:   sudo apt install libssl-dev
 *   macOS:   brew install openssl
 */

#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <iomanip>
#include <sstream>

// platform-specific network headers
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef int socklen_t;
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR   -1
    #define closesocket    close
    typedef int SOCKET;
#endif

#include <openssl/md5.h>

constexpr int    DEFAULT_PORT    = 5005;
constexpr size_t MAX_PACKET_SIZE = 65535;
constexpr size_t HEADER_SIZE     = 6;     // TransmissionID(2) + SeqNr(4)
constexpr size_t MD5_SIZE        = 16;    // 128 bit

// reads big-endian uint16 from buffer
uint16_t read_u16(const uint8_t* buf) {
    return (uint16_t(buf[0]) << 8) | buf[1];
}

// reads big-endian uint32 from buffer
uint32_t read_u32(const uint8_t* buf) {
    return (uint32_t(buf[0]) << 24) |
           (uint32_t(buf[1]) << 16) |
           (uint32_t(buf[2]) <<  8) |
            uint32_t(buf[3]);
}

// computes MD5 of a byte vector
std::vector<uint8_t> compute_md5(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> digest(MD5_SIZE);
    MD5(data.data(), data.size(), digest.data());
    return digest;
}

// hex string from bytes
std::string hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream ss;
    for (auto b : bytes)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return ss.str();
}

int main(int argc, char* argv[]) {

    int port = (argc > 1) ? std::stoi(argv[1]) : DEFAULT_PORT;

// Windows socket

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        std::cerr << "[RX-CPP] WSAStartup failed\n";
        return 1;
    }
#endif

    // creating UDP socket
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) {
        std::cerr << "[RX-CPP] ERROR: Could not create socket\n";
        return 1;
    }

    // binding to port
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;   // listen on all interfaces

    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "[RX-CPP] ERROR: bind() failed on port " << port << "\n";
        closesocket(sock);
        return 1;
    }

    std::cout << "[RX-CPP] Listening on UDP port " << port << " ...\n";
    std::cout << std::string(60, '-') << "\n";

    // state variables
    std::map<uint32_t, std::vector<uint8_t>> packets;  // SeqNr - chunk data
    std::string  filename;
    uint32_t     max_seq   = 0;
    uint16_t     trans_id  = 0;
    bool         got_first = false;
    bool         got_last  = false;
    std::vector<uint8_t> received_md5;

    // receive loop
    std::vector<uint8_t> buf(MAX_PACKET_SIZE);

    while (!got_last) {
        sockaddr_in sender{};
        socklen_t sender_len = sizeof(sender);

        ssize_t n = recvfrom(sock, (char*)buf.data(), buf.size(), 0,
                             (sockaddr*)&sender, &sender_len);
        if (n < 0) {
            std::cerr << "[RX-CPP] ERROR: recvfrom() failed\n";
            break;
        }

        if ((size_t)n < HEADER_SIZE) {
            std::cerr << "[RX-CPP] WARNING: Packet too small, ignoring\n";
            continue;
        }

        // parsing common header
        uint16_t pkt_trans_id = read_u16(buf.data());
        uint32_t seq_nr       = read_u32(buf.data() + 2);
        size_t   payload_size = (size_t)n - HEADER_SIZE;
        uint8_t* payload      = buf.data() + HEADER_SIZE;

        // FIRST PACKET (SeqNr = 0)
        if (seq_nr == 0) {
            if (payload_size < 4) {
                std::cerr << "[RX-CPP] ERROR: First packet too small\n";
                continue;
            }
            trans_id  = pkt_trans_id;
            max_seq   = read_u32(payload);              // MaxSeqNr
            filename  = std::string(                    // FileName (rest of payload)
                            (char*)(payload + 4),
                            payload_size - 4
                        );
            got_first = true;
            std::cout << "[RX-CPP] FIRST packet | TransID=" << trans_id
                      << " | MaxSeq=" << max_seq
                      << " | File='" << filename << "'\n";
            continue;
        }

        // LAST PACKET: SeqNr = max_seq + 1, payload = 16 bytes MD5
        if (got_first && seq_nr == max_seq + 1 && payload_size == MD5_SIZE) {
            received_md5.assign(payload, payload + MD5_SIZE);
            got_last = true;
            std::cout << "[RX-CPP] LAST  packet | MD5=" << hex(received_md5) << "\n";
            continue;
        }

        // DATA PACKET
        if (seq_nr >= 1) {
            packets[seq_nr] = std::vector<uint8_t>(payload, payload + payload_size);
            std::cout << "[RX-CPP] DATA  packet | SeqNr=" << seq_nr
                      << "/" << max_seq
                      << " | " << payload_size << " bytes\n";
        }
    }

    closesocket(sock);

    // reassemble file
    if (!got_first || !got_last) {
        std::cerr << "[RX-CPP] ERROR: Incomplete transmission\n";
        return 1;
    }

    std::cout << std::string(60, '-') << "\n";
    std::cout << "[RX-CPP] Reassembling " << packets.size() << " chunks...\n";

    std::vector<uint8_t> file_data;
    for (uint32_t i = 1; i <= max_seq; ++i) {
        auto it = packets.find(i);
        if (it == packets.end()) {
            std::cerr << "[RX-CPP] WARNING: Missing chunk SeqNr=" << i << "\n";
        } else {
            file_data.insert(file_data.end(), it->second.begin(), it->second.end());
        }
    }

    // verifying MD5
    auto computed_md5 = compute_md5(file_data);
    std::cout << "[RX-CPP] Computed MD5 : " << hex(computed_md5) << "\n";
    std::cout << "[RX-CPP] Received MD5 : " << hex(received_md5) << "\n";

    if (computed_md5 == received_md5) {
        std::string outfile = "received_" + filename;
        std::ofstream ofs(outfile, std::ios::binary);
        ofs.write((char*)file_data.data(), file_data.size());
        ofs.close();
        std::cout << "[RX-CPP] MD5 OK! File saved as '" << outfile << "'\n";
    } else {
        std::cerr << "[RX-CPP] MD5 MISMATCH! File may be corrupted.\n";
        return 1;
    }

    return 0;
}