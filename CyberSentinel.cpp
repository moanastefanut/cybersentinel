#include <iostream>
#include <thread>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <chrono>
#include <fstream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>

std::mutex output_mutex;

std::string detect_service_banner(const std::string& ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        char buffer[1024];
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            close(sock);
            return std::string(buffer);
        }
    }
    close(sock);
    return "";
}

void scan_port(const std::string& ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::cout << "[+] Open port: " << port << " on " << ip;
        std::string banner = detect_service_banner(ip, port);
        if (!banner.empty()) {
            std::cout << " | Banner: " << banner.substr(0, 60);
        }
        std::cout << "\n";
    }
    close(sock);
}

void port_scanner(const std::string& ip, int start_port, int end_port) {
    std::vector<std::thread> threads;
    for (int port = start_port; port <= end_port; ++port) {
        threads.emplace_back(scan_port, ip, port);
    }
    for (auto& t : threads) {
        t.join();
    }
}

void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    std::ofstream* outfile = reinterpret_cast<std::ofstream*>(user);

    const struct ip* ip_hdr = (struct ip*)(packet + 14);
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

    std::lock_guard<std::mutex> lock(output_mutex);
    std::cout << "[PACKET] " << src_ip << " -> " << dst_ip << "\n";

    if (outfile && outfile->is_open()) {
        (*outfile) << "[PACKET] " << src_ip << " -> " << dst_ip << "\n";
    }
}

void start_sniffer(const std::string& iface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device: " << errbuf << "\n";
        return;
    }

    std::ofstream outfile("captured_packets.log");
    pcap_loop(handle, 20, packet_handler, reinterpret_cast<u_char*>(&outfile));
    outfile.close();
    pcap_close(handle);
}

void fingerprint_os(const std::string& ip) {
    std::cout << "[~] Performing basic OS fingerprinting on " << ip << "...\n";
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    connect(sock, (sockaddr*)&addr, sizeof(addr));

    int ttl;
    socklen_t len = sizeof(ttl);
    if (getsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, &len) == 0) {
        if (ttl >= 128) {
            std::cout << "[+] Likely Windows host (TTL=" << ttl << ")\n";
        }
        else if (ttl >= 64) {
            std::cout << "[+] Likely Linux/Unix host (TTL=" << ttl << ")\n";
        }
        else {
            std::cout << "[?] Unknown OS (TTL=" << ttl << ")\n";
        }
    }
    close(sock);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: ./CyberSentinel <mode> <target> [options]\n";
        std::cout << "Modes:\n  scan <ip> <start_port> <end_port>\n  sniff <interface>\n  fingerprint <ip>\n";
        return 1;
    }

    std::string mode = argv[1];
    if (mode == "scan" && argc == 5) {
        std::string ip = argv[2];
        int start_port = std::stoi(argv[3]);
        int end_port = std::stoi(argv[4]);
        port_scanner(ip, start_port, end_port);
    }
    else if (mode == "sniff" && argc == 3) {
        start_sniffer(argv[2]);
    }
    else if (mode == "fingerprint" && argc == 3) {
        fingerprint_os(argv[2]);
    }
    else {
        std::cerr << "Invalid usage. Run without arguments to see help.\n";
        return 1;
    }
    return 0;
}
