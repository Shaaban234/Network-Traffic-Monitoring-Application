#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <string>
#include <chrono>
#include <thread>
#include <pcap.h>
#include <Winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wpcap.lib")


using namespace std;

struct ip_header 
{
    u_char ver_ihl;
    u_char tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char ttl;
    u_char proto;
    u_short crc;
    u_int saddr;
    u_int daddr;
};

struct tcp_header 
{
    u_short sport;
    u_short dport;
    u_int seqnum;
    u_int acknum;
    u_char th_off;
    u_char flags;
    u_short win;
    u_short crc;
    u_short urg_ptr;
};

struct ConnectionStats 
{
    unsigned long totalPackets = 0;
    unsigned long totalBytes = 0;
    unsigned long tcpPackets = 0;
    unsigned long udpPackets = 0;
    string domainName;
    string appProtocol;
    chrono::steady_clock::time_point startTime;
};

struct GlobalMetrics 
{
    unsigned long totalPackets = 0;
    unsigned long tcpPackets = 0;
    unsigned long udpPackets = 0;
    unsigned long totalBytes = 0;
} globalMetrics;

map<string, ConnectionStats> connections;

string resolveDomainName(const char* ipAddress) 
{
    struct sockaddr_in sa;
    char host[NI_MAXHOST];
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ipAddress, &sa.sin_addr);

    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0) 
    {
        return string(host);
    }
    return "";
}

void identifyApplicationLayerProtocol(unsigned short port, string& protocol) 
{
    switch (port) 
    {
        case 80: protocol = "HTTP"; break;
        case 443: protocol = "HTTPS"; break;
        case 21: protocol = "FTP"; break;
        case 53: protocol = "DNS"; break;
        default: protocol = "Unknown"; break;
    }
}

void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) 
{
    const ip_header* ipHeader = (ip_header*)(packet + 14);
    int ipVersion = ipHeader->ver_ihl >> 4;
    if (ipVersion == 4) 
    { // IPv4
        char sourceIp[INET_ADDRSTRLEN];
        char destIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ipHeader->saddr), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->daddr), destIp, INET_ADDRSTRLEN);
        globalMetrics.totalPackets++;
        globalMetrics.totalBytes += pkthdr->len;
        string connectionKey = string(sourceIp) + " -> " + string(destIp);
        if (connections.find(connectionKey) == connections.end()) 
        {
            connections[connectionKey].startTime = chrono::steady_clock::now();
            connections[connectionKey].domainName = resolveDomainName(destIp);
        }
        connections[connectionKey].totalPackets++;
        connections[connectionKey].totalBytes += pkthdr->len;
        if (ipHeader->proto == 6) 
        { // TCP
            const tcp_header* tcpHeader = (tcp_header*)(packet + 14 + (ipHeader->ver_ihl & 0xf) * 4);
            connections[connectionKey].tcpPackets++;
            globalMetrics.tcpPackets++;
            identifyApplicationLayerProtocol(ntohs(tcpHeader->dport), connections[connectionKey].appProtocol);
        } 
        else if (ipHeader->proto == 17) 
        { // UDP
            connections[connectionKey].udpPackets++;
            globalMetrics.udpPackets++;
        }
    }
}
void writeMetricsToFile() 
{
    ofstream outFile("network_metrics.json");
    if (!outFile.is_open()) 
    {
        cerr << "Error opening output file!" << endl;
        return;
    }
    outFile << "{\n\"globalMetrics\": {\n";
    outFile << "  \"totalPackets\": " << globalMetrics.totalPackets << ",\n";
    outFile << "  \"tcpPackets\": " << globalMetrics.tcpPackets << ",\n";
    outFile << "  \"udpPackets\": " << globalMetrics.udpPackets << ",\n";
    outFile << "  \"totalBytes\": " << globalMetrics.totalBytes << "\n";
    outFile << "},\n\"connections\": [\n";
    bool first = true;
    for (const auto& conn : connections) 
    {
        if (!first) outFile << ",\n";
        first = false;
        auto duration = chrono::duration_cast<chrono::seconds>(
                          chrono::steady_clock::now() - conn.second.startTime).count();
        double flowRate = duration > 0 ? conn.second.totalPackets / static_cast<double>(duration) : 0.0;
        outFile << "  {\n";
        outFile << "    \"connection\": \"" << conn.first << "\",\n";
        outFile << "    \"domain\": \"" << conn.second.domainName << "\",\n";
        outFile << "    \"totalPackets\": " << conn.second.totalPackets << ",\n";
        outFile << "    \"totalBytes\": " << conn.second.totalBytes << ",\n";
        outFile << "    \"duration\": " << duration << ",\n";
        outFile << "    \"flowRate\": " << flowRate << ",\n";
        outFile << "    \"applicationProtocol\": \"" << conn.second.appProtocol << "\"\n";
        outFile << "  }";
    }
    outFile << "\n]\n}";
    outFile.close();
    cout << "Metrics written to network_metrics.json" << endl;
}
int main() 
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const char* deviceName = "\\Device\\NPF_{9B35A563-1310-4D7A-9612-9B81D4C378EA}";
    descr = pcap_open_live(deviceName, BUFSIZ, 1, 1000, errbuf);
    if (descr == nullptr) 
    {
        cerr << "pcap_open_live() failed: " << errbuf << endl;
        return 1;
    }
    cout << "Capturing on device: " << deviceName << endl;
    auto captureThread = thread([&descr]() 
    {
        pcap_loop(descr, 0, packetHandler, nullptr);
    });
    for (int i = 0; i < 60; ++i) 
    {
        this_thread::sleep_for(chrono::seconds(5));
        writeMetricsToFile();
    }
    pcap_breakloop(descr);
    captureThread.join();
    pcap_close(descr);
    return 0;
}
