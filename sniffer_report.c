#include <pcap/pcap.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>

namespace {

constexpr std::size_t kTopN = 5;
constexpr std::size_t kEtherHdrLen = 14;

struct AddrStats {
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;
};

struct Report {
    std::uint64_t total_packets = 0;
    std::uint64_t total_bytes = 0;
    std::uint64_t ipv4_packets = 0;
    std::uint64_t ipv6_packets = 0;
    std::uint64_t arp_packets = 0;
    std::uint64_t other_l2_packets = 0;
    std::uint64_t tcp_packets = 0;
    std::uint64_t udp_packets = 0;
    std::uint64_t icmp_packets = 0;
    std::uint64_t icmpv6_packets = 0;
    std::uint64_t other_l4_packets = 0;
    std::unordered_map<std::string, AddrStats> src;
    std::unordered_map<std::string, AddrStats> dst;
};

void usage(std::ostream &out) {
    out << "Usage: sniffer_report -i <interface> [-c packet_count] [-t seconds] [-f bpf_filter]\n";
}

void update_addr(std::unordered_map<std::string, AddrStats> &table,
                 const std::string &addr,
                 std::uint32_t bytes) {
    auto &entry = table[addr];
    entry.packets++;
    entry.bytes += bytes;
}

std::vector<std::pair<std::string, AddrStats>> top_n(const std::unordered_map<std::string, AddrStats> &table) {
    std::vector<std::pair<std::string, AddrStats>> rows(table.begin(), table.end());
    std::sort(rows.begin(), rows.end(), [](const auto &a, const auto &b) {
        if (a.second.packets != b.second.packets)
            return a.second.packets > b.second.packets;
        return a.second.bytes > b.second.bytes;
    });
    if (rows.size() > kTopN)
        rows.resize(kTopN);
    return rows;
}

void print_top(const char *label, const std::unordered_map<std::string, AddrStats> &table) {
    std::cout << label << ":\n";
    const auto rows = top_n(table);
    if (rows.empty()) {
        std::cout << "  (none)\n";
        return;
    }
    for (std::size_t i = 0; i < rows.size(); ++i) {
        std::cout << "  " << (i + 1) << ") " << rows[i].first
                  << " packets=" << rows[i].second.packets
                  << " bytes=" << rows[i].second.bytes << "\n";
    }
}

std::uint16_t read_be16(const u_char *p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

void process_packet(Report &rep, const pcap_pkthdr *h, const u_char *data) {
    rep.total_packets++;
    rep.total_bytes += h->caplen;

    if (h->caplen < kEtherHdrLen) {
        rep.other_l2_packets++;
        return;
    }

    const auto eth_type = read_be16(data + 12);

    if (eth_type == 0x0800) {
        rep.ipv4_packets++;
        if (h->caplen < kEtherHdrLen + 20)
            return;

        const u_char *ip = data + kEtherHdrLen;
        const std::uint8_t ihl = static_cast<std::uint8_t>((ip[0] & 0x0f) * 4);
        if (ihl < 20 || h->caplen < kEtherHdrLen + ihl)
            return;

        char src[INET_ADDRSTRLEN] = {};
        char dst[INET_ADDRSTRLEN] = {};
        if (inet_ntop(AF_INET, ip + 12, src, sizeof(src)) != nullptr)
            update_addr(rep.src, src, h->caplen);
        if (inet_ntop(AF_INET, ip + 16, dst, sizeof(dst)) != nullptr)
            update_addr(rep.dst, dst, h->caplen);

        switch (ip[9]) {
        case 6: rep.tcp_packets++; break;
        case 17: rep.udp_packets++; break;
        case 1: rep.icmp_packets++; break;
        default: rep.other_l4_packets++; break;
        }
        return;
    }

    if (eth_type == 0x86dd) {
        rep.ipv6_packets++;
        if (h->caplen < kEtherHdrLen + 40)
            return;

        const u_char *ip6 = data + kEtherHdrLen;
        char src[INET6_ADDRSTRLEN] = {};
        char dst[INET6_ADDRSTRLEN] = {};
        if (inet_ntop(AF_INET6, ip6 + 8, src, sizeof(src)) != nullptr)
            update_addr(rep.src, src, h->caplen);
        if (inet_ntop(AF_INET6, ip6 + 24, dst, sizeof(dst)) != nullptr)
            update_addr(rep.dst, dst, h->caplen);

        switch (ip6[6]) {
        case 6: rep.tcp_packets++; break;
        case 17: rep.udp_packets++; break;
        case 58: rep.icmpv6_packets++; break;
        default: rep.other_l4_packets++; break;
        }
        return;
    }

    if (eth_type == 0x0806)
        rep.arp_packets++;
    else
        rep.other_l2_packets++;
}

int start_capture(const char *ifname, int packet_count, int duration_seconds, const char *filter) {
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_t *pcap = pcap_create(ifname, errbuf);
    if (pcap == nullptr) {
        std::cerr << "pcap_create(" << ifname << "): " << errbuf << "\n";
        return 1;
    }

    int ret = 0;
    if ((ret = pcap_set_snaplen(pcap, 65535)) != 0 ||
        (ret = pcap_set_promisc(pcap, 1)) != 0 ||
        (ret = pcap_set_timeout(pcap, 500)) != 0 ||
        (ret = pcap_set_immediate_mode(pcap, 1)) != 0) {
        std::cerr << "pcap setup failed: " << pcap_statustostr(ret) << "\n";
        pcap_close(pcap);
        return 1;
    }

    ret = pcap_activate(pcap);
    if (ret < 0) {
        std::cerr << "pcap_activate: " << pcap_geterr(pcap) << "\n";
        pcap_close(pcap);
        return 1;
    }

    bpf_program prog{};
    bool filter_loaded = false;
    if (filter != nullptr) {
        if (pcap_compile(pcap, &prog, filter, 1, PCAP_NETMASK_UNKNOWN) < 0 ||
            pcap_setfilter(pcap, &prog) < 0) {
            std::cerr << "BPF filter failed: " << pcap_geterr(pcap) << "\n";
            pcap_close(pcap);
            return 1;
        }
        filter_loaded = true;
    }

    Report rep;
    int packets_seen = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(duration_seconds > 0 ? duration_seconds : 0);

    for (;;) {
        pcap_pkthdr *h = nullptr;
        const u_char *data = nullptr;
        ret = pcap_next_ex(pcap, &h, &data);

        if (ret == 1) {
            process_packet(rep, h, data);
            ++packets_seen;
            if (packet_count > 0 && packets_seen >= packet_count)
                break;
            continue;
        }

        if (ret == 0) {
            if (duration_seconds > 0 && std::chrono::steady_clock::now() >= deadline)
                break;
            continue;
        }

        if (ret == -2)
            break;

        std::cerr << "capture error: " << pcap_geterr(pcap) << "\n";
        if (filter_loaded)
            pcap_freecode(&prog);
        pcap_close(pcap);
        return 1;
    }

    std::cout << "=== Lightweight Network Behavior Report ===\n";
    std::cout << "Interface: " << ifname << "\n";
    std::cout << "Packets captured: " << rep.total_packets << "\n";
    std::cout << "Bytes captured:   " << rep.total_bytes << "\n";
    std::cout << "L2 breakdown: IPv4=" << rep.ipv4_packets
              << " IPv6=" << rep.ipv6_packets
              << " ARP=" << rep.arp_packets
              << " Other=" << rep.other_l2_packets << "\n";
    std::cout << "L4 breakdown: TCP=" << rep.tcp_packets
              << " UDP=" << rep.udp_packets
              << " ICMP=" << rep.icmp_packets
              << " ICMPv6=" << rep.icmpv6_packets
              << " Other=" << rep.other_l4_packets << "\n";
    print_top("Top source addresses", rep.src);
    print_top("Top destination addresses", rep.dst);

    if (filter_loaded)
        pcap_freecode(&prog);
    pcap_close(pcap);
    return 0;
}

} // namespace

int main(int argc, char **argv) {
    const char *ifname = nullptr;
    const char *filter = nullptr;
    int packet_count = 500;
    int duration_seconds = 10;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-i") == 0 && i + 1 < argc)
            ifname = argv[++i];
        else if (std::strcmp(argv[i], "-c") == 0 && i + 1 < argc)
            packet_count = std::atoi(argv[++i]);
        else if (std::strcmp(argv[i], "-t") == 0 && i + 1 < argc)
            duration_seconds = std::atoi(argv[++i]);
        else if (std::strcmp(argv[i], "-f") == 0 && i + 1 < argc)
            filter = argv[++i];
        else {
            usage(std::cerr);
            return 1;
        }
    }

    if (ifname == nullptr) {
        usage(std::cerr);
        return 1;
    }

    if (packet_count <= 0)
        packet_count = 0;
    if (duration_seconds <= 0)
        duration_seconds = 0;

    return start_capture(ifname, packet_count, duration_seconds, filter);
}
