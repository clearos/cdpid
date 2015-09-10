// ClearOS DPI Daemon
// Copyright (C) 2015 ClearFoundation <http://www.clearfoundation.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#ifndef _CDPI_H
#define _CDPI_H

#define CDPI_DETECTION_TICKS    1000    // Ticks-per-second (1000 = milliseconds)

#define CDPI_PCAP_SNAPLEN       1536    // Capture snap length
#define CDPI_PCAP_READ_TIMEOUT  500     // Milliseconds

struct cdpiDetectionStats
{
    uint64_t pkt_raw;
    uint64_t pkt_mpls;
    uint64_t pkt_pppoe;
    uint64_t pkt_vlan;
    uint64_t pkt_frags;
    uint64_t pkt_discard;
    uint32_t pkt_maxlen;
    uint64_t pkt_ip;
    uint64_t pkt_tcp;
    uint64_t pkt_udp;
    uint64_t pkt_ip_bytes;
    uint64_t pkt_wire_bytes;
};

#define CDPI_SSL_CERTLEN        48      // SSL certificate length

struct cdpiFlow
{
    uint8_t version;

    struct in_addr lower_addr;
    struct in_addr upper_addr;

    struct in6_addr lower_addr6;
    struct in6_addr upper_addr6;

    char lower_ip[INET6_ADDRSTRLEN];
    char upper_ip[INET6_ADDRSTRLEN];

    uint16_t lower_port;
    uint16_t upper_port;

    uint8_t protocol;

    uint16_t vlan_id;

    uint64_t ts_last_seen;

    uint64_t bytes;
    uint32_t packets;

    bool detection_complete;
    bool detection_guessed;

    ndpi_protocol detected_protocol;

    struct ndpi_flow_struct *ndpi_flow;

    struct ndpi_id_struct *id_src;
    struct ndpi_id_struct *id_dst;

    char host_server_name[HOST_NAME_MAX];
    struct {
        char client_cert[CDPI_SSL_CERTLEN];
        char server_cert[CDPI_SSL_CERTLEN];
    } ssl;

    void hash(string &digest);

    inline bool operator==(const cdpiFlow &f) const {
        if (lower_port != f.lower_port || upper_port != f.upper_port) return false;
        switch (version) {
        case 4:
            if (memcmp(&lower_addr, &f.lower_addr, sizeof(struct in_addr)) == 0 &&
                memcmp(&upper_addr, &f.upper_addr, sizeof(struct in_addr)) == 0)
                return true;
            break;
        case 6:
            if (memcmp(&lower_addr6, &f.lower_addr6, sizeof(struct in6_addr)) == 0 &&
                memcmp(&upper_addr6, &f.upper_addr6, sizeof(struct in6_addr)) == 0)
                return true;
            break;
        }
        return false;
    }

    inline void release(void) {
        if (ndpi_flow != NULL) { ndpi_free_flow(ndpi_flow); ndpi_flow = NULL; }
        if (id_src) { delete id_src; id_src = NULL; }
        if (id_dst) { delete id_dst; id_dst = NULL; }
    }
};

typedef unordered_map<string, struct cdpiFlow *> cdpi_flow_map;
typedef pair<string, struct cdpiFlow *> cdpi_flow_pair;
typedef pair<cdpi_flow_map::iterator, bool> cdpi_flow_insert;

#endif // _CDPI_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
