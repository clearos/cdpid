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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <iostream>
#include <unordered_map>

#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>

#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>
#ifndef OPENSSL_THREADS
#error "OpenSSL missing thread support"
#endif
#include <openssl/sha.h>

extern "C" {
#include "ndpi_api.h"
}

using namespace std;

#include "cdpi.h"
#include "cdpi-util.h"
#include "cdpi-thread.h"

static void *cdpi_thread_entry(void *param)
{
    void *rv = NULL;
    cdpiThread *thread = NULL;

    sigset_t signal_set;
    sigfillset(&signal_set);
    sigdelset(&signal_set, SIGPROF);

    try {
        if (pthread_sigmask(SIG_BLOCK, &signal_set, NULL) != 0)
            throw cdpiThreadException("pthread_sigmask");

        thread = reinterpret_cast<cdpiThread *>(param);
        thread->SetProcName();
        rv = thread->Entry();
    }
    catch (exception &e) {
        cerr << thread->GetTag() << ": Exception: " << e.what() << endl;
    }

    return rv;
}

void cdpiFlow::hash(string &digest)
{
    SHA_CTX ctx;
    uint8_t _digest[SHA_DIGEST_LENGTH];

    if (SHA1_Init(&ctx) != 1)
        throw cdpiThreadException("SHA1_Init");

    SHA1_Update(&ctx, &vlan_id, sizeof(vlan_id));

    switch (version) {
    case 4:
        SHA1_Update(&ctx, &lower_addr, sizeof(struct in_addr));
        SHA1_Update(&ctx, &upper_addr, sizeof(struct in_addr));
        break;
    case 6:
        SHA1_Update(&ctx, &lower_addr6, sizeof(struct in6_addr));
        SHA1_Update(&ctx, &upper_addr6, sizeof(struct in6_addr));
        break;
    default:
        break;
    }

    SHA1_Update(&ctx, &protocol, sizeof(protocol));
    SHA1_Update(&ctx, &lower_port, sizeof(lower_port));
    SHA1_Update(&ctx, &upper_port, sizeof(upper_port));

    SHA1_Final(_digest, &ctx);
    digest.assign((const char *)_digest, SHA_DIGEST_LENGTH);
}


void cdpiFlow::print(const char *tag, struct ndpi_detection_module_struct *ndpi)
{
    char *p = NULL, buffer[64];

    if (detected_protocol.master_protocol) {
        ndpi_protocol2name(ndpi,
            detected_protocol, buffer, sizeof(buffer));
        p = buffer;
    }
    else
        p = ndpi_get_proto_name(ndpi, detected_protocol.protocol);
#if 1
    printf(
        "%s: %s%s: %s:%hu <-> %s:%hu\n", tag, p,
        (detection_guessed &&
            detected_protocol.protocol != NDPI_PROTOCOL_UNKNOWN) ? " [GUESSED]" : "",
        lower_ip,
        ntohs(lower_port), upper_ip,
        ntohs(upper_port));
#else
    printf(
        "%s: %s%s: %s:[%02x:%02x:%02x:%02x:%02x:%02x]:%hu <-> %s:[%02x:%02x:%02x:%02x:%02x:%02x]:%hu\n", tag, p,
        (detection_guessed &&
            detected_protocol.protocol != NDPI_PROTOCOL_UNKNOWN) ? " [GUESSED]" : "",
        lower_ip,
        lower_mac[0], lower_mac[1], lower_mac[2],
        lower_mac[3], lower_mac[4], lower_mac[5],
        ntohs(lower_port), upper_ip,
        upper_mac[0], upper_mac[1], upper_mac[2],
        upper_mac[3], upper_mac[4], upper_mac[5],
        ntohs(upper_port));
#endif
}

cdpiThread::cdpiThread(const string &tag, long cpu)
    : tag(tag), id(0), cpu(cpu), terminate(false), lock(NULL)
{
    int rc;

    if ((rc = pthread_attr_init(&attr)) != 0)
        throw cdpiThreadException(strerror(rc));

    lock = new pthread_mutex_t;
    if (lock == NULL) throw cdpiThreadException(strerror(ENOMEM));

    if ((rc = pthread_mutex_init(lock, NULL)) != 0)
        throw cdpiThreadException(strerror(rc));

    if (cpu == -1) return;

    long cpus = sysconf(_SC_NPROCESSORS_ONLN);

    if (cpu >= cpus) cpu = 0;

    cpu_set_t *cpuset = CPU_ALLOC(cpus);
    if (cpuset == NULL) return;

    size_t size = CPU_ALLOC_SIZE(cpus);

    CPU_ZERO_S(size, cpuset);
    CPU_SET_S(cpu, size, cpuset);

    rc = pthread_attr_setaffinity_np(
        &attr,
        CPU_COUNT_S(size, cpuset),
        cpuset
    );

    CPU_FREE(cpuset);
}

cdpiThread::~cdpiThread(void)
{
    pthread_attr_destroy(&attr);
    if (lock != NULL) {
        pthread_mutex_destroy(lock);
        delete lock;
    }
}

void cdpiThread::SetProcName(void)
{
    char name[CDPI_THREAD_MAX_PROCNAMELEN];

    snprintf(name, CDPI_THREAD_MAX_PROCNAMELEN, "%s", tag.c_str());
    if (tag.length() >= CDPI_THREAD_MAX_PROCNAMELEN - 1)
        name[CDPI_THREAD_MAX_PROCNAMELEN - 2] = '+';

    pthread_setname_np(id, name);
}

void cdpiThread::Create(void)
{
    int rc;

    if (id != 0)
        throw cdpiThreadException("Thread previously created");
    if ((rc = pthread_create(&id, &attr,
        cdpi_thread_entry, static_cast<void *>(this))) != 0)
        throw cdpiThreadException(strerror(rc));
}

int cdpiThread::Join(void)
{
    int rc = -1;

    if (id == 0) {
        cerr << "Thread ID invalid." << endl;
        return rc;
    }

    rc = pthread_join(id, NULL);
    id = 0;

    return rc;
}

cdpiDetectionThread::cdpiDetectionThread(const string &dev,
    cdpi_flow_map *flow_map, cdpiDetectionStats *stats, long cpu)
    : cdpiThread(dev, cpu), flows(flow_map), stats(stats),
    pcap(NULL), ndpi(NULL),
    pcap_snaplen(CDPI_PCAP_SNAPLEN), pcap_datalink_type(0),
    pkt_header(NULL), pkt_data(NULL), ts_pkt_last(0),
    ts_last_idle_scan(0)
{
    memset(stats, 0, sizeof(struct cdpiDetectionStats));

    pcap = pcap_open_live(
        dev.c_str(),
        pcap_snaplen,
        1, // Promisc?
        CDPI_PCAP_READ_TIMEOUT,
        pcap_errbuf
    );

    if (pcap == NULL)
        throw cdpiThreadException(pcap_errbuf);

    pcap_datalink_type = pcap_datalink(pcap);

    ndpi = ndpi_init_detection_module(
        CDPI_DETECTION_TICKS,
        cdpi_mem_alloc,
        cdpi_mem_free,
        cdpi_debug_printf
    );

    if (ndpi == NULL)
        throw cdpiThreadException("Detection module initialization failure");

    NDPI_PROTOCOL_BITMASK proto_all;
    NDPI_BITMASK_SET_ALL(proto_all);

    ndpi_set_protocol_detection_bitmask2(ndpi, &proto_all);
}

cdpiDetectionThread::~cdpiDetectionThread()
{
    Join();
    if (pcap != NULL) pcap_close(pcap);
}

void *cdpiDetectionThread::Entry(void)
{
    cdpi_printf("%s: capture started on CPU: %lu\n",
        tag.c_str(), cpu >= 0 ? cpu : 0);

    do {
        switch (pcap_next_ex(pcap, &pkt_header, &pkt_data)) {
        case 0:
            break;
        case 1:
            try {
                pthread_mutex_lock(lock);
                ProcessPacket();
                pthread_mutex_unlock(lock);
            }
            catch (exception &e) {
                pthread_mutex_unlock(lock);
                throw;
            }
            break;
        case -1:
            throw cdpiThreadException(pcap_errbuf);
        }
    }
    while (terminate == false);

    return NULL;
}

void cdpiDetectionThread::ProcessPacket(void)
{
    const struct ethhdr *hdr_eth = NULL;
    const struct iphdr *hdr_ip = NULL;
    const struct ip6_hdr *hdr_ip6 = NULL;

    const uint8_t *layer3 = NULL;

    uint64_t ts_pkt;
    uint16_t type, ip_offset, ip_len, l4_len = 0;
    uint16_t frag_off = 0;
    uint8_t vlan_packet = 0;
    int addr_cmp = 0;

    struct cdpiFlow flow;
    memset(&flow, 0, sizeof(struct cdpiFlow));

    string digest;

    struct ndpi_id_struct *id_src, *id_dst;

    stats->pkt_raw++;
    if (pkt_header->len > stats->pkt_maxlen)
        stats->pkt_maxlen = pkt_header->len;
#if 0
    if (pkt_header->caplen < pkt_header->len) {
        // XXX: Warning: capture size less than packet size.
        // XXX: Increase capture size (detection may not work)...
    }
#endif
    ts_pkt = ((uint64_t)pkt_header->ts.tv_sec) * CDPI_DETECTION_TICKS +
        pkt_header->ts.tv_usec / (1000000 / CDPI_DETECTION_TICKS);

    if (ts_pkt_last > ts_pkt) ts_pkt = ts_pkt_last;
    ts_pkt_last = ts_pkt;

    switch (pcap_datalink_type) {
    case DLT_NULL:
        if (ntohl(*((uint32_t *)pkt_data)) == 2)
            type = ETH_P_IP;
        else
            type = ETH_P_IPV6;

        ip_offset = 4;
        break;

    case DLT_EN10MB:
        hdr_eth = reinterpret_cast<const struct ethhdr *>(pkt_data);
        type = ntohs(hdr_eth->h_proto);
        ip_offset = sizeof(struct ethhdr);
        stats->pkt_eth++;
        break;

    case DLT_LINUX_SLL:
        type = (pkt_data[14] << 8) + pkt_data[15];
        ip_offset = 16;
        break;

    default:
        return;
    }

    while (true) {
        if (type == ETH_P_8021Q) {
            vlan_packet = 1;
            flow.vlan_id = ((pkt_data[ip_offset] << 8) + pkt_data[ip_offset + 1]) & 0xFFF;
            type = (pkt_data[ip_offset + 2] << 8) + pkt_data[ip_offset + 3];
            ip_offset += 4;
        }
        else if (type == ETH_P_MPLS_UC) {
            stats->pkt_mpls++;
            uint32_t label = ntohl(*((uint32_t *)&pkt_data[ip_offset]));
            type = ETH_P_IP;
            ip_offset += 4;

            while ((label & 0x100) != 0x100) {
                ip_offset += 4;
                label = ntohl(*((uint32_t *)&pkt_data[ip_offset]));
            }
        }
        else if (type == ETH_P_PPP_SES) {
            stats->pkt_pppoe++;
            type = ETH_P_IP;
            ip_offset += 8;
        }
        else
            break;
    }

    stats->pkt_vlan += vlan_packet;

    hdr_ip = reinterpret_cast<const struct iphdr *>(&pkt_data[ip_offset]);
    flow.version = hdr_ip->version;

    if (flow.version == 4) {
        ip_len = ((uint16_t)hdr_ip->ihl * 4);
        l4_len = ntohs(hdr_ip->tot_len) - ip_len;
        flow.protocol = hdr_ip->protocol;
        layer3 = reinterpret_cast<const uint8_t *>(hdr_ip);

        if (pkt_header->caplen >= ip_offset)
            frag_off = ntohs(hdr_ip->frag_off);

        if (pkt_header->len - ip_offset < sizeof(iphdr)) {
            // XXX: Warning: header too small
            stats->pkt_discard += pkt_header->len;
            return;
        }

        if ((frag_off & 0x3FFF) != 0) {
            // XXX: Warning: packet fragmentation not supported
            stats->pkt_frags++;
            stats->pkt_discard += pkt_header->len;
            return;
        }

        if ((frag_off & 0x1FFF) != 0) {
            stats->pkt_discard += pkt_header->len;
            return;
        }

        if (ip_len > pkt_header->len - ip_offset) {
            stats->pkt_discard += pkt_header->len;
            return;
        }

        if (pkt_header->len - ip_offset < ntohs(hdr_ip->tot_len)) {
            stats->pkt_discard += pkt_header->len;
            return;
        }

        addr_cmp = memcmp(&hdr_ip->saddr, &hdr_ip->daddr, 4);

        if (addr_cmp < 0) {
            flow.lower_addr.s_addr = hdr_ip->saddr;
            flow.upper_addr.s_addr = hdr_ip->daddr;
            if (pcap_datalink_type == DLT_EN10MB) {
                memcpy(flow.lower_mac, hdr_eth->h_source, ETH_ALEN);
                memcpy(flow.upper_mac, hdr_eth->h_dest, ETH_ALEN);
            }
        }
        else {
            flow.lower_addr.s_addr = hdr_ip->daddr;
            flow.upper_addr.s_addr = hdr_ip->saddr;
            if (pcap_datalink_type == DLT_EN10MB) {
                memcpy(flow.lower_mac, hdr_eth->h_dest, ETH_ALEN);
                memcpy(flow.upper_mac, hdr_eth->h_source, ETH_ALEN);
            }
        }
    }
    else if (flow.version == 6) {
        hdr_ip6 = reinterpret_cast<const struct ip6_hdr *>(&pkt_data[ip_offset]);
        ip_len = sizeof(struct ip6_hdr);
        l4_len = ntohs(hdr_ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
        flow.protocol = hdr_ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        layer3 = reinterpret_cast<const uint8_t *>(hdr_ip6);

        if (flow.protocol == IPPROTO_DSTOPTS) {
            const uint8_t *options = reinterpret_cast<const uint8_t *>(
                hdr_ip6 + sizeof(const struct ip6_hdr)
            );
            flow.protocol = options[0];
            ip_len += 8 * (options[1] + 1);
        }

        int i = 0;
        if (memcmp(&hdr_ip6->ip6_src, &hdr_ip6->ip6_dst, sizeof(struct in6_addr))) {
            do {
                addr_cmp = memcmp(
                    &hdr_ip6->ip6_src.s6_addr32[i], 
                    &hdr_ip6->ip6_dst.s6_addr32[i], 4);
                i++;
            }
            while (addr_cmp == 0);
        }

        if (addr_cmp < 0) {
            memcpy(&flow.lower_addr6, &hdr_ip6->ip6_src, sizeof(struct in6_addr));
            memcpy(&flow.upper_addr6, &hdr_ip6->ip6_dst, sizeof(struct in6_addr));
            if (pcap_datalink_type == DLT_EN10MB) {
                memcpy(flow.lower_mac, hdr_eth->h_source, ETH_ALEN);
                memcpy(flow.upper_mac, hdr_eth->h_dest, ETH_ALEN);
            }
        }
        else {
            memcpy(&flow.lower_addr6, &hdr_ip6->ip6_dst, sizeof(struct in6_addr));
            memcpy(&flow.upper_addr6, &hdr_ip6->ip6_src, sizeof(struct in6_addr));
            if (pcap_datalink_type == DLT_EN10MB) {
                memcpy(flow.lower_mac, hdr_eth->h_dest, ETH_ALEN);
                memcpy(flow.upper_mac, hdr_eth->h_source, ETH_ALEN);
            }
        }
    }
    else {
        // XXX: Warning: unsupported protocol version (IPv4/6 only)
        stats->pkt_discard += pkt_header->len;
        return;
    }

    switch (flow.protocol) {
    case IPPROTO_TCP:
        if (l4_len >= 20) {
            const struct tcphdr *hdr_tcp;
            hdr_tcp = reinterpret_cast<const struct tcphdr *>(layer3 + ip_len);
            stats->pkt_tcp++;

            if (addr_cmp < 0) {
                flow.lower_port = hdr_tcp->source;
                flow.upper_port = hdr_tcp->dest;
            }
            else {
                flow.lower_port = hdr_tcp->dest;
                flow.upper_port = hdr_tcp->source;

                if (addr_cmp == 0) {
                    if (flow.lower_port > flow.upper_port) {
                        flow.lower_port = flow.upper_port;
                        flow.upper_port = hdr_tcp->dest;
                    }
                }
            }
        }
        break;

    case IPPROTO_UDP:
        if (l4_len >= 8) {
            const struct udphdr *hdr_udp;
            hdr_udp = reinterpret_cast<const struct udphdr *>(layer3 + ip_len);
            stats->pkt_udp++;

            if (addr_cmp < 0) {
                flow.lower_port = hdr_udp->source;
                flow.upper_port = hdr_udp->dest;
            }
            else {
                flow.lower_port = hdr_udp->dest;
                flow.upper_port = hdr_udp->source;
            }
        }
        break;

    default:
        // Non-TCP/UDP protocols...
        break;
    }

    flow.hash(digest);

    cdpiFlow *new_flow = new cdpiFlow(flow);
    if (new_flow == NULL) throw cdpiThreadException(strerror(ENOMEM));

    cdpi_flow_insert rc = flows->insert(cdpi_flow_pair(digest, new_flow));

    if (rc.second) {
        new_flow->ndpi_flow = new ndpi_flow_struct;
        if (new_flow->ndpi_flow == NULL) throw cdpiThreadException(strerror(ENOMEM));
        memset(new_flow->ndpi_flow, 0, sizeof(ndpi_flow_struct));

        new_flow->id_src = new ndpi_id_struct;
        if (new_flow->id_src == NULL) throw cdpiThreadException(strerror(ENOMEM));
        new_flow->id_dst = new ndpi_id_struct;
        if (new_flow->id_dst == NULL) throw cdpiThreadException(strerror(ENOMEM));
        memset(new_flow->id_src, 0, sizeof(ndpi_id_struct));
        memset(new_flow->id_dst, 0, sizeof(ndpi_id_struct));
        id_src = new_flow->id_src;
        id_dst = new_flow->id_dst;
    }
    else {
        delete new_flow;
        new_flow = rc.first->second;

        if (flow == *new_flow)
            id_src = new_flow->id_src, id_dst = new_flow->id_dst;
        else
            id_src = new_flow->id_dst, id_dst = new_flow->id_src;
    }

    stats->pkt_ip++;
    stats->pkt_ip_bytes += pkt_header->len;
    stats->pkt_wire_bytes += pkt_header->len + 24;
    new_flow->packets++;
    new_flow->bytes += pkt_header->len;
    new_flow->ts_last_seen = ts_pkt;

    if (new_flow->detection_complete) return;

    new_flow->detected_protocol = ndpi_detection_process_packet(
        ndpi,
        new_flow->ndpi_flow,
        (new_flow->version == 4) ?
            (const uint8_t *)hdr_ip : (const uint8_t *)hdr_ip6,
        pkt_header->len - ip_offset,
        pkt_header->len,
        id_src,
        id_dst
    );

    if (new_flow->detected_protocol.protocol != NDPI_PROTOCOL_UNKNOWN
        || (new_flow->protocol == IPPROTO_UDP && new_flow->packets > 8)
        || (new_flow->protocol == IPPROTO_TCP && new_flow->packets > 10)) {

        new_flow->detection_complete = true;

        if (new_flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) {
            if (new_flow->ndpi_flow->num_stun_udp_pkts > 0) {
                ndpi_set_detected_protocol(
                    ndpi,
                    new_flow->ndpi_flow,
                    NDPI_PROTOCOL_STUN,
                    NDPI_PROTOCOL_UNKNOWN
                );
            }
            else {
                new_flow->detection_guessed = true;
                new_flow->detected_protocol = ndpi_guess_undetected_protocol(
                    ndpi,
                    new_flow->protocol,
                    ntohl(
                        (new_flow->version == 4) ?
                            new_flow->lower_addr.s_addr :
                                new_flow->lower_addr6.s6_addr32[2] +
                                new_flow->lower_addr6.s6_addr32[3]
                    ),
                    ntohs(new_flow->lower_port),
                    ntohl(
                        (new_flow->version == 4) ?
                            new_flow->upper_addr.s_addr :
                                new_flow->upper_addr6.s6_addr32[2] +
                                new_flow->upper_addr6.s6_addr32[3]
                    ),
                    ntohs(new_flow->upper_port)
                );
                new_flow->detected_protocol.master_protocol = NDPI_PROTOCOL_UNKNOWN;
            }
        }

        snprintf(
            new_flow->host_server_name, HOST_NAME_MAX,
            "%s", new_flow->ndpi_flow->host_server_name
        );

        if (new_flow->protocol == IPPROTO_TCP
            && new_flow->detected_protocol.protocol != NDPI_PROTOCOL_DNS) {
            snprintf(new_flow->ssl.client_cert, CDPI_SSL_CERTLEN,
                "%s", new_flow->ndpi_flow->protos.ssl.client_certificate);
            snprintf(new_flow->ssl.server_cert, CDPI_SSL_CERTLEN,
                "%s", new_flow->ndpi_flow->protos.ssl.server_certificate);
        }

        switch (new_flow->version) {
        case 4:
            inet_ntop(AF_INET, &new_flow->lower_addr.s_addr,
                new_flow->lower_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &new_flow->upper_addr.s_addr,
                new_flow->upper_ip, INET_ADDRSTRLEN);
            break;

        case 6:
            inet_ntop(AF_INET6, &new_flow->lower_addr6.s6_addr,
                new_flow->lower_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &new_flow->upper_addr6.s6_addr,
                new_flow->upper_ip, INET6_ADDRSTRLEN);
            break;
        }

        new_flow->release();

        new_flow->print(tag.c_str(), ndpi);
    }

    if (ts_last_idle_scan + CDPI_IDLE_SCAN_TIME < ts_pkt_last) {
        uint64_t purged = 0;
        cdpi_flow_map::iterator i = flows->begin();
        while (i != flows->end()) {
            if (i->second->ts_last_seen + CDPI_IDLE_FLOW_TIME < ts_pkt_last) {
                i->second->release();
                delete i->second;
                i = flows->erase(i);
                purged++;
            }
            else
                i++;
        }

        ts_last_idle_scan = ts_pkt_last;
/*
        if (purged > 0) {
            cdpi_printf("%s: Purged %lu idle flows (%lu active)\n",
                tag.c_str(), purged, flows->size());
        }
*/
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
