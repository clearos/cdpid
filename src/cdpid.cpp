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

#include <iostream>
#include <stdexcept>
#include <unordered_map>

#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <linux/if_ether.h>

#include <pcap/pcap.h>

#include "ndpi_main.h"

using namespace std;

#include "cdpi.h"
#include "cdpi-util.h"
#include "cdpi-thread.h"

cdpi_output_flags cdpi_output_mode = CDPI_PRINTF_STDOUT;
pthread_mutex_t *cdpi_output_mutex = NULL;

#define TEST_THREADS    1
//#define TEST_THREADS    2
//#define TEST_THREADS    3

int main(int argc, char *argv[])
{
    int rc = 0;
    bool terminate = false;
    sigset_t sigset;
    struct sigevent sigev;
    timer_t timer_id;
    struct itimerspec it_spec;
    static const char *dev[TEST_THREADS] = { "ens37" };
    //static const char *dev[TEST_THREADS] = { "enp0s3", "enp0s8" };
    //static const char *dev[TEST_THREADS] = { "ens32", "ens34", "ens37" };
    cdpi_flow_map *flows[TEST_THREADS];
    cdpiDetectionStats *stats[TEST_THREADS], totals;
    cdpiDetectionThread *threads[TEST_THREADS];

    cdpi_output_mutex = new pthread_mutex_t;
    pthread_mutex_init(cdpi_output_mutex, NULL);

    cdpi_printf("cDPId v%s\n", PACKAGE_VERSION);

    sigfillset(&sigset);
    sigdelset(&sigset, SIGPROF);

    sigprocmask(SIG_BLOCK, &sigset, NULL);

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGRTMIN);

    memset(&totals, 0, sizeof(cdpiDetectionStats));

    for (int i = 0; i < TEST_THREADS; i++) {
        flows[i] = new cdpi_flow_map;
        stats[i] = new cdpiDetectionStats;
    }

    try {
        long cpu = 0;
        long cpus = sysconf(_SC_NPROCESSORS_ONLN);

        for (int i = 0; i < TEST_THREADS; i++) {
            threads[i] = new cdpiDetectionThread(
                dev[i],
                flows[i],
                stats[i],
                (TEST_THREADS > 1) ? cpu++ : -1
            );
            threads[i]->Create();
            if (cpu == cpus) cpu = 0;
        }
    }
    catch (exception &e) {
        cdpi_printf("Runtime error: %s\n", e.what());
        return 1;
    }

    memset(&sigev, 0, sizeof(struct sigevent));
    sigev.sigev_notify = SIGEV_SIGNAL;
    sigev.sigev_signo = SIGRTMIN;

    if (timer_create(CLOCK_REALTIME, &sigev, &timer_id) < 0) {
        cdpi_printf("timer_create: %s\n", strerror(errno));
        return 1;
    }

    it_spec.it_value.tv_sec = CDPI_STATS_INTERVAL;
    it_spec.it_value.tv_nsec = 0;
    it_spec.it_interval.tv_sec = CDPI_STATS_INTERVAL;
    it_spec.it_interval.tv_nsec = 0;

    timer_settime(timer_id, 0, &it_spec, NULL);

    while (!terminate) {
        int sig;
        siginfo_t si;

        sig = sigwaitinfo(&sigset, &si);
        if (sig < 0) {
            cdpi_printf("sigwaitinfo: %s\n", strerror(errno));
            rc = -1;
            terminate = true;
            continue;
        }

        if (sig == SIGINT || sig == SIGTERM) {
            rc = 0;
            terminate = true;
            continue;
        }

        if (sig == sigev.sigev_signo) {
            uint64_t flow_count = 0;
            memset(&totals, 0, sizeof(cdpiDetectionStats));

            for (int i = 0; i < TEST_THREADS; i++) {
                threads[i]->Lock();

                totals.pkt_raw += stats[i]->pkt_raw;
                totals.pkt_eth += stats[i]->pkt_eth;
                totals.pkt_mpls += stats[i]->pkt_mpls;
                totals.pkt_pppoe += stats[i]->pkt_pppoe;
                totals.pkt_vlan += stats[i]->pkt_vlan;
                totals.pkt_frags += stats[i]->pkt_frags;
                totals.pkt_discard += stats[i]->pkt_discard;
                if (stats[i]->pkt_maxlen > totals.pkt_maxlen)
                    totals.pkt_maxlen = stats[i]->pkt_maxlen;
                totals.pkt_ip += stats[i]->pkt_ip;
                totals.pkt_tcp += stats[i]->pkt_tcp;
                totals.pkt_udp += stats[i]->pkt_udp;
                totals.pkt_ip_bytes += stats[i]->pkt_ip_bytes;
                totals.pkt_wire_bytes += stats[i]->pkt_wire_bytes;

                flow_count += flows[i]->size();

                threads[i]->Unlock();
            }

            cdpi_printf("\nCumulative Totals:\n", totals.pkt_raw);
            cdpi_printf("        RAW: %lu\n", totals.pkt_raw);
            cdpi_printf("        ETH: %lu\n", totals.pkt_eth);
            cdpi_printf("         IP: %lu\n", totals.pkt_ip);
            cdpi_printf("        TCP: %lu\n", totals.pkt_tcp);
            cdpi_printf("        UDP: %lu\n", totals.pkt_udp);
            cdpi_printf("       MPLS: %lu\n", totals.pkt_mpls);
            cdpi_printf("      PPPoE: %lu\n", totals.pkt_pppoe);
            cdpi_printf("       VLAN: %lu\n", totals.pkt_vlan);
            cdpi_printf("      Frags: %lu\n", totals.pkt_frags);
            cdpi_printf("    Discard: %lu\n", totals.pkt_discard);
            cdpi_printf("    Largest: %u\n", totals.pkt_maxlen);
            cdpi_printf("   IP bytes: %u\n", totals.pkt_ip_bytes);
            cdpi_printf(" Wire bytes: %u\n", totals.pkt_wire_bytes);
            cdpi_printf("      Flows: %lu\n\n", flow_count);

            continue;
        }

        cdpi_printf("Unhandled signal: %s\n", strsignal(sig));
    }

    timer_delete(timer_id);

    for (int i = 0; i < TEST_THREADS; i++) {
        threads[i]->Terminate();
        delete threads[i];
    }

    pthread_mutex_destroy(cdpi_output_mutex);

    return 0;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
