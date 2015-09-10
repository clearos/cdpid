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
#include <sys/socket.h>
#include <pcap/pcap.h>

#include "ndpi_main.h"

using namespace std;

#include "cdpi.h"
#include "cdpi-util.h"
#include "cdpi-thread.h"

#define TEST_THREADS    1
//#define TEST_THREADS    2
//#define TEST_THREADS    3

int main(int argc, char *argv[])
{
    static const char *dev[TEST_THREADS] = { "ens37" };
    //static const char *dev[TEST_THREADS] = { "enp0s3", "enp0s8" };
    //static const char *dev[TEST_THREADS] = { "ens32", "ens34", "ens37" };
    cdpi_flow_map *flows[TEST_THREADS];
    cdpiDetectionStats *stats[TEST_THREADS], totals;
    cdpiDetectionThread *threads[TEST_THREADS];

    cout << "cDPId v" << PACKAGE_VERSION << endl;

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

        sleep(60);

        for (int i = 0; i < TEST_THREADS; i++) {
            threads[i]->Terminate();
            delete threads[i];

            totals.pkt_raw += stats[i]->pkt_raw;
            totals.pkt_udp += stats[i]->pkt_udp;
            totals.pkt_tcp += stats[i]->pkt_tcp;
            totals.pkt_mpls += stats[i]->pkt_mpls;
            totals.pkt_pppoe += stats[i]->pkt_pppoe;
            totals.pkt_vlan += stats[i]->pkt_vlan;
            totals.pkt_frags += stats[i]->pkt_frags;
            totals.pkt_discard += stats[i]->pkt_discard;
            if (stats[i]->pkt_maxlen > totals.pkt_maxlen)
                totals.pkt_maxlen = stats[i]->pkt_maxlen;
        }

        cout << "raw packets: " << totals.pkt_raw << endl;
        cout << "TCP packets: " << totals.pkt_tcp << endl;
        cout << "UDP packets: " << totals.pkt_udp << endl;
        cout << "MPLS packets: " << totals.pkt_mpls << endl;
        cout << "PPPoE packets: " << totals.pkt_pppoe << endl;
        cout << "VLAN packets: " << totals.pkt_vlan << endl;
        cout << "fragmented packets: " << totals.pkt_frags << endl;
        cout << "discarded packets: " << totals.pkt_discard << endl;
        cout << "largest packet seen: " << totals.pkt_maxlen << endl;
    }
    catch (exception &e) {
        cerr << "Runtime error: " << e.what() << endl;
    }

    return 0;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
