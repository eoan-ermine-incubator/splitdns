#pragma once

#include <arpa/inet.h>
#include <resolv.h>
#include <string.h>
#include <stdio.h>

std::vector<std::string> resolv(const char* domain, const char* nameserver) {
    std::vector<std::string> ips;
    struct __res_state state;
    memset(&state, 0, sizeof(state));

    if (res_ninit(&state) != 0) {
        perror("res_ninit");
        throw 1;
    }

    /* Override the configured nameserver. */
    state.nscount = 1;
    memset(&state.nsaddr_list[0], 0, sizeof(state.nsaddr_list[0]));
    state.nsaddr_list[0].sin_family = AF_INET;
    state.nsaddr_list[0].sin_port = htons(53);

    if (inet_pton(AF_INET, nameserver,
                  &state.nsaddr_list[0].sin_addr) != 1) {
        res_nclose(&state);
        throw 1;
    }

    unsigned char answer[4096];

    int len = res_nquery(&state, domain, ns_c_in,
                        ns_t_a, answer, sizeof(answer));

    if (len < 0) {
        res_nclose(&state);
        fprintf(stderr, "DNS query failed\n");
        throw 1;
    }

    ns_msg msg;
    if (ns_initparse(answer, len, &msg) < 0) {
        res_nclose(&state);
        fprintf(stderr, "Failed to parse DNS response\n");
        throw 1;
    }

    for (int i = 0; i < ns_msg_count(msg, ns_s_an); i++) {
        ns_rr rr;

        if (ns_parserr(&msg, ns_s_an, i, &rr) < 0)
            continue;

        /* IPv4 A record */
        if (ns_rr_type(rr) == ns_t_a && ns_rr_rdlen(rr) == 4) {
            char ip[INET_ADDRSTRLEN];

            if (inet_ntop(AF_INET, ns_rr_rdata(rr),
                        ip, sizeof(ip))) {
                ips.push_back(ip);
            }
        }
    }

    res_nclose(&state);
    return ips;
}