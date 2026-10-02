// lwIP's ip4addr_aton (software/lwip/src/core/ipv4/ip4_addr.c at 26a22151): network_target.cc decides what an IPv4
// literal is with it, so the host tests need the same predicate (127.1, 0x7f.0.0.1 and "1.2.3.4 x" included).
// The function below is lwIP's, under lwIP's license, reproduced verbatim:
/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#include <ctype.h>
#include <arpa/inet.h>
#include "lwip/dns.h"

int ip4addr_aton(const char *cp, ip4_addr_t *addr)
{
    uint32_t val;
    uint8_t base;
    char c;
    uint32_t parts[4];
    uint32_t *pp = parts;

    c = *cp;
    for (;;) {
        if (!isdigit((unsigned char)c)) {
            return 0;
        }
        val = 0;
        base = 10;
        if (c == '0') {
            c = *++cp;
            if (c == 'x' || c == 'X') {
                base = 16;
                c = *++cp;
            } else {
                base = 8;
            }
        }
        for (;;) {
            if (isdigit((unsigned char)c)) {
                if ((base == 8) && ((uint32_t)(c - '0') >= 8))
                    break;
                val = (val * base) + (uint32_t)(c - '0');
                c = *++cp;
            } else if (base == 16 && isxdigit((unsigned char)c)) {
                val = (val << 4) | (uint32_t)(c + 10 - (islower((unsigned char)c) ? 'a' : 'A'));
                c = *++cp;
            } else {
                break;
            }
        }
        if (c == '.') {
            if (pp >= parts + 3) {
                return 0;
            }
            *pp++ = val;
            c = *++cp;
        } else {
            break;
        }
    }
    if (c != '\0' && !isspace((unsigned char)c)) {
        return 0;
    }
    switch (pp - parts + 1) {
        case 0:
            return 0;
        case 1:
            break;
        case 2:
            if (val > 0xffffffUL) {
                return 0;
            }
            if (parts[0] > 0xff) {
                return 0;
            }
            val |= parts[0] << 24;
            break;
        case 3:
            if (val > 0xffff) {
                return 0;
            }
            if ((parts[0] > 0xff) || (parts[1] > 0xff)) {
                return 0;
            }
            val |= (parts[0] << 24) | (parts[1] << 16);
            break;
        case 4:
            if (val > 0xff) {
                return 0;
            }
            if ((parts[0] > 0xff) || (parts[1] > 0xff) || (parts[2] > 0xff)) {
                return 0;
            }
            val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
            break;
        default:
            break;
    }
    if (addr) {
        addr->addr = htonl(val);
    }
    return 1;
}
