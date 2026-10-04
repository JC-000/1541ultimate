/*
 * network_target.cc
 *
 *  Created on: Jul 22, 2015
 *      Author: Gideon
 */

#include "network_target.h"
#include "network_interface.h"
#include "socket.h"
#include "lwip/opt.h"
#include "netdb.h"
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#if U64 == 1
#include "wifi_random.h"
#endif
#if NET_TLS
#include "lwip/dns.h"
#include "lwip/tcpip.h"
#include "FreeRTOS.h"
#include "task.h"
#include "sntp_time.h"
#include "wifi_tls.h"
#endif

NetworkTarget net(3);

Message c_net_message_identification = { 34, true, (uint8_t *)"ULTIMATE-II NETWORK INTERFACE V1.0" };
Message c_status_invalid_params      = { 17, true, (uint8_t *)"81,INVALID PARAMS" };
Message c_status_param_out_of_range  = { 28, true, (uint8_t *)"82,PARAMETER(S) OUT OF RANGE" };
Message c_status_interface_not_set   = { 26, true, (uint8_t *)"83,INTERFACE NOT AVAILABLE" };
Message c_status_host_not_resolvable = { 18, true, (uint8_t *)"84,UNRESOLVED HOST" };
Message c_status_no_socket           = { 23, true, (uint8_t *)"85,ERROR OPENING SOCKET" };
Message c_status_socket_closed       = { 28, true, (uint8_t *)"01,CONNECTION CLOSED BY HOST" };
Message c_status_net_no_data         = { 26, true, (uint8_t *)"03,MORE DATA NOT SUPPORTED" };
Message c_status_internal_error      = { 17, true, (uint8_t *)"86,INTERNAL ERROR" };
Message c_status_no_entropy          = { 20, true, (uint8_t *)"87,NO ENTROPY SOURCE" };
Message c_status_entropy_busy        = { 22, true, (uint8_t *)"88,ENTROPY SOURCE BUSY" };

// The TLS commands (M3-SPEC v1). Texts are those of section 2.
#define TLS_MESSAGE(text) { sizeof(text) - 1, true, (uint8_t *)text }
Message c_status_tls_not_available = TLS_MESSAGE("90,TLS NOT AVAILABLE");
Message c_status_tls_in_use        = TLS_MESSAGE("91,TLS SESSIONS IN USE");
Message c_status_tls_no_time       = TLS_MESSAGE("92,NO TRUSTED TIME");
Message c_status_tls_no_custom_ca  = TLS_MESSAGE("97,NO CUSTOM CA");
Message c_status_tls_module        = TLS_MESSAGE("17,TLS MODULE NOT RESPONDING");
Message c_status_tls_hs_timeout    = TLS_MESSAGE("15,TLS HANDSHAKE TIMEOUT");
Message c_status_tls_downgrade     = TLS_MESSAGE("19,TLS DOWNGRADE DETECTED");
Message c_status_tls_pin_mismatch  = TLS_MESSAGE("96,PINNED KEY MISMATCH");
Message c_status_tls_no_notify     = TLS_MESSAGE("05,TLS CLOSED WITHOUT NOTIFY");

#if NET_TLS
// Deadlines and caps (M3-SPEC 4.3).
#define TLS_DNS_MS            10000
#define TLS_CONNECT_MS        10000
#define TLS_OPEN_TOTAL_MS     40000
#define TLS_HANDSHAKE_MS      15000
#define TLS_STEP_RPC_MS       5000
#define TLS_OPEN_RPC_MS       5000
#define TLS_CLOSE_RPC_MS      1000
#define TLS_STATS_RPC_MS      1000
#define TLS_CLOSE_ALL_RPC_MS  500
#define TLS_READ_WAIT_MS      40
#define TLS_READ_BUDGET_STEPS 8
#define TLS_READ_BUDGET_MS    250
#define TLS_READ_TOTAL_MS     10000
#define TLS_WRITE_BUDGET      4
#define TLS_WRITE_TOTAL_MS    10000
#define TLS_SEND_MS           5000
#define TLS_NOTIFY_SEND_MS    100
#define TLS_UNSENT_RETRIES    10
#define TLS_UNSENT_DELAY_MS   50
#define TLS_SLICE_MS          100  // the longest any wait goes without looking at a reset
#define TLS_SNDTIMEO_MS       500  // OI-3: caps lwIP's close when it cannot get memory for the FIN
                                   // (api_msg.c:1034-1037, else 20 s); our sends are MSG_DONTWAIT
#define TLS_EARLIEST_TIME     1735689600u // 2025-01-01: an SNTP time before this is not one

#define CA_EMPTY     0
#define CA_UPLOADING 1
#define CA_LOADED    2

// How a stream ends once the C64 has read everything before the end.
#define TLS_END_NONE      0
#define TLS_END_CLOSED    1 // close_notify: 01, the handle is gone
#define TLS_END_NO_NOTIFY 2 // TCP end without close_notify: 05, the handle is gone
#define TLS_END_RX_ERR    3 // the latched receive error: sticky 12

static_assert(NET_MAX_TLS == WIFI_TLS_MAX_SESSIONS, "the TLS table must match the module's cap");
static_assert(NET_TLS_CT_MAX == WIFI_TLS_STEP_MAX_IN, "a step takes at most this much ciphertext");
static_assert(NET_TLS_PT_MAX == WIFI_TLS_STEP_MAX_OUT, "a step hands out at most this much");
static_assert(NET_TLS_CA_MAX == WIFI_TLS_CA_MAX, "CA sizes differ");
static_assert(NET_MAX_SOCKET_READ <= NET_CMD_BUFSIZE, "a TLS read goes through buffer");
#endif

NetworkTarget::NetworkTarget(int id)
{
    command_targets[id] = this;
    data_message.message = new uint8_t[CMD_MAX_REPLY_LEN];
    status_message.message = new uint8_t[CMD_MAX_STATUS_LEN];
    socket_count = 0;
    discard_read_reply();
#if NET_TLS
    memset(tls, 0, sizeof(tls));
    tls_last_tag = 0;
    tls_generation_known = false;
    tls_generation = 0;
    ca_state = 0; // CA_EMPTY
    ca_tag = 0;
    tls_new_ca_tag();
    ca_len = 0;
    ca_total = 0;
    info_valid = false;
    info_generation = 0;
    info_ready = 0;
    info_block_max_ms = 0;
#endif
    discard_write_chunk();
}

NetworkTarget::~NetworkTarget()
{
    close_all_sockets();
    delete[] data_message.message;
    delete[] status_message.message;
}


void NetworkTarget :: parse_command(Message *command, Message **reply, Message **status)
{
    NetworkInterface *interface;

    // The command interface only accepts a command while it is idle, so a
    // reply that is still being handed out cannot normally be interrupted by
    // one. Dropping it here as well means no path into this target can hand a
    // client bytes left over from an earlier read.
    discard_read_reply();

    // M3-SPEC 1.1 Rule 2: every command claims every TLS session, so that
    // only the session of the latest OPEN_TLS or START_TLS can be unclaimed,
    // and only until the next command. $25, which frees an unclaimed session,
    // and $23 $FF, which counts them, leave them as they are.
    uint8_t code = (command->length >= 2) ? command->message[1] : 0;
    bool keeps_claims = (code == NET_CMD_TLS_RELEASE) ||
                        ((code == NET_CMD_TLS_INFO) && (command->length == 3) && (command->message[2] == 0xFF));
#if NET_TLS
    tls_check_generation();
    if (!keeps_claims) {
        for (int i = 0; i < NET_MAX_TLS; i++) {
            tls[i].claimed = true;
        }
    }
    // A CA upload takes no other network command in between (1.2).
    if ((code != NET_CMD_TLS_TRUST_CA) && (ca_state == CA_UPLOADING)) {
        ca_state = CA_EMPTY;
    }
#else
    (void)keeps_claims;
#endif

    // Any other command ends a chunked write that is still accumulating. That
    // is what keeps the accumulation out of the way of `buffer`'s other users,
    // open_socket's name resolution and a read reply being handed out.
    if (command->message[1] != NET_CMD_WRITE_SOCKET_CHUNK) {
        discard_write_chunk();
    }

    switch(command->message[1]) {
        case NET_CMD_IDENTIFY:
            *reply  = &c_net_message_identification;
            *status = &c_status_ok;
            break;
        case NET_CMD_GET_INTERFACE_COUNT:
        	data_message.message[0] = (uint8_t)NetworkInterface :: getNumberOfInterfaces();
        	data_message.length = 1;
        	data_message.last_part = true;
        	*reply  = &data_message;
            *status = &c_status_ok;
        	break;
/*
        case NET_CMD_SET_INTERFACE:
        	*reply = &c_message_empty;
        	if (command->length != 3) {
        		*status = &c_status_invalid_params;
	        } else if (command->message[2] >= (uint8_t)NetworkInterface :: getNumberOfInterfaces()) {
        		*status = &c_status_param_out_of_range;
	        } else {
                *status = &c_status_ok;
        		interface_number = command->message[2];
        	}
        	break;
*/
        case NET_CMD_GET_IPADDR:
            *reply = &c_message_empty;
            if (command->length != 3) {
                *status = &c_status_invalid_params;
                break;
            }
            if (command->message[2] >= (uint8_t)NetworkInterface :: getNumberOfInterfaces()) {
                *status = &c_status_param_out_of_range;
                break;
            }
            interface = NetworkInterface :: getInterface(command->message[2]);
            if (interface) {
        		*reply = &data_message;
        		*status = &c_status_ok;
        		interface->getIpAddr(data_message.message);
        		data_message.length = 12;
            	data_message.last_part = true;
        	} else {
        		*status = &c_status_interface_not_set;
        	}
        	break;
        case NET_CMD_GET_NETADDR:
            *reply = &c_message_empty;
            if (command->length != 3) {
                *status = &c_status_invalid_params;
                break;
            }
            if (command->message[2] >= (uint8_t)NetworkInterface :: getNumberOfInterfaces()) {
                *status = &c_status_param_out_of_range;
                break;
            }
            interface = NetworkInterface :: getInterface(command->message[2]);
        	if (interface) {
        		*reply = &data_message;
        		*status = &c_status_ok;
        		interface->getMacAddr(data_message.message);
        		data_message.length = 6;
            	data_message.last_part = true;
        	} else {
        		*reply = &c_message_empty;
        		*status = &c_status_interface_not_set;
        	}
        	break;
        case NET_CMD_SET_IPADDR:
            *reply = &c_message_empty;
            if (command->length != 15) { // 12 + 3
                *status = &c_status_invalid_params;
                break;
            }
            if (command->message[2] >= (uint8_t)NetworkInterface :: getNumberOfInterfaces()) {
                *status = &c_status_param_out_of_range;
                break;
            }
            interface = NetworkInterface :: getInterface(command->message[2]);
        	if (interface) {
				interface->setIpAddr(&command->message[3]);
                *reply = &c_message_empty;
                *status = &c_status_ok;
        	} else {
        		*reply = &c_message_empty;
        		*status = &c_status_interface_not_set;
        	}
        	break;
        case NET_CMD_OPEN_TCP:
            if (command->length < 5) { // Impossible
                *reply = &c_message_empty;
                *status = &c_status_invalid_params;
                break;
            }
            open_socket(command, reply, status, SOCK_STREAM);
			break;
        case NET_CMD_OPEN_UDP:
            if (command->length < 5) { // Impossible
                *reply = &c_message_empty;
                *status = &c_status_invalid_params;
                break;
            }
        	open_socket(command, reply, status, SOCK_DGRAM);
        	break;
        case NET_CMD_CLOSE_SOCKET:
            if (command->length != 3) { // 2 + 1
                *reply = &c_message_empty;
                *status = &c_status_invalid_params;
                break;
            }
            close_socket(command, reply, status);
            break;
        case NET_CMD_READ_SOCKET:
            if (command->length != 5) { // 2 + 3
                *reply = &c_message_empty;
                *status = &c_status_invalid_params;
                break;
            }
        	read_socket(command, reply, status);
        	break;
        case NET_CMD_WRITE_SOCKET:
        	write_socket(command, reply, status);
        	break;
        case NET_CMD_WRITE_SOCKET_CHUNK:
            if (command->length < 7) { // 2 + 5
                *reply = &c_message_empty;
                *status = &c_status_invalid_params;
                discard_write_chunk();
                break;
            }
            write_socket_chunk(command, reply, status);
            break;
        case NET_CMD_GET_RANDOM:
            if (command->length != 4) { // 2 + 2
                *reply = &c_message_empty;
                *status = &c_status_invalid_params;
                break;
            }
            get_random(command, reply, status);
            break;
        case NET_CMD_OPEN_TLS:
            open_tls(command, reply, status);
            break;
        case NET_CMD_TLS_TRUST_CA:
            trust_ca(command, reply, status);
            break;
        case NET_CMD_TLS_INFO:
            tls_info(command, reply, status);
            break;
        case NET_CMD_START_TLS:
            start_tls(command, reply, status);
            break;
        case NET_CMD_TLS_RELEASE:
            tls_release(command, reply, status);
            break;
        default:
            *reply  = &c_message_empty;
            *status = &c_status_unknown_command;
    }
}

void NetworkTarget :: open_socket(Message *command, Message **reply, Message **status, int type)
{
	*reply = &c_message_empty;
	*status = &c_status_ok;

	uint16_t port_number = uint16_t(command->message[2]) | (uint16_t(command->message[3]) << 8);
	struct sockaddr_in addr;
	  /* set up address to connect to */
	memset(&addr, 0, sizeof(addr));
	addr.sin_len = sizeof(addr);
	addr.sin_family = AF_INET;
	addr.sin_port = PP_HTONS(port_number);
	command->message[command->length] = 0;

	struct hostent hent;
	struct hostent *hent_result;
	int h_errno;

	gethostbyname_r((const char *)&command->message[4], &hent, (char *)buffer, NET_CMD_BUFSIZE, &hent_result, &h_errno);

	if (hent_result) {
		struct in_addr *s;
		s = (struct in_addr *)hent_result->h_addr_list[0];
		addr.sin_addr.s_addr = s->s_addr;
	} else {
		*status = &c_status_host_not_resolvable;
		return;
	}

	int socket = socket(AF_INET, type, 0);
	if (socket < 0) {
		*status = &c_status_no_socket;
		return;
	}

	int ret = connect(socket, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		*status = &status_message;
		sprintf((char *)this->status_message.message, "11,ERROR ON CONNECT: %d", errno);
		this->status_message.length = strlen((char *)this->status_message.message);
		lwip_close(socket);
		return;
	}

	if (socket > 255) {
        *status = &c_status_internal_error;
        lwip_close(socket);
        return;
	}

	// The table has room for every socket lwip can create, so this cannot
	// fail. Refusing rather than writing past the table keeps that a check
	// instead of an assumption.
	if (!track_socket(socket)) {
		*status = &c_status_no_socket;
		lwip_close(socket);
		return;
	}
	*reply = &data_message;
	this->data_message.message[0] = (uint8_t)socket;
	this->data_message.length = 1;
	data_message.last_part = true;

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 40000; // 40 ms
	setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
}

void NetworkTarget :: read_socket(Message *command, Message **reply, Message **status)
{
	uint8_t socketnr = command->message[2];
	uint32_t length = ((uint32_t)command->message[3]) | (((uint32_t)command->message[4]) << 8);

#if NET_TLS
    TlsSocket *session = tls_find(socketnr);
    if (session) {
        tls_read(session, length, reply, status);
        return;
    }
#endif

    // A complete unfragmented IPv4 UDP datagram is the most this command can
    // ever return, so that is what it accepts. Anything larger cannot arrive.
    if (length > NET_MAX_SOCKET_READ) {
        *status = &c_status_param_out_of_range;
        *reply = &c_message_empty;
        return;
    }

    *reply = &data_message;
    // The whole payload is received here, into a buffer that outlives this
    // call, so that a reply spanning several blocks never has to go back to
    // the socket. A second receive on a datagram socket would take the next
    // datagram rather than the rest of this one.
    //
    // lwip_recvmsg rather than lwip_recv: on a datagram socket it returns the
    // length of the datagram itself and sets MSG_TRUNC when it did not fit,
    // where lwip_recv reports only what was copied and drops the rest without
    // a trace. On a stream socket the two behave the same way.
    struct iovec iov;
    struct msghdr msg;
    iov.iov_base = buffer;
    iov.iov_len = length;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    int ret;
    if (owns_socket(socketnr)) {
        ret = lwip_recvmsg(socketnr, &msg, 0);
    } else {
        errno = EBADF;
        ret = -1;
    }
    // The header is the number of bytes this reply carries, which is what the
    // network target document specifies and what existing clients read. On a
    // reply that spans blocks it is still the total, not the part in the first
    // block, so a client that concatenates the blocks gets exactly the reply a
    // large enough response queue would have delivered in one.
    int copied = (ret > (int)length) ? (int)length : ret;
    data_message.length = 2;
    data_message.last_part = true;
    data_message.message[0] = (copied & 0xFF);
    data_message.message[1] = (copied & 0xFF00) >> 8;

    // printf("Reading %d bytes from socket %d resulted in %d\n", length, socketnr, ret);
	if (ret == 0) {
		untrack_socket(socketnr);
		lwip_close(socketnr);
		*status = &c_status_socket_closed;
		return;
	}
	if (ret > 0) {
		Message *result = &c_status_ok;
		if (msg.msg_flags & MSG_TRUNC) {
			// The datagram was longer than the caller asked for and the rest is
			// gone. Reporting that on the status channel leaves the reply itself
			// unchanged, so a client that does not look is no worse off than
			// before, and one that does can tell a short datagram from a
			// truncated one.
			sprintf((char *)this->status_message.message, "04,DATAGRAM TRUNCATED: %d", ret);
			this->status_message.length = strlen((char *)this->status_message.message);
			result = &status_message;
		}
		start_read_reply(copied, result, reply, status);
		return;
	}
	*status = &status_message;
	sprintf((char *)this->status_message.message, "02,NO DATA: %d", errno);
	this->status_message.length = strlen((char *)this->status_message.message);
}

void NetworkTarget :: start_read_reply(int payload_length, Message *result, Message **reply, Message **status)
{
    read_total = payload_length;
    read_offset = 0;
    read_status = result;

    int chunk = (payload_length > NET_FIRST_BLOCK_PAYLOAD) ? NET_FIRST_BLOCK_PAYLOAD : payload_length;
    memcpy(&data_message.message[2], buffer, chunk);
    read_offset = chunk;
    data_message.length = chunk + 2;
    data_message.last_part = (read_offset >= read_total);

    *reply = &data_message;
    // The command has one result and reports it once, on the block that ends
    // the reply. An intermediate block leaves the status queue empty rather
    // than repeating the text, so a client that appends the status of every
    // block ends up with exactly the text a single block reply would give it.
    *status = data_message.last_part ? read_status : &c_message_empty;
    if (data_message.last_part) {
        discard_read_reply();
    }
}

void NetworkTarget :: discard_read_reply(void)
{
    read_total = 0;
    read_offset = 0;
    read_status = &c_status_ok;
}

#include "dump_hex.h"
// Both write commands report a send from here, so they cannot drift apart in
// what they tell the client. The one lwip_send is the contract and not an
// optimisation: a retry loop around it would send #807's several datagrams.
void NetworkTarget :: send_to_socket(int socketnr, uint8_t *src, int length, Message **reply, Message **status)
{
    int ret;
#if NET_TLS
    // A TLS handle is written through its session, whichever write command
    // carries the payload; a raw send would put plaintext into the TLS stream.
    // A negative length is a WRITE_SOCKET too short to name a socket.
    TlsSocket *session = (length >= 0) ? tls_find(socketnr) : NULL;
    if (session) {
        tls_write(session, src, length, reply, status);
        return;
    }
#endif
    if (owns_socket(socketnr)) {
        ret = lwip_send(socketnr, src, length, 0);
    } else {
        errno = EBADF;
        ret = -1;
    }
    // printf("Writing %d bytes to socket %d resulted in %d\n", length, socketnr, ret);
    // dump_hex_relative(src, length);

    *reply = &data_message;
    data_message.length = 2;
    data_message.last_part = true;
    data_message.message[0] = (ret & 0xFF);
    data_message.message[1] = (ret & 0xFF00) >> 8;

    if (ret < 0) {
		*status = &status_message;
		sprintf((char *)this->status_message.message, "12,SEND ERROR: %d", errno);
		this->status_message.length = strlen((char *)this->status_message.message);
	} else {
	    *status = &c_status_ok;
	}
}

void NetworkTarget :: write_socket(Message *command, Message **reply, Message **status)
{
    uint8_t socketnr = command->message[2];
    uint8_t *src = &command->message[3];

    int length = command->length - 3;
    send_to_socket(socketnr, src, length, reply, status);
}

void NetworkTarget :: write_socket_chunk(Message *command, Message **reply, Message **status)
{
    uint8_t socketnr = command->message[2];
    int offset = ((int)command->message[3]) | (((int)command->message[4]) << 8);
    int total = ((int)command->message[5]) | (((int)command->message[6]) << 8);
    int length = command->length - 7;

    *reply = &c_message_empty;

    if (offset == 0) {
        // An opening chunk announces the payload and replaces whatever was
        // accumulating, so a client that restarts a payload gets a clean one.
        discard_write_chunk();
        if (total > NET_MAX_SOCKET_WRITE) {
            *status = &c_status_param_out_of_range;
            return;
        }
        write_handle = socketnr;
        write_total = total;
    } else if ((offset != write_offset) || (socketnr != write_handle) || (total != write_total)) {
        // A chunk carries where it belongs, so one that does not continue the
        // payload in progress, or that arrives when none is, is refused here
        // rather than spliced into a datagram the client never asked for.
        discard_write_chunk();
        *status = &c_status_invalid_params;
        return;
    }

    if ((write_offset + length) > write_total) {
        discard_write_chunk();
        *status = &c_status_invalid_params;
        return;
    }

    memcpy(&buffer[write_offset], &command->message[7], length);
    write_offset += length;

    if (write_offset < write_total) {
        // The payload is short of its total, so nothing goes out yet. The empty
        // reply and this status say the chunk was taken and no more.
        *status = &c_status_ok;
        return;
    }

    // Complete, so it leaves as the single datagram the client asked for. The
    // accumulation ends here, before the send, so a send that fails cannot
    // leave a payload behind for the next chunk to continue.
    int handle = write_handle;
    int payload = write_total;
    discard_write_chunk();
    send_to_socket(handle, buffer, payload, reply, status);
}

void NetworkTarget :: discard_write_chunk(void)
{
    write_handle = 0;
    write_total = 0;
    write_offset = 0;
}

void NetworkTarget :: close_socket(Message *command, Message **reply, Message **status)
{
    uint8_t socketnr = command->message[2];
    int result = -1;
#if NET_TLS
    // Always OK: the session goes, whatever state it is in (1.5).
    TlsSocket *session = tls_find(socketnr);
    if (session) {
        tls_close_entry(session, true);
        *reply = &c_message_empty;
        *status = &c_status_ok;
        return;
    }
#endif
    if (owns_socket(socketnr)) {
        untrack_socket(socketnr);
        result = lwip_close(socketnr);
    } else {
        errno = EBADF;
    }
    *reply = &c_message_empty;
    if (result < 0) {
        *status = &status_message;
        sprintf((char *)this->status_message.message, "12,ERROR ON CLOSE: %d", errno);
        this->status_message.length = strlen((char *)this->status_message.message);
    } else {
        *status = &c_status_ok;
    }
}

void NetworkTarget :: get_random(Message *command, Message **reply, Message **status)
{
    uint16_t length = uint16_t(command->message[2]) | (uint16_t(command->message[3]) << 8);

    *reply = &c_message_empty;
    if ((length == 0) || (length > NET_MAX_RANDOM)) {
        *status = &c_status_param_out_of_range;
        return;
    }
    // The bytes come from the WiFi module's hardware generator and from
    // nowhere else, so without that module there are none.
    *status = &c_status_no_entropy;
#if U64 == 1
    // The reply stays empty unless the result may carry data, and 87 stays
    // for any status not handled here.
    int result = wifi_get_random(data_message.message, length, NULL);
    if (wifi_random_has_data(result)) {
        data_message.length = length;
        data_message.last_part = true;
        *reply = &data_message;
        *status = &c_status_ok;
    } else if (wifi_random_status(result) == 88) {
        *status = &c_status_entropy_busy;
    } else if (wifi_random_status(result) == 86) {
        *status = &c_status_internal_error;
    }
#endif
}

// A socket handed to the client without a table entry would survive a C64
// reset, which is the defect in #808, so the table must cover every descriptor
// lwip can return. lwip's NUM_SOCKETS is MEMP_NUM_NETCONN, tested here rather
// than including lwip's private socket header.
static_assert(NET_MAX_SOCKETS >= MEMP_NUM_NETCONN,
              "the socket table is smaller than the number of lwip sockets");

bool NetworkTarget :: track_socket(int socketnr)
{
    if (socket_count >= NET_MAX_SOCKETS) {
        return false;
    }
    sockets[socket_count++] = socketnr;
    return true;
}

void NetworkTarget :: untrack_socket(int socketnr)
{
    for (int i = 0; i < socket_count; i++) {
        if (sockets[i] == socketnr) {
            socket_count--;
            for (; i < socket_count; i++) {
                sockets[i] = sockets[i + 1];
            }
            return;
        }
    }
}

bool NetworkTarget :: owns_socket(int socketnr)
{
    for (int i = 0; i < socket_count; i++) {
        if (sockets[i] == socketnr) {
            return true;
        }
    }
    return false;
}

void NetworkTarget :: close_all_sockets(void)
{
    for (int i = 0; i < socket_count; i++) {
        lwip_close(sockets[i]);
    }
    socket_count = 0;
}

void NetworkTarget :: c64_reset(void)
{
    // abort() also drops the reply, but it does not run when the reset's
    // queue post was dropped. Without this the next program could be handed
    // what is left of the previous one's read over Data More.
    discard_read_reply();
    // A payload half collected when the machine went down must not be there for
    // the next program's chunks to complete, which they would: lwip hands out
    // the low descriptors again, so a stale handle can name a live socket.
    discard_write_chunk();
    close_all_sockets();
#if NET_TLS
    // The sockets went with close_all_sockets. The sessions on the module go
    // with CLOSE_ALL, and if that is lost, with the next OPEN of each slot;
    // the CA with the new ca_tag, which the module's copy can never match.
    for (int i = 0; i < NET_MAX_TLS; i++) {
        tls[i].used = false;
    }
    ca_state = CA_EMPTY;
    tls_new_ca_tag();
    if (wifi_tls_module_available()) {
        int esp_err;
        wifi_tls_close_all(&esp_err, TLS_CLOSE_ALL_RPC_MS);
    }
#endif
}

void NetworkTarget :: get_more_data(Message **reply, Message **status)
{
    if (read_offset >= read_total) {
        // Nothing was left pending, so this is a client asking for a block
        // that was never announced.
        *reply = &c_message_empty;
        *status = &c_status_net_no_data;
        return;
    }

    int chunk = read_total - read_offset;
    if (chunk > NET_MAX_REPLY_BLOCK) {
        chunk = NET_MAX_REPLY_BLOCK;
    }
    // A continuation block is payload only. The header went out with the first
    // block and already counted these bytes.
    memcpy(data_message.message, &buffer[read_offset], chunk);
    read_offset += chunk;
    data_message.length = chunk;
    data_message.last_part = (read_offset >= read_total);

    *reply = &data_message;
    *status = data_message.last_part ? read_status : &c_message_empty;
    if (data_message.last_part) {
        discard_read_reply();
    }
}

void NetworkTarget :: abort(int a)
{
    // `a` counts the bytes the client took from the block it abandoned. They
    // are its business; what is left of the payload goes away with the
    // transaction, which is what a datagram read means anyway.
    discard_read_reply();
    // A chunked write goes the same way, so an abandoned payload is never
    // completed by whatever the client sends next.
    discard_write_chunk();
}

// ---------------------------------------------------------------------------
// TLS sockets (esp-tls M3, M3-SPEC v1 sections 1-4)
// ---------------------------------------------------------------------------

Message *NetworkTarget :: set_status(const char *text)
{
    int n = strlen(text);
    if (n > CMD_MAX_STATUS_LEN) {
        n = CMD_MAX_STATUS_LEN;
    }
    memcpy(status_message.message, text, n);
    status_message.length = n;
    status_message.last_part = true;
    return &status_message;
}

// Byte-exact parsing of OPEN_TLS ($21, fixed = 6) and START_TLS ($24, fixed =
// 5): the refusals that need nothing but the command, 81 before 82 (1.1 step
// 1). For OPEN the tail is host [ $00 [ name [ $00 ] ] ]; for START it is
// [ name ] [ $00 ]. host and name point into the command and are not
// terminated. NULL when the command is well formed.
Message *NetworkTarget :: tls_parse_open(Message *command, int fixed, bool start, uint8_t *trust, uint8_t *flags,
                                         const uint8_t **pin, const char **host, int *host_len, const char **name,
                                         int *name_len)
{
    const uint8_t *m = command->message;
    int length = command->length;
    if (length < fixed) {
        return &c_status_invalid_params;
    }
    *trust = m[fixed - 2];
    *flags = m[fixed - 1];
    int pos = fixed;
    *pin = NULL;
    if (*trust == 2) { // PIN
        if (length < fixed + 32) {
            return &c_status_invalid_params;
        }
        *pin = &m[fixed];
        pos += 32;
    }
    *host = NULL;
    *host_len = 0;
    *name = NULL;
    *name_len = 0;

    int end = pos;
    if (!start) {
        while ((end < length) && (m[end] != 0)) {
            end++;
        }
        *host = (const char *)&m[pos];
        *host_len = end - pos;
        if ((*host_len < 1) || (*host_len > 253)) {
            return &c_status_invalid_params;
        }
        if (end == length) {
            return NULL; // host
        }
        pos = end + 1; // past the $00
        if (pos == length) {
            return NULL; // host $00
        }
    } else if ((length - pos == 1) && (m[pos] == 0)) {
        return NULL; // a lone $00: no name
    }
    if (pos == length) {
        return NULL; // START_TLS without a name
    }
    end = pos;
    while ((end < length) && (m[end] != 0)) {
        end++;
    }
    *name = (const char *)&m[pos];
    *name_len = end - pos;
    if ((*name_len < 1) || (*name_len > 253)) {
        return &c_status_invalid_params;
    }
    // After the name, at most its $00, as the very last byte.
    if ((end < length) && (end != length - 1)) {
        return &c_status_invalid_params;
    }
    return NULL;
}

#if NET_TLS

// Status texts carry numbers; the firmware's printf is not relied on for hex.
static char *put_text(char *p, const char *text)
{
    while (*text) {
        *p++ = *text++;
    }
    *p = 0;
    return p;
}

static char *put_dec(char *p, int value)
{
    char digits[12];
    int n = 0;
    uint32_t v = (value < 0) ? (uint32_t)(-(int64_t)value) : (uint32_t)value;
    if (value < 0) {
        *p++ = '-';
    }
    do {
        digits[n++] = '0' + (v % 10);
        v /= 10;
    } while (v);
    while (n) {
        *p++ = digits[--n];
    }
    *p = 0;
    return p;
}

static char *put_hex(char *p, uint32_t value, int digits)
{
    static const char hex[] = "0123456789ABCDEF";
    p = put_text(p, "0x");
    for (int i = digits - 1; i >= 0; i--) {
        *p++ = hex[(value >> (4 * i)) & 0xF];
    }
    *p = 0;
    return p;
}

// An mbedTLS code, -0x%04X (M3-SPEC 1, status hex format).
static char *put_error(char *p, int error)
{
    if (error < 0) {
        *p++ = '-';
        return put_hex(p, (uint32_t)(-(int64_t)error), 4);
    }
    return put_hex(p, (uint32_t)error, 4);
}

// lwIP's own predicate for an IPv4 literal, which also takes 127.1 and
// 0x7f.0.0.1 (1.1).
static bool is_ipv4_literal(const char *text, int length)
{
    char name[254];
    memcpy(name, text, length);
    name[length] = 0;
    ip4_addr_t address;
    return ip4addr_aton(name, &address) != 0;
}

static bool reached(uint32_t deadline)
{
    return (int32_t)(xTaskGetTickCount() - deadline) >= 0;
}

static uint32_t tick_after(uint32_t ms)
{
    return xTaskGetTickCount() + pdMS_TO_TICKS(ms);
}

static uint32_t earlier(uint32_t a, uint32_t b)
{
    return ((int32_t)(a - b) <= 0) ? a : b;
}

// The cancel predicate of the module calls (4.1): a C64 reset always, and a
// deadline for the waits that have one. Cleanup calls pass no deadline.
typedef struct {
    bool use_deadline;
    uint32_t deadline;
} tls_cancel_context_t;

static bool tls_cancelled(void *context)
{
    tls_cancel_context_t *c = (tls_cancel_context_t *)context;
    if (cmd_if.reset_pending()) {
        return true;
    }
    return c->use_deadline && reached(c->deadline);
}

static bool reset_now(void)
{
    return cmd_if.reset_pending();
}

TlsSocket *NetworkTarget :: tls_find(int socketnr)
{
    for (int i = 0; i < NET_MAX_TLS; i++) {
        if (tls[i].used && (tls[i].socketnr == socketnr)) {
            return &tls[i];
        }
    }
    return NULL;
}

// A free entry, not yet in use; the slot on the module is its index.
TlsSocket *NetworkTarget :: tls_reserve(void)
{
    for (int i = 0; i < NET_MAX_TLS; i++) {
        if (!tls[i].used) {
            return &tls[i];
        }
    }
    return NULL;
}

int NetworkTarget :: tls_in_use(bool unclaimed_only)
{
    int n = 0;
    for (int i = 0; i < NET_MAX_TLS; i++) {
        if (tls[i].used && (!unclaimed_only || !tls[i].claimed)) {
            n++;
        }
    }
    return n;
}

uint16_t NetworkTarget :: tls_new_tag(void)
{
    if (++tls_last_tag == 0) {
        tls_last_tag = 1;
    }
    return tls_last_tag;
}

void NetworkTarget :: tls_new_ca_tag(void)
{
    if (++ca_tag == 0) {
        ca_tag = 1;
    }
}

// A module restart ends every session it held, and its CA (4.5).
void NetworkTarget :: tls_check_generation(void)
{
    if (!wifi_tls_module_available()) {
        return;
    }
    uint32_t now = wifi_tls_generation();
    if (!tls_generation_known) {
        tls_generation_known = true;
        tls_generation = now;
        return;
    }
    if (now == tls_generation) {
        return;
    }
    tls_generation = now;
    for (int i = 0; i < NET_MAX_TLS; i++) {
        TlsSocket *e = &tls[i];
        if (e->used) {
            if (!e->failed) {
                tls_fail(e, "17,TLS MODULE NOT RESPONDING");
            }
            e->module_live = false;
        }
    }
    ca_state = CA_EMPTY;
    tls_new_ca_tag();
}

// Sticky: the entry answers text on every READ and WRITE until CLOSE, and
// plaintext not yet read is dropped (U8).
void NetworkTarget :: tls_fail(TlsSocket *e, const char *text)
{
    e->failed = true;
    strncpy(e->sticky, text, NET_TLS_STICKY_MAX - 1);
    e->sticky[NET_TLS_STICKY_MAX - 1] = 0;
    e->rx_len = 0;
    e->rx_off = 0;
    e->end = TLS_END_NONE;
}

// 17. With cleanup, the session is closed on the module at once, since
// nothing says what it did with the last request.
void NetworkTarget :: tls_fail_module(TlsSocket *e, bool cleanup)
{
    tls_fail(e, "17,TLS MODULE NOT RESPONDING");
    if (!cleanup) {
        e->module_live = false;
    } else {
        tls_cleanup_close(e);
    }
}

// A session that FAILED after its handshake: 14 for a fatal alert from the
// peer, 16 otherwise (section 2). The module has freed it.
void NetworkTarget :: tls_fail_step(TlsSocket *e, int esp_err, uint8_t alert_in)
{
    char text[NET_TLS_STICKY_MAX];
    if (alert_in != WIFI_TLS_ALERT_NONE) {
        put_dec(put_text(text, "14,TLS ALERT RECEIVED: "), alert_in);
    } else {
        put_error(put_text(text, "16,TLS SESSION FAILED: "), esp_err);
    }
    e->module_live = false;
    tls_fail(e, text);
}

// CLOSE with the reset as its only cancel, bounded by CLOSE_RPC_MS; what the
// module answers is not sent. A module that no longer knows the session has
// freed it all the same.
void NetworkTarget :: tls_cleanup_close(TlsSocket *e)
{
    if (!e->module_live || reset_now()) {
        return;
    }
    tls_cancel_context_t context = { false, 0 };
    wifi_tls_cancel_t cancel = { tls_cancelled, &context };
    uint16_t notify_len;
    int esp_err;
    int result = wifi_tls_close(e->slot, e->tag, tls_ct_out, sizeof(tls_ct_out), &notify_len, &esp_err,
                                TLS_CLOSE_RPC_MS, &cancel);
    if ((result == 0) || ((result == WIFI_TLS_REFUSED) && (esp_err == WIFI_TLS_ESP_NOT_FOUND))) {
        e->module_live = false;
    }
}

// CLOSE_SOCKET, $25, and the end of a stream: the session on the module, its
// close_notify best effort, the socket, the entry.
void NetworkTarget :: tls_close_entry(TlsSocket *e, bool send_notify)
{
    if (e->module_live && !reset_now()) {
        tls_cancel_context_t context = { false, 0 };
        wifi_tls_cancel_t cancel = { tls_cancelled, &context };
        uint16_t notify_len = 0;
        int esp_err;
        int result = wifi_tls_close(e->slot, e->tag, tls_ct_out, sizeof(tls_ct_out), &notify_len, &esp_err,
                                    TLS_CLOSE_RPC_MS, &cancel);
        if ((result == 0) && send_notify && notify_len) {
            tls_send_all(e->socketnr, tls_ct_out, notify_len, tick_after(TLS_NOTIFY_SEND_MS));
        }
    }
    untrack_socket(e->socketnr);
    lwip_close(e->socketnr);
    e->used = false;
}

// One STEP, sent again while it could not be sent at all.
int NetworkTarget :: tls_run_step(TlsSocket *e, void *step, uint32_t deadline, bool use_deadline)
{
    tls_cancel_context_t context = { use_deadline, deadline };
    wifi_tls_cancel_t cancel = { tls_cancelled, &context };
    int result;
    for (int i = 0; ; i++) {
        result = wifi_tls_step(e->slot, e->tag, (wifi_tls_step_t *)step, TLS_STEP_RPC_MS, &cancel);
        if ((result != WIFI_TLS_UNSENT) || (i == TLS_UNSENT_RETRIES) || tls_cancelled(&context)) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(TLS_UNSENT_DELAY_MS));
    }
    return result;
}

// Waits at most one slice, and never past until, for the socket to become
// readable (or writable). True when it did.
bool NetworkTarget :: tls_wait(int sock, bool for_write, uint32_t until)
{
    int32_t left = (int32_t)(until - xTaskGetTickCount());
    if (left <= 0) {
        return false;
    }
    if (left > (int32_t)pdMS_TO_TICKS(TLS_SLICE_MS)) {
        left = pdMS_TO_TICKS(TLS_SLICE_MS);
    }
    fd_set fds, errs;
    FD_ZERO(&fds);
    FD_ZERO(&errs);
    FD_SET(sock, &fds);
    FD_SET(sock, &errs);
    struct timeval tv;
    uint32_t us = (uint32_t)left * portTICK_PERIOD_MS * 1000;
    tv.tv_sec = us / 1000000;
    tv.tv_usec = us % 1000000;
    int n = lwip_select(sock + 1, for_write ? NULL : &fds, for_write ? &fds : NULL, &errs, &tv);
    return n > 0;
}

// Sends all of it, polling a non-blocking socket, before SEND_MS and deadline
// (4.3). Returns 0, an errno (ETIMEDOUT at the deadline), or -1 on a reset.
int NetworkTarget :: tls_send_all(int sock, const uint8_t *data, int length, uint32_t deadline)
{
    uint32_t until = earlier(tick_after(TLS_SEND_MS), deadline);
    while (length > 0) {
        int sent = lwip_send(sock, data, length, MSG_DONTWAIT);
        if (sent > 0) {
            data += sent;
            length -= sent;
            continue;
        }
        if ((sent < 0) && (errno != EWOULDBLOCK) && (errno != EAGAIN)) {
            return errno;
        }
        if (reset_now()) {
            return -1;
        }
        if (reached(until)) {
            return ETIMEDOUT;
        }
        tls_wait(sock, true, until);
    }
    return 0;
}

// DNS inside OPEN_TLS (1.1): lwIP's callback resolver, polled. One slot, and a
// lookup is known by its sequence number, carried by value; a late answer to
// an abandoned lookup finds another number and writes nothing.
#define DNS_PENDING 0
#define DNS_OK      1
#define DNS_FAILED  2
static struct {
    uint32_t cur_seq;
    ip_addr_t addr;
    uint8_t state;
} tls_dns;

static void tls_dns_found(const char *name, const ip_addr_t *ipaddr, void *arg)
{
    // On the tcpip thread, which holds the core lock.
    if ((uint32_t)(uintptr_t)arg != tls_dns.cur_seq) {
        return;
    }
    if (ipaddr) {
        tls_dns.addr = *ipaddr;
        tls_dns.state = DNS_OK;
    } else {
        tls_dns.state = DNS_FAILED;
    }
}

// 0 with the address, 84, or -1 on a reset.
int NetworkTarget :: tls_resolve(const char *host, uint32_t deadline, uint32_t *address)
{
    ip_addr_t found;
    LOCK_TCPIP_CORE();
    uint32_t seq = ++tls_dns.cur_seq;
    tls_dns.state = DNS_PENDING;
    err_t err = dns_gethostbyname(host, &found, tls_dns_found, (void *)(uintptr_t)seq);
    UNLOCK_TCPIP_CORE();
    if (err == ERR_OK) {
        *address = ip4_addr_get_u32(ip_2_ip4(&found));
        return 0;
    }
    if (err != ERR_INPROGRESS) {
        return 84;
    }
    while (true) {
        LOCK_TCPIP_CORE();
        uint8_t state = tls_dns.state;
        found = tls_dns.addr;
        UNLOCK_TCPIP_CORE();
        if (state == DNS_OK) {
            *address = ip4_addr_get_u32(ip_2_ip4(&found));
            return 0;
        }
        if (state == DNS_FAILED) {
            return 84;
        }
        if (reset_now()) {
            return -1;
        }
        int32_t left = (int32_t)(deadline - xTaskGetTickCount());
        if (left <= 0) {
            return 84;
        }
        vTaskDelay((left > (int32_t)pdMS_TO_TICKS(TLS_SLICE_MS)) ? pdMS_TO_TICKS(TLS_SLICE_MS) : left);
    }
}

// A non-blocking connect, polled: lwIP answers EALREADY while it is under way
// and EISCONN once it is done. 0, an errno (ETIMEDOUT at the deadline), or -1
// on a reset.
int NetworkTarget :: tls_connect(int sock, uint32_t address, uint16_t port, uint32_t deadline)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = PP_HTONS(port);
    addr.sin_addr.s_addr = address;
    while (lwip_connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int error = errno;
        if (error == EISCONN) {
            return 0;
        }
        if ((error != EINPROGRESS) && (error != EALREADY)) {
            return error;
        }
        if (reset_now()) {
            return -1;
        }
        int32_t left = (int32_t)(deadline - xTaskGetTickCount());
        if (left <= 0) {
            return ETIMEDOUT;
        }
        tls_wait(sock, true, deadline);
    }
    return 0;
}

// What every TLS socket gets (4.3): non-blocking, TCP_NODELAY, and a send
// timeout, which lwIP's close also takes as its bound when it runs out of
// memory for the FIN (OI-3). OPEN_TLS sets them on its new socket; START_TLS
// only once steps 1-5 have passed, so that a kept code leaves the socket as
// it was.
static void tls_socket_options(int sock)
{
    int on = 1;
    lwip_ioctl(sock, FIONBIO, &on);
    lwip_setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = TLS_SNDTIMEO_MS * 1000;
    lwip_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

// Steps 2 to 5 of the refusal order (1.1): the module, the table, the CA, and
// the OPEN RPC, which starts a session on the module under (slot, tag). keep
// says whether START_TLS leaves the TCP socket as it was. NULL once the module
// holds the session.
Message *NetworkTarget :: tls_prepare(TlsSocket *e, uint8_t trust, uint8_t flags, const uint8_t *pin,
                                      const char *name, int name_len, uint32_t total, bool *keep)
{
    *keep = true;
    if (!wifi_tls_module_available()) {
        return &c_status_tls_not_available;
    }
    if (!e) {
        return &c_status_tls_in_use;
    }
    if ((trust == WIFI_TLS_TRUST_CUSTOM) && (ca_state != CA_LOADED)) {
        return &c_status_tls_no_custom_ca;
    }
    memset(e, 0, offsetof(TlsSocket, rx)); // all but the buffers
    e->slot = (uint8_t)(e - tls);
    e->tag = tls_new_tag();
    e->trust = trust;
    e->module_live = false;

    wifi_tls_open_t open;
    open.trust = trust;
    open.slot = e->slot;
    open.tag = e->tag;
    open.opts = flags & WIFI_TLS_OPT_REQUIRE_TLS13;
    uint32_t now = sntp_utc_now();
    open.time_source = (now >= TLS_EARLIEST_TIME) ? WIFI_TLS_TIME_NIOS : WIFI_TLS_TIME_NONE;
    open.unix_time = (now >= TLS_EARLIEST_TIME) ? now : 0;
    open.ca_tag = (trust == WIFI_TLS_TRUST_CUSTOM) ? ca_tag : 0;
    open.pin = (trust == WIFI_TLS_TRUST_PIN) ? pin : NULL;
    open.sni = name;
    open.sni_len = (uint8_t)name_len;

    tls_cancel_context_t context = { true, earlier(tick_after(TLS_OPEN_RPC_MS), total) };
    wifi_tls_cancel_t cancel = { tls_cancelled, &context };
    int esp_err;
    uint8_t reason;
    int result;
    for (int i = 0; ; i++) {
        result = wifi_tls_open(&open, TLS_OPEN_RPC_MS, &cancel, &esp_err, &reason);
        if ((result != WIFI_TLS_UNSENT) || (i == TLS_UNSENT_RETRIES) || tls_cancelled(&context)) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(TLS_UNSENT_DELAY_MS));
    }
    if (result == 0) {
        e->module_live = true;
        return NULL;
    }
    if (result == WIFI_TLS_NO_MODULE) {
        return &c_status_tls_not_available;
    }
    if (result == WIFI_TLS_REFUSED) {
        switch (reason) {
            case WIFI_TLS_REASON_NO_ENTROPY:   return &c_status_no_entropy;
            case WIFI_TLS_REASON_NO_TIME:      return &c_status_tls_no_time;
            case WIFI_TLS_REASON_NO_CUSTOM_CA: return &c_status_tls_no_custom_ca;
            default: break;
        }
        if (esp_err == WIFI_TLS_ESP_NOT_SUPPORTED) {
            return &c_status_tls_not_available; // a module image without TLS
        }
        *keep = false;
        return &c_status_tls_module;
    }
    // No answer, or not a well formed one: the module may hold the session
    // all the same. The (slot, tag) takeover covers a CLOSE that is lost too.
    *keep = false;
    e->module_live = true;
    tls_cleanup_close(e);
    return &c_status_tls_module;
}

// A handshake that FAILED, to its code (section 2, verify classification).
Message *NetworkTarget :: tls_classify(TlsSocket *e, void *step)
{
    wifi_tls_step_t *st = (wifi_tls_step_t *)step;
    char text[64];
    uint32_t w = st->verify_flags;
    bool pin = (e->trust == WIFI_TLS_TRUST_PIN);
    switch (st->fail_reason) {
        case WIFI_TLS_FAIL_NONE:
            if (st->alert_in != WIFI_TLS_ALERT_NONE) {
                put_dec(put_text(text, "14,TLS ALERT RECEIVED: "), st->alert_in);
            } else {
                put_error(put_text(text, "13,TLS HANDSHAKE FAILED: "), st->esp_err);
            }
            return set_status(text);
        case WIFI_TLS_FAIL_VERSION_REFUSED:
            put_hex(put_text(text, "18,TLS VERSION REFUSED: "), w & 0xFFFF, 4);
            return set_status(text);
        case WIFI_TLS_FAIL_DOWNGRADE:
            return &c_status_tls_downgrade;
        case WIFI_TLS_FAIL_NO_EMS:
            return set_status("13,TLS HANDSHAKE FAILED: NO EMS");
        case WIFI_TLS_FAIL_CERT_VERIFY:
            if ((w == 0xFFFFFFFF) || pin) {
                put_hex(put_text(text, "93,CERTIFICATE NOT TRUSTED: "), w, 8);
            } else if (w & 0x04) { // MBEDTLS_X509_BADCERT_CN_MISMATCH
                put_hex(put_text(text, "94,CERTIFICATE NAME MISMATCH: "), w, 8);
            } else if (w & (0x01 | 0x200)) { // BADCERT_EXPIRED, BADCERT_FUTURE
                put_hex(put_text(text, "95,CERTIFICATE EXPIRED: "), w, 8);
            } else {
                put_hex(put_text(text, "93,CERTIFICATE NOT TRUSTED: "), w, 8);
            }
            return set_status(text);
        case WIFI_TLS_FAIL_PIN_MISMATCH:
            return pin ? &c_status_tls_pin_mismatch : &c_status_tls_module;
        case WIFI_TLS_FAIL_PEER_CLOSED:
            return set_status("13,TLS HANDSHAKE FAILED: PEER CLOSED");
        default:
            return &c_status_tls_module;
    }
}

// Step 8: the handshake, through to the STATS that the OPEN reply is made of.
// NULL when the session is ESTABLISHED; otherwise the code, and e->module_live
// says whether the module still holds the session.
Message *NetworkTarget :: tls_handshake(TlsSocket *e, uint32_t total)
{
    uint32_t started = xTaskGetTickCount();
    uint32_t deadline = earlier(tick_after(TLS_HANDSHAKE_MS), total);
    char text[64];
    bool more = true; // the first step, with no input, makes the ClientHello
    e->held_len = 0;
    while (true) {
        if (reset_now()) {
            return &c_status_tls_module;
        }
        if (reached(deadline)) {
            return &c_status_tls_hs_timeout;
        }
        if ((e->held_len == 0) && !more) {
            if (!tls_wait(e->socketnr, false, deadline)) {
                continue;
            }
            int n = lwip_recv(e->socketnr, e->held, NET_TLS_CT_MAX, MSG_DONTWAIT);
            if (n == 0) {
                return set_status("13,TLS HANDSHAKE FAILED: PEER CLOSED");
            }
            if (n < 0) {
                if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                    continue;
                }
                put_dec(put_text(text, "13,TLS HANDSHAKE FAILED: PEER RESET: "), errno);
                return set_status(text);
            }
            e->held_len = n;
        }
        wifi_tls_step_t st;
        memset(&st, 0, sizeof(st));
        st.ct_in = e->held;
        st.ct_in_len = e->held_len;
        st.ct_out = tls_ct_out;
        st.ct_out_room = sizeof(tls_ct_out);
        st.pt_out = tls_pt;
        st.pt_out_room = sizeof(tls_pt);
        int result = tls_run_step(e, &st, deadline, true);
        if (reset_now()) {
            return &c_status_tls_module;
        }
        if ((result != 0) && (result != WIFI_TLS_AGAIN)) {
            if ((result == WIFI_TLS_REFUSED) && (st.esp_err == WIFI_TLS_ESP_NOT_FOUND)) {
                e->module_live = false;
            }
            if ((result == WIFI_TLS_BUSY) && reached(deadline)) {
                return &c_status_tls_hs_timeout;
            }
            return &c_status_tls_module;
        }
        if (result == 0) {
            e->held_len = 0;
        }
        if (st.state == WIFI_TLS_FAILED || st.state == WIFI_TLS_CLOSED) {
            e->module_live = false;
        }
        // Every ciphertext goes out before the next step, a failure's alert too.
        if (st.ct_out_len) {
            int error = tls_send_all(e->socketnr, tls_ct_out, st.ct_out_len, deadline);
            if ((error != 0) && (st.state != WIFI_TLS_FAILED)) {
                if (error < 0) {
                    return &c_status_tls_module;
                }
                if ((error == ETIMEDOUT) && reached(deadline)) {
                    return &c_status_tls_hs_timeout;
                }
                // Section 2 gives 12 to READ/WRITE only; a send that fails
                // mid-handshake, by a reset or by SEND_MS (116), is a
                // handshake failure (D3, ruled).
                put_dec(put_text(text, "13,TLS HANDSHAKE FAILED: SEND ERROR: "), error);
                return set_status(text);
            }
        }
        if (st.state == WIFI_TLS_FAILED) {
            return tls_classify(e, &st);
        }
        if (st.state == WIFI_TLS_CLOSED) {
            return set_status("13,TLS HANDSHAKE FAILED: PEER CLOSED");
        }
        if (st.state == WIFI_TLS_ESTABLISHED) {
            if (st.pt_out_len) {
                memcpy(e->rx, tls_pt, st.pt_out_len);
                e->rx_len = st.pt_out_len;
            }
            e->module_more = true;
            break;
        }
        more = (st.ct_out_len != 0) || (result == WIFI_TLS_AGAIN);
    }

    // What the reply reports is the module's, never guessed here (1.7).
    tls_cancel_context_t context = { true, deadline };
    wifi_tls_cancel_t cancel = { tls_cancelled, &context };
    wifi_tls_stats_t stats;
    int esp_err;
    int result = wifi_tls_stats(e->slot, e->tag, &stats, &esp_err, TLS_STATS_RPC_MS, &cancel);
    if ((result != 0) || (stats.group == 0)) {
        if (!reset_now() && reached(deadline)) {
            return &c_status_tls_hs_timeout;
        }
        return &c_status_tls_module;
    }
    e->version = stats.tls_version;
    e->suite = stats.ciphersuite;
    e->group = stats.group;
    e->bits = stats.ems ? 0x01 : 0x00;
    memcpy(e->spki, stats.spki_sha256, sizeof(e->spki));
    e->handshake_ms = (xTaskGetTickCount() - started) * portTICK_PERIOD_MS;
    return NULL;
}

void NetworkTarget :: tls_reply_open(TlsSocket *e, Message **reply)
{
    uint8_t *m = data_message.message;
    m[0] = (uint8_t)e->socketnr;
    m[1] = (uint8_t)e->version;
    m[2] = (uint8_t)(e->version >> 8);
    m[3] = (uint8_t)e->suite;
    m[4] = (uint8_t)(e->suite >> 8);
    m[5] = (uint8_t)e->group;
    m[6] = (uint8_t)(e->group >> 8);
    m[7] = e->bits;
    data_message.length = 8;
    data_message.last_part = true;
    *reply = &data_message;
}

// A failed OPEN or START: the entry stays free, and the session goes on the
// module unless the module ended it itself.
void NetworkTarget :: tls_abandon(TlsSocket *e)
{
    e->used = false;
    tls_cleanup_close(e);
}

void NetworkTarget :: open_tls(Message *command, Message **reply, Message **status)
{
    *reply = &c_message_empty;
    // No reply means nothing opened (1.1): an OPEN whose handle nobody reads
    // could never be closed.
    if (command->message[0] & CMD_IF_NO_REPLY) {
        *status = &c_status_invalid_params;
        return;
    }
    uint8_t trust, flags;
    const uint8_t *pin;
    const char *host, *name;
    int host_len, name_len;
    Message *refusal = tls_parse_open(command, 6, false, &trust, &flags, &pin, &host, &host_len, &name,
                                      &name_len);
    // The effective server name: the explicit one, else the host unless that
    // is an IPv4 literal, else none.
    bool host_literal = refusal ? false : is_ipv4_literal(host, host_len);
    bool name_literal = (!refusal && name) ? is_ipv4_literal(name, name_len) : false;
    if (!refusal && (trust <= WIFI_TLS_TRUST_CUSTOM)) {
        if (name ? name_literal : host_literal) {
            refusal = &c_status_invalid_params; // BUNDLE and CUSTOM check a name (U11)
        }
    }
    if (!refusal) {
        if (trust > WIFI_TLS_TRUST_PIN) {
            refusal = &c_status_param_out_of_range;
        } else if (flags & 0xFE) {
            refusal = &c_status_param_out_of_range;
        } else if (pin) {
            int nonzero = 0;
            for (int i = 0; i < 32; i++) {
                nonzero |= pin[i];
            }
            if (!nonzero) {
                refusal = &c_status_param_out_of_range;
            }
        }
    }
    if (refusal) {
        *status = refusal;
        return;
    }
    const char *sni = name ? name : host;
    int sni_len = name ? name_len : host_len;
    if ((trust == WIFI_TLS_TRUST_PIN) && (name ? name_literal : host_literal)) {
        sni = NULL; // an IPv4 literal never reaches SNI
        sni_len = 0;
    }
    uint16_t port = uint16_t(command->message[2]) | (uint16_t(command->message[3]) << 8);
    char hostname[254];
    memcpy(hostname, host, host_len);
    hostname[host_len] = 0;

    uint32_t total = tick_after(TLS_OPEN_TOTAL_MS);
    TlsSocket *e = tls_reserve();
    bool keep;
    Message *failure = tls_prepare(e, trust, flags, pin, sni, sni_len, total, &keep);
    if (failure) {
        *status = failure;
        return;
    }
    // From here on, every refusal closes the session just opened (1.1).
    uint32_t address = 0;
    int result = tls_resolve(hostname, earlier(tick_after(TLS_DNS_MS), total), &address);
    if (result) {
        *status = (result < 0) ? &c_status_tls_module : &c_status_host_not_resolvable;
        tls_abandon(e);
        return;
    }
    int sock = lwip_socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        *status = &c_status_no_socket;
        tls_abandon(e);
        return;
    }
    if (sock > 255) {
        lwip_close(sock);
        *status = &c_status_internal_error;
        tls_abandon(e);
        return;
    }
    tls_socket_options(sock);
    result = tls_connect(sock, address, port, earlier(tick_after(TLS_CONNECT_MS), total));
    if (result) {
        lwip_close(sock);
        if (result < 0) {
            *status = &c_status_tls_module;
        } else {
            char text[40];
            put_dec(put_text(text, "11,ERROR ON CONNECT: "), result);
            *status = set_status(text);
        }
        tls_abandon(e);
        return;
    }
    e->socketnr = sock;
    failure = tls_handshake(e, total);
    if (failure || !track_socket(sock)) {
        *status = failure ? failure : &c_status_no_socket;
        lwip_close(sock);
        tls_abandon(e);
        return;
    }
    e->used = true;
    e->claimed = false;
    tls_reply_open(e, reply);
    *status = &c_status_ok;
}

void NetworkTarget :: start_tls(Message *command, Message **reply, Message **status)
{
    *reply = &c_message_empty;
    if (command->message[0] & CMD_IF_NO_REPLY) {
        *status = &c_status_invalid_params;
        return;
    }
    // The handle first, before any other check: a TCP socket this target
    // owns that is not TLS already (1.4). Every 81 here leaves it alone.
    if (command->length < 3) {
        *status = &c_status_invalid_params;
        return;
    }
    int sock = command->message[2];
    int type = -1;
    socklen_t type_len = sizeof(type);
    if (!owns_socket(sock) || (lwip_getsockopt(sock, SOL_SOCKET, SO_TYPE, &type, &type_len) < 0) ||
        (type != SOCK_STREAM) || tls_find(sock)) {
        *status = &c_status_invalid_params;
        return;
    }
    uint8_t trust, flags;
    const uint8_t *pin;
    const char *host, *name;
    int host_len, name_len;
    Message *refusal = tls_parse_open(command, 5, true, &trust, &flags, &pin, &host, &host_len, &name,
                                      &name_len);
    bool name_literal = (!refusal && name) ? is_ipv4_literal(name, name_len) : false;
    if (!refusal && (trust <= WIFI_TLS_TRUST_CUSTOM) && (!name || name_literal)) {
        refusal = &c_status_invalid_params;
    }
    if (!refusal) {
        if ((trust > WIFI_TLS_TRUST_PIN) || (flags & 0xFE)) {
            refusal = &c_status_param_out_of_range;
        } else if (pin) {
            int nonzero = 0;
            for (int i = 0; i < 32; i++) {
                nonzero |= pin[i];
            }
            if (!nonzero) {
                refusal = &c_status_param_out_of_range;
            }
        }
    }
    if (refusal) {
        *status = refusal;
        return;
    }
    if (name_literal) {
        name = NULL; // PIN: an IPv4 literal never reaches SNI
        name_len = 0;
    }
    uint32_t total = tick_after(TLS_OPEN_TOTAL_MS);
    TlsSocket *e = tls_reserve();
    bool keep;
    Message *failure = tls_prepare(e, trust, flags, pin, name, name_len, total, &keep);
    if (failure && keep) {
        *status = failure; // nothing was sent: the TCP handle is as it was
        return;
    }
    if (!failure) {
        // Only now, so that a kept code leaves the socket truly unchanged.
        tls_socket_options(sock);
        e->socketnr = sock;
        failure = tls_handshake(e, total);
    }
    if (failure) {
        // Every other code ends the handle (1.4).
        *status = failure;
        untrack_socket(sock);
        lwip_close(sock);
        tls_abandon(e);
        return;
    }
    e->used = true;
    e->claimed = false;
    tls_reply_open(e, reply);
    *status = &c_status_ok;
}

// $22 (1.2): the Nios owns the CA state; the module gets the certificate once
// it is complete.
void NetworkTarget :: trust_ca(Message *command, Message **reply, Message **status)
{
    *reply = &c_message_empty;
    if (command->length < 6) {
        *status = &c_status_invalid_params;
        return;
    }
    const uint8_t *m = command->message;
    uint16_t offset = uint16_t(m[2]) | (uint16_t(m[3]) << 8);
    uint16_t total = uint16_t(m[4]) | (uint16_t(m[5]) << 8);
    int chunk = command->length - 6;
    if (offset == 0) {
        if (total == 0) {
            if (chunk) {
                *status = &c_status_invalid_params;
                return;
            }
            ca_state = CA_EMPTY; // cleared
            tls_new_ca_tag();
            *status = &c_status_ok;
            return;
        }
        // Any start drops the installed CA at once, under a new tag.
        ca_state = CA_EMPTY;
        tls_new_ca_tag();
        if (total > NET_TLS_CA_MAX) {
            *status = &c_status_param_out_of_range;
            return;
        }
        ca_state = CA_UPLOADING;
        ca_len = 0;
        ca_total = total;
    } else {
        // Only offset 0 touches an installed CA; a sequence error drops an upload.
        if (ca_state != CA_UPLOADING) {
            *status = &c_status_invalid_params;
            return;
        }
        if ((offset != ca_len) || (total != ca_total)) {
            ca_state = CA_EMPTY;
            *status = &c_status_invalid_params;
            return;
        }
    }
    if (ca_len + chunk > ca_total) {
        ca_state = CA_EMPTY;
        *status = &c_status_invalid_params;
        return;
    }
    memcpy(&ca_buf[ca_len], &m[6], chunk);
    ca_len += chunk;
    if (ca_len < ca_total) {
        *status = &c_status_ok;
        return;
    }

    // The final chunk.
    ca_state = CA_EMPTY;
    if (!wifi_tls_module_available()) {
        *status = &c_status_tls_not_available;
        return;
    }
    tls_cancel_context_t context = { false, 0 };
    wifi_tls_cancel_t cancel = { tls_cancelled, &context };
    int esp_err;
    uint8_t reject;
    int result;
    for (int i = 0; ; i++) {
        result = wifi_tls_set_ca(ca_buf, ca_len, ca_tag, &esp_err, &reject, TLS_OPEN_RPC_MS, &cancel);
        if ((result != WIFI_TLS_UNSENT) || (i == TLS_UNSENT_RETRIES) || reset_now()) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(TLS_UNSENT_DELAY_MS));
    }
    char text[64];
    if (result == 0) {
        ca_state = CA_LOADED;
        *status = &c_status_ok;
    } else if (result == WIFI_TLS_NO_MODULE) {
        *status = &c_status_tls_not_available;
    } else if ((result == WIFI_TLS_REFUSED) && (esp_err == WIFI_TLS_ESP_NOT_SUPPORTED) && (reject == 0)) {
        *status = &c_status_tls_not_available;
    } else if ((result == WIFI_TLS_REFUSED) && (reject == WIFI_TLS_REJECT_NONE) && (esp_err <= -2)) {
        put_error(put_text(text, "97,CUSTOM CA INVALID: "), esp_err);
        *status = set_status(text);
    } else if ((result == WIFI_TLS_REFUSED) && (reject == WIFI_TLS_REJECT_RSA_KEY_SHORT)) {
        *status = set_status("97,CUSTOM CA REJECTED: RSA KEY < 2048");
    } else if ((result == WIFI_TLS_REFUSED) && (reject == WIFI_TLS_REJECT_CURVE)) {
        *status = set_status("97,CUSTOM CA REJECTED: CURVE");
    } else if ((result == WIFI_TLS_REFUSED) && (reject == WIFI_TLS_REJECT_NOT_CA)) {
        *status = set_status("97,CUSTOM CA REJECTED: NOT A CA");
    } else {
        *status = &c_status_tls_module;
    }
    if (ca_state != CA_LOADED) {
        tls_new_ca_tag(); // whatever the module holds can no longer match
    }
}

void NetworkTarget :: tls_info(Message *command, Message **reply, Message **status)
{
    *reply = &c_message_empty;
    if (command->length != 3) {
        *status = &c_status_invalid_params;
        return;
    }
    uint8_t *m = data_message.message;
    uint8_t handle = command->message[2];
    if (handle == 0xFF) {
        memset(m, 0, 16);
        m[0] = 1;
        m[1] = NET_MAX_TLS;
        m[2] = (uint8_t)tls_in_use(false);
        m[3] = 0x07; // BUNDLE, CUSTOM, PIN
        m[5] = 0x03; // TLS 1.2 (hardened), TLS 1.3
        uint32_t now = sntp_utc_now();
        uint8_t ready = (ca_state == CA_LOADED) ? 0x08 : 0x00;
        if (now >= TLS_EARLIEST_TIME) {
            ready |= 0x04;
        }
        if (wifi_tls_module_available()) {
            uint16_t major, minor;
            wifi_tls_module_version(&major, &minor);
            m[6] = (uint8_t)major;
            m[7] = (uint8_t)minor;
            m[8] = (uint8_t)(minor >> 8);
            uint32_t generation = wifi_tls_generation();
            if (info_valid && (info_generation != generation)) {
                info_valid = false; // the module restarted
            }
            tls_cancel_context_t context = { false, 0 };
            wifi_tls_cancel_t cancel = { tls_cancelled, &context };
            wifi_tls_stats_t stats;
            int esp_err;
            int result = wifi_tls_stats(WIFI_TLS_SLOT_GLOBAL, 0, &stats, &esp_err, TLS_STATS_RPC_MS, &cancel);
            if (result == 0) {
                info_valid = true;
                info_generation = generation;
                info_ready = 0x01 | (stats.entropy_source ? 0x02 : 0) | (stats.time_source ? 0x04 : 0);
                info_block_max_ms = stats.block_max_ms;
            } else if ((result == WIFI_TLS_NO_MODULE) ||
                       ((result == WIFI_TLS_REFUSED) && (esp_err == WIFI_TLS_ESP_NOT_SUPPORTED))) {
                // No module application, or no TLS in it. Anything else (no
                // answer, a full TLS queue's ESP_ERR_TIMEOUT, a bad answer)
                // says the module is busy, and the last good STATS stands.
                info_valid = false;
            }
        } else {
            info_valid = false;
        }
        if (info_valid) {
            ready |= info_ready;
            m[12] = (uint8_t)info_block_max_ms;
            m[13] = (uint8_t)(info_block_max_ms >> 8);
            // The CA store date: no reply carries it, so "a bundle, date
            // unknown" (Amendment 3, errata v1.2 candidate).
            m[9] = 0xFF;
            m[10] = 0xFF;
            m[11] = 0xFF;
        }
        m[4] = ready;
        m[14] = (uint8_t)tls_in_use(true);
        data_message.length = 16;
        data_message.last_part = true;
        *reply = &data_message;
        *status = &c_status_ok;
        return;
    }
    TlsSocket *e = tls_find(handle);
    if (!e) {
        *status = &c_status_invalid_params;
        return;
    }
    memset(m, 0, 48);
    m[0] = (uint8_t)e->version;
    m[1] = (uint8_t)(e->version >> 8);
    m[2] = (uint8_t)e->suite;
    m[3] = (uint8_t)(e->suite >> 8);
    m[4] = (uint8_t)e->group;
    m[5] = (uint8_t)(e->group >> 8);
    m[6] = e->trust;
    m[7] = e->bits;
    memcpy(&m[8], e->spki, 32);
    m[40] = (uint8_t)e->handshake_ms;
    m[41] = (uint8_t)(e->handshake_ms >> 8);
    m[42] = (uint8_t)(e->handshake_ms >> 16);
    m[43] = (uint8_t)(e->handshake_ms >> 24);
    data_message.length = 48;
    data_message.last_part = true;
    *reply = &data_message;
    *status = &c_status_ok;
}

void NetworkTarget :: tls_release(Message *command, Message **reply, Message **status)
{
    *reply = &c_message_empty;
    if (command->length != 2) {
        *status = &c_status_invalid_params;
        return;
    }
    int closed = 0;
    for (int i = 0; i < NET_MAX_TLS; i++) {
        if (tls[i].used && !tls[i].claimed) {
            tls_close_entry(&tls[i], true);
            closed++;
        }
    }
    data_message.message[0] = (uint8_t)closed;
    data_message.length = 1;
    data_message.last_part = true;
    *reply = &data_message;
    *status = &c_status_ok;
}

static void read_header(Message *m, uint16_t value)
{
    m->message[0] = (uint8_t)value;
    m->message[1] = (uint8_t)(value >> 8);
    m->length = 2;
    m->last_part = true;
}

// The end of a stream whose plaintext has all been read: $0000 and the
// status; the handle is gone after 01 and 05, and owned until CLOSE after a
// sticky failure.
void NetworkTarget :: tls_end(TlsSocket *e, Message **reply, Message **status)
{
    read_header(&data_message, 0);
    *reply = &data_message;
    char text[NET_TLS_STICKY_MAX];
    // A WRITE that reported the latched 12 fixes the end to that 12, also
    // when the drain had found close_notify before it (4.3, r7.5 L-2): the
    // client was told to CLOSE, so the handle must still be its own (M10).
    if (e->write_saw_rx_err && (e->end != TLS_END_NONE)) {
        e->end = TLS_END_RX_ERR;
    }
    if (e->end == TLS_END_RX_ERR) {
        put_dec(put_text(text, "12,RECEIVE ERROR: "), e->rx_err);
        tls_fail(e, text);
    }
    if (e->failed) {
        *status = set_status(e->sticky);
        return;
    }
    if (e->end == TLS_END_CLOSED) {
        tls_close_entry(e, false);
        *status = &c_status_socket_closed;
    } else {
        tls_close_entry(e, true);
        *status = &c_status_tls_no_notify;
    }
}

// READ on a TLS handle (1.6, 4.3): plaintext already received first; else
// steps, within READ_BUDGET, until one hands out plaintext or the stream
// ends.
void NetworkTarget :: tls_read(TlsSocket *e, uint32_t length, Message **reply, Message **status)
{
    *reply = &c_message_empty;
    if ((length == 0) || (length > NET_MAX_SOCKET_READ)) {
        *status = &c_status_param_out_of_range;
        return;
    }
    if (!e->failed && (e->rx_len == 0) && (e->end == TLS_END_NONE)) {
        uint32_t deadline = tick_after(TLS_READ_TOTAL_MS);
        uint32_t budget_end = tick_after(TLS_READ_BUDGET_MS);
        int steps = 0;
        while (!reset_now()) {
            // Eager: top up the ciphertext before each step, unless the
            // stream has ended or a receive error is latched (4.3).
            if (!e->rx_err && !e->rx_fin && (e->held_len < NET_TLS_CT_MAX)) {
                int n = lwip_recv(e->socketnr, e->held + e->held_len, NET_TLS_CT_MAX - e->held_len, MSG_DONTWAIT);
                if (n > 0) {
                    e->held_len += n;
                } else if (n == 0) {
                    e->rx_fin = true;
                } else if ((errno != EWOULDBLOCK) && (errno != EAGAIN)) {
                    e->rx_err = errno; // the first one; no receive after it
                }
            }
            bool draining = e->rx_err || e->rx_fin;
            if ((e->held_len == 0) && !e->module_more && !draining) {
                // Nothing to feed, and the module had nothing more to say.
                uint32_t until = earlier(earlier(tick_after(TLS_READ_WAIT_MS), budget_end), deadline);
                bool ready = false;
                while (!ready && !reached(until) && !reset_now()) {
                    ready = tls_wait(e->socketnr, false, until);
                }
                if (!ready) {
                    break;
                }
                continue;
            }
            if ((steps >= TLS_READ_BUDGET_STEPS) || reached(budget_end) || reached(deadline)) {
                break;
            }
            wifi_tls_step_t st;
            memset(&st, 0, sizeof(st));
            st.ct_in = e->held;
            st.ct_in_len = e->held_len;
            st.ct_out = tls_ct_out;
            st.ct_out_room = sizeof(tls_ct_out);
            st.pt_out = tls_pt;
            st.pt_out_room = sizeof(tls_pt);
            uint16_t fed = e->held_len;
            int result = tls_run_step(e, &st, deadline, true);
            steps++;
            if (reset_now()) {
                break;
            }
            if ((result != 0) && (result != WIFI_TLS_AGAIN)) {
                bool gone = (result == WIFI_TLS_REFUSED) && (st.esp_err == WIFI_TLS_ESP_NOT_FOUND);
                tls_fail_module(e, !gone);
                break;
            }
            if (result == 0) {
                e->held_len = 0;
            }
            if (st.ct_out_len) {
                int error = tls_send_all(e->socketnr, tls_ct_out, st.ct_out_len, deadline);
                if (error < 0) {
                    break;
                }
                // After a receive error the peer is gone; its alert need not arrive.
                if (error && !e->rx_err && (st.state != WIFI_TLS_FAILED)) {
                    char text[NET_TLS_STICKY_MAX];
                    put_dec(put_text(text, "12,SEND ERROR: "), error);
                    tls_fail(e, text);
                    break;
                }
            }
            e->module_more = (st.ct_out_len != 0) || (st.pt_out_len != 0) || (result == WIFI_TLS_AGAIN);
            if (st.state == WIFI_TLS_FAILED) {
                e->module_live = false;
                if (e->write_saw_rx_err) {
                    e->end = TLS_END_RX_ERR; // a WRITE already said 12; plaintext read so far stays
                } else {
                    tls_fail_step(e, st.esp_err, st.alert_in);
                }
                break;
            }
            if (st.pt_out_len) {
                memcpy(e->rx, tls_pt, st.pt_out_len);
                e->rx_off = 0;
                e->rx_len = st.pt_out_len;
            }
            if (st.state == WIFI_TLS_CLOSED) {
                // close_notify wins over a latched receive error, unless a
                // WRITE has reported that error already.
                e->module_live = false;
                e->module_more = false;
                e->end = e->write_saw_rx_err ? TLS_END_RX_ERR : TLS_END_CLOSED;
                break;
            }
            if (st.state != WIFI_TLS_ESTABLISHED) {
                tls_fail_module(e, true);
                break;
            }
            if (e->rx_len) {
                e->quiet = 0; // plaintext: not a quiet step
                break;
            }
            if (draining && (fed == 0)) {
                // Two quiet input-less steps: the module holds nothing more.
                if (++e->quiet >= 2) {
                    e->end = e->rx_err ? TLS_END_RX_ERR : TLS_END_NO_NOTIFY;
                    break;
                }
            } else {
                e->quiet = 0;
            }
        }
    }
    if (e->rx_len) {
        int n = (e->rx_len < length) ? e->rx_len : length;
        memcpy(buffer, e->rx + e->rx_off, n);
        e->rx_off += n;
        e->rx_len -= n;
        if (!e->rx_len) {
            e->rx_off = 0;
        }
        read_header(&data_message, n);
        start_read_reply(n, &c_status_ok, reply, status);
        return;
    }
    if (e->failed || (e->end != TLS_END_NONE)) {
        tls_end(e, reply, status);
        return;
    }
    // Nothing yet: the same answer as an idle TCP read.
    read_header(&data_message, 0xFFFF);
    *reply = &data_message;
    char text[24];
    put_dec(put_text(text, "02,NO DATA: "), EWOULDBLOCK);
    *status = set_status(text);
}

static void write_header(Message *m, Message **reply, uint16_t value)
{
    read_header(m, value);
    *reply = m;
}

// WRITE on a TLS handle (1.6): all of it, or a sticky failure. The steps take
// no ciphertext in and hand no plaintext out (NO_READ).
void NetworkTarget :: tls_write(TlsSocket *e, const uint8_t *data, int length, Message **reply, Message **status)
{
    char text[NET_TLS_STICKY_MAX];
    if (e->failed) {
        write_header(&data_message, reply, 0xFFFF);
        *status = set_status(e->sticky);
        return;
    }
    if (e->rx_err) {
        // Nothing is sent; the READs go on draining, and end in this 12 (4.3).
        e->write_saw_rx_err = true;
        write_header(&data_message, reply, 0xFFFF);
        put_dec(put_text(text, "12,RECEIVE ERROR: "), e->rx_err);
        *status = set_status(text);
        return;
    }
    if (!e->module_live) {
        // The peer's close_notify ended the session on the module.
        put_dec(put_text(text, "12,SEND ERROR: "), EPIPE);
        tls_fail(e, text);
        write_header(&data_message, reply, 0xFFFF);
        *status = set_status(e->sticky);
        return;
    }
    if (length == 0) {
        write_header(&data_message, reply, 0);
        *status = &c_status_ok;
        return;
    }
    uint32_t deadline = tick_after(TLS_WRITE_TOTAL_MS);
    int pending = length;
    int steps = 0;
    while (true) {
        if (reset_now()) {
            tls_fail(e, "17,TLS MODULE NOT RESPONDING");
            break;
        }
        if (steps >= TLS_WRITE_BUDGET) {
            tls_fail_module(e, true);
            break;
        }
        wifi_tls_step_t st;
        memset(&st, 0, sizeof(st));
        st.flags = WIFI_TLS_STEP_NO_READ;
        st.pt_in = data;
        st.pt_in_len = pending;
        st.ct_out = tls_ct_out;
        st.ct_out_room = sizeof(tls_ct_out);
        st.pt_out = tls_pt;
        st.pt_out_room = sizeof(tls_pt);
        int result = tls_run_step(e, &st, deadline, true);
        steps++;
        if (reset_now()) {
            tls_fail(e, "17,TLS MODULE NOT RESPONDING");
            break;
        }
        if ((result != 0) && (result != WIFI_TLS_AGAIN)) {
            bool gone = (result == WIFI_TLS_REFUSED) && (st.esp_err == WIFI_TLS_ESP_NOT_FOUND);
            tls_fail_module(e, !gone);
            break;
        }
        if (result == 0) {
            pending = 0;
        }
        if (st.ct_out_len) {
            int error = tls_send_all(e->socketnr, tls_ct_out, st.ct_out_len, deadline);
            if (error) {
                if (error < 0) {
                    tls_fail(e, "17,TLS MODULE NOT RESPONDING");
                } else {
                    put_dec(put_text(text, "12,SEND ERROR: "), error);
                    tls_fail(e, text); // the ciphertext may be torn
                }
                break;
            }
        }
        if (st.state == WIFI_TLS_FAILED) {
            tls_fail_step(e, st.esp_err, st.alert_in);
            break;
        }
        if (st.state != WIFI_TLS_ESTABLISHED) {
            tls_fail_module(e, st.state != WIFI_TLS_CLOSED);
            break;
        }
        if ((pending == 0) && (st.ct_out_len == 0)) {
            write_header(&data_message, reply, (uint16_t)length);
            *status = &c_status_ok;
            return;
        }
    }
    write_header(&data_message, reply, 0xFFFF);
    *status = set_status(e->sticky);
}

#else // !NET_TLS

// Without the WiFi module the commands exist, and TLS is not available.
void NetworkTarget :: open_tls(Message *command, Message **reply, Message **status)
{
    uint8_t trust, flags;
    const uint8_t *pin;
    const char *host, *name;
    int host_len, name_len;
    *reply = &c_message_empty;
    *status = tls_parse_open(command, 6, false, &trust, &flags, &pin, &host, &host_len, &name, &name_len);
    if (!*status) {
        *status = &c_status_tls_not_available;
    }
}

void NetworkTarget :: start_tls(Message *command, Message **reply, Message **status)
{
    *reply = &c_message_empty;
    *status = (command->length < 3) || !owns_socket(command->message[2]) ? &c_status_invalid_params
                                                                        : &c_status_tls_not_available;
}

void NetworkTarget :: trust_ca(Message *command, Message **reply, Message **status)
{
    *reply = &c_message_empty;
    *status = (command->length < 6) ? &c_status_invalid_params : &c_status_tls_not_available;
}

void NetworkTarget :: tls_info(Message *command, Message **reply, Message **status)
{
    *reply = &c_message_empty;
    if ((command->length != 3) || (command->message[2] != 0xFF)) {
        *status = &c_status_invalid_params;
        return;
    }
    uint8_t *m = data_message.message;
    memset(m, 0, 16);
    m[0] = 1;
    m[1] = NET_MAX_TLS;
    m[3] = 0x07;
    m[5] = 0x03;
    data_message.length = 16;
    data_message.last_part = true;
    *reply = &data_message;
    *status = &c_status_ok;
}

void NetworkTarget :: tls_release(Message *command, Message **reply, Message **status)
{
    *reply = &c_message_empty;
    if (command->length != 2) {
        *status = &c_status_invalid_params;
        return;
    }
    data_message.message[0] = 0;
    data_message.length = 1;
    data_message.last_part = true;
    *reply = &data_message;
    *status = &c_status_ok;
}

#endif // NET_TLS
