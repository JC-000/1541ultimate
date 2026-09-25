/*
 * rpc_calls.h
 *
 *  Created on: Nov 7, 2021
 *      Author: gideon
 */

#ifndef SOFTWARE_WIFI_SCAN_MAIN_RPC_CALLS_H_
#define SOFTWARE_WIFI_SCAN_MAIN_RPC_CALLS_H_

#include <stdint.h>
#include "lwip/sockets.h"
#include "lwip/netdb.h"

#define DEFAULT_SCAN_LIST_SIZE 24

typedef struct {
    uint8_t command;
    uint8_t thread;
    uint16_t sequence;
} rpc_header_t;

typedef struct {
    rpc_header_t hdr;
    int esp_err; // to be casted to esp_err_t
} rpc_espcmd_resp;

typedef struct {
    rpc_header_t hdr;
} rpc_identify_req;

typedef struct {
    rpc_header_t hdr;
    uint16_t major;
    uint16_t minor;
    char string;
} rpc_identify_resp;

typedef struct {
    rpc_header_t hdr;
    int esp_err; // to be casted to esp_err_t
    uint16_t vbus;
    uint16_t vaux;
    uint16_t v50;
    uint16_t v33;
    uint16_t v18;
    uint16_t v10;
    uint16_t vusb;
} rpc_get_voltages_resp;

typedef struct {
    rpc_header_t hdr;
    int esp_err; // to be casted to esp_err_t
    uint8_t mac[6];
} rpc_getmac_resp;

typedef struct {
    rpc_header_t hdr;
    int esp_err; // to be casted to esp_err_t
    uint8_t status;
} rpc_get_connection_resp;

typedef struct {
    rpc_header_t hdr;
    int baudrate;
    uint8_t flowctrl;
    uint8_t inversions;
} rpc_setbaud_req;

typedef struct {
    rpc_header_t hdr;
    uint8_t auth_mode; // to be casted to wifi_auth_mode_t
    char ssid[32];
    char password[64];
} rpc_wifi_connect_req;

/* 42 byte AP record */
typedef struct {
    uint8_t bssid[6];            // MAC address of AP
    uint8_t ssid[33];            // SSID of AP
    uint8_t channel;             // channel of AP
    int8_t  rssi;                // signal strength of AP
    uint8_t authmode;            // authmode of AP
} ultimate_ap_record_t;

typedef struct {
    uint8_t num_records;
    uint8_t reserved;
    ultimate_ap_record_t aps[DEFAULT_SCAN_LIST_SIZE];
} ultimate_ap_records_t;

typedef struct {
    rpc_header_t hdr;
    int esp_err;
    ultimate_ap_records_t rec;
} rpc_scan_resp;

typedef struct {
    rpc_header_t hdr;
    u16_t len;
    char data;
} rpc_rx_pkt;

typedef struct {
    rpc_header_t hdr;
    char timezone[128];
} rpc_get_time_req;

typedef struct {
    uint16_t year;
    uint8_t month;
    uint8_t day;
    uint8_t weekday;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
} esp_datetime_t;

typedef struct {
    rpc_header_t hdr;
    int esp_err;
    esp_datetime_t datetime;
} rpc_get_time_resp;

//----------------------------------
// hardware random bytes
#define RANDOM_MAX_BYTES 512

typedef enum {
    ENTROPY_NONE  = 0, // RNG not fed by a live entropy source; no bytes are returned
    ENTROPY_RADIO = 1, // Wi-Fi is running, so the RNG gives true random numbers
    ENTROPY_ADC   = 2, // reserved
} entropy_source_t;

typedef struct {
    rpc_header_t hdr;
    uint16_t length;
} rpc_get_random_req;

typedef struct {
    rpc_header_t hdr;
    int esp_err; // to be casted to esp_err_t
    uint8_t source; // to be casted to entropy_source_t
    uint16_t length;
    uint8_t data[]; // sizeof() excludes it, so it is exactly the header size
} rpc_get_random_resp;

//----------------------------------
// TLS sessions: the module holds the keys, the host carries the ciphertext
#define TLS_FLAG_VERIFY     0x01 // verify the server's chain and name
#define TLS_FLAG_CA_BUNDLE  0x02 // trust the CA bundle
#define TLS_FLAG_TEST_CA    0x04 // trust the built in test CA
#define TLS_SESSION_GLOBAL  0xFF // STATS for the module as a whole
#define TLS_STEP_MAX_IN     1024 // ct_in_len + pt_in_len in one step
#define TLS_STEP_MAX_OUT    1024 // ct_out_len + pt_out_len in one step

typedef enum {
    TLS_STATE_HANDSHAKING = 0,
    TLS_STATE_ESTABLISHED = 1,
    TLS_STATE_CLOSED      = 2,
    TLS_STATE_FAILED      = 3, // esp_err holds the mbedTLS error
} tls_state_t;

typedef struct {
    rpc_header_t hdr;
    uint8_t flags; // TLS_FLAG_*
    uint8_t sni_len;
    char sni[]; // sni_len bytes, not terminated
} rpc_tls_open_req;

typedef struct {
    rpc_header_t hdr;
    int esp_err; // to be casted to esp_err_t
    uint8_t session;
} rpc_tls_open_resp;

typedef struct {
    rpc_header_t hdr;
    uint8_t session;
    uint8_t reserved;
    uint16_t ct_in_len;
    uint16_t pt_in_len;
    uint8_t data[]; // ct_in, then pt_in
} rpc_tls_step_req;

typedef struct {
    rpc_header_t hdr;
    int esp_err; // to be casted to esp_err_t, or the mbedTLS error when FAILED
    uint8_t state; // to be casted to tls_state_t
    uint8_t reserved;
    uint16_t ct_out_len;
    uint16_t pt_out_len;
    uint16_t reserved2; // so that data starts at sizeof()
    uint8_t data[]; // ct_out, then pt_out
} rpc_tls_step_resp;

typedef struct {
    rpc_header_t hdr;
    uint8_t session;
} rpc_tls_close_req; // answered with rpc_espcmd_resp

typedef struct {
    rpc_header_t hdr;
    uint8_t session; // or TLS_SESSION_GLOBAL
} rpc_tls_stats_req;

typedef struct {
    rpc_header_t hdr;
    int esp_err; // to be casted to esp_err_t
    uint32_t heap_free;
    uint32_t heap_min_ever;
    uint32_t largest_block;
    uint32_t ct_in_bytes; // the session's counters; 0 for TLS_SESSION_GLOBAL
    uint32_t ct_out_bytes;
    uint32_t pt_in_bytes;
    uint32_t pt_out_bytes;
    uint32_t handshake_us;
    uint16_t tls_version; // as on the wire: 0x0304 is TLS 1.3
    uint16_t ciphersuite; // IANA number, e.g. 0x1301
    uint16_t group; // IANA NamedGroup, e.g. 0x001D for X25519
    uint16_t reserved;
} rpc_tls_stats_resp;

//----------------------------------
// send raw packet
typedef struct {
    rpc_header_t hdr;
    uint32_t length;
    char data;
} rpc_send_eth_req;

typedef struct { // this response might be deprecated soon
    rpc_header_t hdr;
} rpc_send_eth_resp;

// Events
typedef struct {
    rpc_header_t hdr;
    uint32_t ip;       // to be casted to [esp_]ip4_addr_t
    uint32_t netmask;  // to be casted to [esp_]ip4_addr_t
    uint32_t gw;       // to be casted to [esp_]ip4_addr_t
    uint8_t changed;
} event_pkt_got_ip;

typedef struct {
    rpc_header_t hdr;
    uint8_t ssid[32];
} event_pkt_connected;

#define CMD_ECHO              0x01
#define CMD_IDENTIFY          0x02
#define CMD_SET_BAUD          0x03
#define CMD_WIFI_SCAN         0x04
#define CMD_WIFI_CONNECT      0x05
#define CMD_WIFI_DISCONNECT   0x06
#define CMD_WIFI_GETMAC       0x07
#define CMD_SEND_PACKET       0x08
#define CMD_MODEM_ON          0x09
#define CMD_MODEM_OFF         0x0A
#define CMD_WIFI_IS_CONNECTED 0x0B
#define CMD_GET_VOLTAGES      0x0C
#define CMD_WIFI_ENABLE       0x0D
#define CMD_WIFI_DISABLE      0x0E
#define CMD_MACHINE_OFF       0x0F
#define CMD_GET_TIME          0x10
#define CMD_CLEAR_APS         0x11
#define CMD_WIFI_AUTOCONNECT  0x12
#define CMD_GET_RANDOM        0x13
#define CMD_TLS_OPEN          0x30
#define CMD_TLS_STEP          0x31
#define CMD_TLS_CLOSE         0x32
#define CMD_TLS_STATS         0x33

/*
#define CMD_SOCKET          0x11
#define CMD_CONNECT         0x12
#define CMD_ACCEPT          0x13
#define CMD_BIND            0x14
#define CMD_SHUTDOWN        0x15
#define CMD_CLOSE           0x16
#define CMD_LISTEN          0x17
#define CMD_READ            0x18
#define CMD_RECV            0x19
#define CMD_RECVFROM        0x1A
#define CMD_WRITE           0x1B
#define CMD_SEND            0x1C
#define CMD_SENDTO          0x1D
#define CMD_GETHOSTBYNAME   0x21
#define CMD_GETPEERNAME     0x22
#define CMD_GETSOCKNAME     0x23
#define CMD_GETSOCKOPT      0x24
#define CMD_SETSOCKOPT      0x25
#define CMD_IOCTL           0x28
#define CMD_FCNTL           0x29
*/
#define EVENT_CONNECTED     0x40
#define EVENT_GOTIP         0x41
#define EVENT_DISCONNECTED  0x42
#define EVENT_RECV_PACKET   0x43
#define EVENT_RESCAN        0x44
#define EVENT_KEEPALIVE     0x45
#define EVENT_DISABLED      0x46

#define EVENT_BUTTON        0x80
#define EVENT_FREEZE        0x81
#define EVENT_MENU          0x82
#define EVENT_RESET         0x83

#define EVENT_JOYSTICK      0x90


#endif /* SOFTWARE_WIFI_SCAN_MAIN_RPC_CALLS_H_ */
