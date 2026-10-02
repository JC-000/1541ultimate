// Stand-in for lwIP's sockets.h on the build host. rpc_calls.h needs only the u16_t type from it.
#ifndef LWIP_SOCKETS_H_STUB
#define LWIP_SOCKETS_H_STUB
#include <stdint.h>
typedef uint16_t u16_t;
#endif
