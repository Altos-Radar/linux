// SPDX-License-Identifier: MIT
/*
 * RPMSG Videobuf protocol
 *
 * Michael Wu <mwu.code@gmail.com>
 */

enum rpvb_msg_type {
	RPVB_MSG_TYPE_QUERY = 0,
	RPVB_MSG_TYPE_QUERY_RESP = 1,
	RPVB_MSG_TYPE_QUEUE = 2,
	RPVB_MSG_TYPE_DEQUEUE = 3,
};

enum rpvb_query_resp_subtype {
	RPVB_QUERY_RESP_BASE = 0,
	RPVB_QUERY_RESP_QUEUE = 1,
};

// Also used as-is in QUERY
struct rpvb_msg_header {
	uint16_t type;
};

struct rpvb_msg_query_resp_header {
	uint16_t type;
	uint16_t subtype;
};

struct rpvb_msg_query_resp_base {
	uint16_t type;
	uint16_t sub_type;
	char name[32];
	uint16_t tx_queues;
	uint16_t rx_queues;
	uint32_t width;
	uint32_t height;
	uint32_t fourcc;
};

struct rpvb_msg_query_resp_queue {
	uint16_t type;
	uint16_t sub_type;
	uint32_t stride;
	uint32_t size;
	uint16_t queue_index;
};

struct rpvb_msg_queue {
	uint16_t type;
	uint16_t queue_index;
	uint16_t sections;
	uint32_t size;
	uint64_t addr[];
};

struct rpvb_msg_dequeue {
	uint16_t type;
	uint16_t queue_index;
	uint32_t size;
};
