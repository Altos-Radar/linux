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
	RPVB_MSG_TYPE_SET_CONTROL = 4,
};

enum rpvb_query_resp_subtype {
	RPVB_QUERY_RESP_BASE = 0,
	RPVB_QUERY_RESP_QUEUE = 1,
	RPVB_QUERY_RESP_CONTROL = 2,
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
	uint32_t controls;
};

struct rpvb_msg_query_resp_queue {
	uint16_t type;
	uint16_t sub_type;
	uint32_t stride;
	uint32_t size;
	uint16_t queue_index;
};

// Subset of V4L2's control types
enum rpvb_control_type {
	RPVB_CTRL_TYPE_INT = 1,
	RPVB_CTRL_TYPE_BOOLEAN = 2,
	RPVB_CTRL_TYPE_INT64 = 5,
	RPVB_CTRL_COMPOUND_U8 = 0x0100,
	RPVB_CTRL_COMPOUND_U16 = 0x0101,
	RPVB_CTRL_COMPOUND_U32 = 0x0102,
};

struct rpvb_msg_query_resp_control {
	uint16_t type;
	uint16_t sub_type;
	char name[32];
	uint16_t ctrl_type;
	uint16_t index;
	int64_t minimum;
	int64_t maximum;
	uint64_t step;
	int64_t default_value;
	uint32_t elem_size;
	uint32_t elems;
	uint32_t dims[4];
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

struct rpvb_msg_set_control_header {
	uint16_t type;
	uint16_t ctrl_type;
	uint32_t ctrl_index;
};

// Also used for RPVB_CTRL_TYPE_BOOLEAN
struct rpvb_msg_set_control_int32 {
	uint16_t type;
	uint16_t ctrl_type;
	uint32_t ctrl_index;
	int32_t val;
};

struct rpvb_msg_set_control_int64 {
	uint16_t type;
	uint16_t ctrl_type;
	uint32_t ctrl_index;
	int64_t val;
};

struct rpvb_msg_set_control_compound_header {
	uint16_t type;
	uint16_t ctrl_type;
	uint32_t ctrl_index;
	uint32_t start_index;
	uint32_t elems;
};

struct rpvb_msg_set_control_compound {
	struct rpvb_msg_set_control_compound_header header;
	uint8_t data[256];
};
