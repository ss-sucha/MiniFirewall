#ifndef _MFW_H_
#define _MFW_H_

#include <linux/types.h>

#define DEVICE_INTF_NAME "mfw_file"
#define DEVICE_MAJOR_NUM 100


/* Mode of an instruction */
enum mfw_mode {
	MFW_NONE = 0,
	MFW_ADD = 1,
	MFW_REMOVE = 2,
	MFW_VIEW = 3
};


/* Filter rule of MiniFirewall */
struct mfw_rule {
	uint32_t in;
	uint32_t s_ip;
	uint32_t s_mask;
	uint16_t s_port;
	uint32_t d_ip;
	uint32_t d_mask;
	uint16_t d_port;
	uint8_t proto;
};


/* Control instruction */
struct mfw_ctl {
	enum mfw_mode mode;
	struct mfw_rule rule;
};

#endif
