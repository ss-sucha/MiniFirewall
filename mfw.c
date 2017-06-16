#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <limits.h>

#include "mfw.h"

#define PORT_NUM_MAX USHRT_MAX


/*
 * The function prints usage and parameters.
 */
static void
print_usage(void)
{
	printf("Usage: mf RULE_OPTIONS..\n"
	       "MiniFirewall implements an exact match algorithm, where "
	       "unspecified options are ignored.\n"
	       "-i --in             input\n"
	       "-o --out            output\n"
	       "-s --s_ip IPADDR    source ip address\n"
	       "-m --s_mask MASK    source mask\n"
	       "-p --s_port PORT    source port\n"
	       "-d --d_ip IPADDR    destination ip address\n"
	       "-n --d_mask MASK    destination mask\n"
	       "-q --d_port PORT    destination port\n"
	       "-c --proto PROTO    protocol\n"
	       "-a --add            add a rule\n"
	       "-r --remove         remove a rule\n"
	       "-v --view           view rules\n"
	       "-h --help           this usage\n");
}


/*
 * The function sends a command to a MiniFirewall module via a device file.
 */
static void
send_instruction(struct mfw_ctl *ctl)
{
	FILE *fp;
	int byte_count;

	fp = fopen(DEVICE_INTF_NAME, "w");
	if(fp == NULL) {
		printf("An device file (%s) cannot be opened.\n",
		       DEVICE_INTF_NAME);
		return;
	}
	byte_count = fwrite(ctl, 1, sizeof(*ctl), fp);
	if(byte_count != sizeof(*ctl))
		printf("Write process is incomplete. Please try again.\n");

	fclose(fp);
}


/*
 * The function prints all existing rules, installed in the kernel module.
 */
static void
view_rules(void)
{
	FILE *fp;
	char *buffer;
	int byte_count;
	struct in_addr addr;
	struct mfw_rule *rule;

	fp = fopen(DEVICE_INTF_NAME, "r");
	if(fp == NULL) {
		printf("An device file (%s) cannot be opened.\n",
		       DEVICE_INTF_NAME);
		return;
	}

	buffer = (char *)malloc(sizeof(*rule));
	if(buffer == NULL) {
		printf("Rule cannot be printed duel to insufficient memory\n");
		return;
	}

	/* Each rule is printed line-by-line. */
	printf("I/O  "
	       "S_Addr           S_Mask           S_Port "
	       "D_Addr           D_Mask           D_Port Proto\n");
	while((byte_count = fread(buffer, 1, sizeof(struct mfw_rule), fp)) > 0) {
		rule = (struct mfw_rule *)buffer;
		printf("%-3s  ", rule->in ? "In" : "Out");
		addr.s_addr = rule->s_ip;
		printf("%-15s  ", inet_ntoa(addr));
		addr.s_addr = rule->s_mask;
		printf("%-15s  ", inet_ntoa(addr));
		printf("%-5d  ", ntohs(rule->s_port));
		addr.s_addr = rule->d_ip;
		printf("%-15s  ", inet_ntoa(addr));
		addr.s_addr = rule->d_mask;
		printf("%-15s  ", inet_ntoa(addr));
		printf("%-5d  ", ntohs(rule->d_port));
		printf("%-3d\n", rule->proto);
	}
	free(buffer);
	fclose(fp);
}


/*
 * The function parses a string and checks its range.
 */
static int64_t
parse_number(const char *str, uint32_t min_val, uint32_t max_val)
{
	uint32_t num;
	char *end;

	num = strtol(str, &end, 10);
	if(end == str || (num > max_val) || (num < min_val))
		return -1;

	return num;
}


/*
 * The function parses arguments (argv) to form a control instruction.
 */
static int
parse_arguments(int argc, char **argv, struct mfw_ctl *ret_ctl)
{
	int opt;
	int64_t lnum;
	int opt_index;
	struct mfw_ctl ctl = {};
	struct in_addr addr;

	/* Long option configuration */
	static struct option long_options[] = {
		{"in", no_argument, 0, 'i'},
		{"out", no_argument, 0, 'o'},
		{"s_ip", required_argument, 0, 's'},
		{"s_mask", required_argument, 0, 'm'},
		{"s_port", required_argument, 0, 'p'},
		{"d_ip", required_argument, 0, 'd'},
		{"d_mask", required_argument, 0, 'n'},
		{"d_port", required_argument, 0, 'q'},
		{"proto", required_argument, 0, 'c'},
		{"add", no_argument, 0, 'a'},
		{"remove", no_argument, 0, 'r'},
		{"view", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	if(argc == 1) {
		print_usage();
		return 0;
	}

	ctl.mode = MFW_NONE;
	ctl.rule.in = -1;
	while(1) {
		opt_index = 0;
		opt = getopt_long(argc, argv, "ios:m:p:d:n:q:c:arvh",
				  long_options, &opt_index);
		if(opt == -1) {
			break;
		}

		switch(opt) {
		case 'i':	/* Inbound rule */
			if(ctl.rule.in == 0) {
				printf("Please select either In or Out\n");
				return -1;
			}
			ctl.rule.in = 1;
			break;
		case 'o':	/* Outbound rule */
			if(ctl.rule.in == 1) {
				printf("Please select either In or Out\n");
				return -1;
			}
			ctl.rule.in = 0;			
			break;
		case 's':	/* Source ip address */
			if(inet_aton(optarg, &addr) == 0) {
				printf("Invalid source ip address\n");
				return -1;
			}
			ctl.rule.s_ip = addr.s_addr;
			break;
		case 'm':	/* Source subnet mask */
			if(inet_aton(optarg, &addr) == 0) {
				printf("Invalid source subnet mask\n");
				return -1;
			}
			ctl.rule.s_mask = addr.s_addr;
			break;
		case 'p':	/* Source port number */
			lnum = parse_number(optarg, 0, USHRT_MAX);
			if(lnum < 0) {
				printf("Invalid source port number\n");
				return -1;
			}
			ctl.rule.s_port = htons((uint16_t)lnum);
			break;
		case 'd':	/* Destination ip address */
			if(inet_aton(optarg, &addr) == 0) {
				printf("Invalid destination ip address\n");
				return -1;
			}
			ctl.rule.d_ip = addr.s_addr;
			break;
		case 'n':	/* Destination subnet mask */
			if(inet_aton(optarg, &addr) == 0) {
				printf("Invalid destination subnet mask\n");
				return -1;
			}
			ctl.rule.d_mask = addr.s_addr;
			break;
		case 'q':	/* Destination port number */
			lnum = parse_number(optarg, 0, USHRT_MAX);
			if(lnum < 0) {
				printf("Invalid destination port number\n");
				return -1;
			}
			ctl.rule.d_port = htons((uint16_t)lnum);
			break;
		case 'c':	/* Protocol number */
			lnum = parse_number(optarg, 0, UCHAR_MAX);
			if(lnum < 0 ||
			   !(lnum == 0 ||
			     lnum == IPPROTO_TCP ||
			     lnum == IPPROTO_UDP)) {
				printf("Invalid protocol number\n");
				return -1;
			}
			ctl.rule.proto = (uint8_t)lnum;
			break;
		case 'a':	/* Add rule */
			if(ctl.mode != MFW_NONE) {
				printf("Only one mode can be selected.\n");
				return -1;
			}
			ctl.mode = MFW_ADD;
			break;
		case 'r':	/* Remove rule */
			if(ctl.mode != MFW_NONE) {
				printf("Only one mode can be selected.\n");
				return -1;
			}
			ctl.mode = MFW_REMOVE;
			break;
		case 'v':	/* View rules */
			if(ctl.mode != MFW_NONE) {
				printf("Only one mode can be selected.\n");
				return -1;
			}
			ctl.mode = MFW_VIEW;
			break;
		case 'h':
		case '?':
		default:
			print_usage();
			return -1;
		}
	}
	if(ctl.mode == MFW_NONE) {
		printf("Please specify mode --(add|remove|view)\n");
		return -1;
	}
	if(ctl.mode != MFW_VIEW && ctl.rule.in == -1) {
		printf("Please specify either In or Out\n");
		return -1;
	}

	*ret_ctl = ctl;
	return 0;
}


int
main(int argc, char *argv[])
{
	struct mfw_ctl ctl = {};
	int ret;

	ret = parse_arguments(argc, argv, &ctl);
	if(ret < 0)
		return ret;

	switch(ctl.mode) {
	case MFW_ADD:
	case MFW_REMOVE:
		send_instruction(&ctl);
		break;
	case MFW_VIEW:
		view_rules();
		break;
	default:
		return 0;
	}
}
