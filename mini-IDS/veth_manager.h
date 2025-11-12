#ifndef VETH_MANAGER_H
#define VETH_MANAGER_H

#include <netlink/netlink.h>
#include <sys/socket.h>
#include <linux/if.h>

int create_veth_pair(const char *name1, const char *name2, int mtu);
int delete_veth(const char *name);
int set_link_up(struct nl_sock *sock, const char *name);
int check_veth_exists(const char *name);

#endif
