#include "veth_manager.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/link/veth.h>

int create_veth_pair(const char *name1, const char *name2, int mtu) {
    struct nl_sock *sock;
    struct rtnl_link *link, *peer;
    int err;
    
    printf("[VETH] veth 쌍 생성 중: %s <-> %s (MTU: %d)\n", name1, name2, mtu);
    
    sock = nl_socket_alloc();
    if (!sock) {
        fprintf(stderr, "[VETH ERROR] netlink 소켓 할당 실패\n");
        return -1;
    }
    
    if (nl_connect(sock, NETLINK_ROUTE) < 0) {
        fprintf(stderr, "[VETH ERROR] netlink 연결 실패\n");
        nl_socket_free(sock);
        return -1;
    }
    
    link = rtnl_link_veth_alloc();
    if (!link) {
        fprintf(stderr, "[VETH ERROR] veth 링크 할당 실패\n");
        nl_socket_free(sock);
        return -1;
    }
    
    rtnl_link_set_name(link, name1);
    rtnl_link_set_mtu(link, mtu);
    
    peer = rtnl_link_veth_get_peer(link);
    if (!peer) {
        fprintf(stderr, "[VETH ERROR] peer 링크 가져오기 실패\n");
        rtnl_link_put(link);
        nl_socket_free(sock);
        return -1;
    }
    
    rtnl_link_set_name(peer, name2);
    rtnl_link_set_mtu(peer, mtu);
    rtnl_link_veth_release(peer);
    
    err = rtnl_link_add(sock, link, NLM_F_CREATE | NLM_F_EXCL);
    if (err < 0) {
        fprintf(stderr, "[VETH ERROR] veth 생성 실패: %s\n", nl_geterror(err));
        rtnl_link_put(link);
        nl_socket_free(sock);
        return -1;
    }
    
    printf("[VETH] veth 쌍 생성 완료\n");
    
    if (set_link_up(sock, name1) < 0 || set_link_up(sock, name2) < 0) {
        fprintf(stderr, "[VETH WARN] 인터페이스 UP 설정 실패\n");
    }
    
    rtnl_link_put(link);
    nl_socket_free(sock);
    
    return 0;
}

int set_link_up(struct nl_sock *sock, const char *name) {
    struct rtnl_link *link, *change;
    int err;
    
    err = rtnl_link_get_kernel(sock, 0, name, &link);
    if (err < 0) {
        fprintf(stderr, "[VETH ERROR] 링크 가져오기 실패 (%s): %s\n", name, nl_geterror(err));
        return -1;
    }
    
    change = rtnl_link_alloc();
    rtnl_link_set_flags(change, IFF_UP);
    
    err = rtnl_link_change(sock, link, change, 0);
    if (err < 0) {
        fprintf(stderr, "[VETH ERROR] 링크 UP 설정 실패 (%s): %s\n", name, nl_geterror(err));
        rtnl_link_put(link);
        rtnl_link_put(change);
        return -1;
    }
    
    printf("[VETH] %s UP 완료\n", name);
    
    rtnl_link_put(link);
    rtnl_link_put(change);
    
    return 0;
}

int delete_veth(const char *name) {
    struct nl_sock *sock;
    struct rtnl_link *link;
    int err;
    
    printf("[VETH] veth 삭제 중: %s\n", name);
    
    sock = nl_socket_alloc();
    if (!sock) {
        return -1;
    }
    
    if (nl_connect(sock, NETLINK_ROUTE) < 0) {
        nl_socket_free(sock);
        return -1;
    }
    
    err = rtnl_link_get_kernel(sock, 0, name, &link);
    if (err < 0) {
        printf("[VETH] %s 이미 삭제됨\n", name);
        nl_socket_free(sock);
        return 0;
    }
    
    err = rtnl_link_delete(sock, link);
    if (err < 0) {
        fprintf(stderr, "[VETH ERROR] veth 삭제 실패: %s\n", nl_geterror(err));
        rtnl_link_put(link);
        nl_socket_free(sock);
        return -1;
    }
    
    printf("[VETH] %s 삭제 완료\n", name);
    
    rtnl_link_put(link);
    nl_socket_free(sock);
    
    return 0;
}

int check_veth_exists(const char *name) {
    struct nl_sock *sock;
    struct rtnl_link *link;
    int err;
    
    sock = nl_socket_alloc();
    if (!sock) {
        return 0;
    }
    
    if (nl_connect(sock, NETLINK_ROUTE) < 0) {
        nl_socket_free(sock);
        return 0;
    }
    
    err = rtnl_link_get_kernel(sock, 0, name, &link);
    
    nl_socket_free(sock);
    
    if (err < 0) {
        return 0;
    }
    
    rtnl_link_put(link);
    return 1;
}
