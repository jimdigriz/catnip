/*
 * catnipd - remote packet mirroring daemon with BPF support
 * Copyright (C) 2013  Alexander Clouter <alex@digriz.org.uk>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * or alternatively visit <http://www.gnu.org/licenses/gpl.html>
 */

#if __linux__
#	include <linux/filter.h>
#	include <netpacket/packet.h>
#	include <net/ethernet.h>
#	include <net/if_arp.h>
#	define AF_LINK AF_PACKET
#else
#	include <net/if_dl.h>
#endif

#include <sysexits.h>
#include <sys/types.h>
#include <errno.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <alloca.h>
#include <string.h>
#include <net/if.h>
#include <fcntl.h>
#include <sys/select.h>

#include "catnip.h"

extern int	verbose;

int get_arphrd_type(char *ifname) {
	int s;
	struct ifreq ifr;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		PERROR("socket");
		return -EX_OSERR;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname,
			MIN(CATNIP_IFNAMSIZ, IFNAMSIZ));
	if (ioctl(s, SIOCGIFHWADDR, &ifr) == -1) {
		PERROR("ioctl[SIOCGIFHWADDR]");
		close(s);
		return -EX_OSERR;
	}

	close(s);

	return ifr.ifr_hwaddr.sa_family;
}

/* from libpcap/pcap-linux.c:map_arphrd_to_dlt */
int map_arphrd_to_dlt(int arptype)
{
	switch (arptype) {
	case ARPHRD_ETHER:
	case ARPHRD_LOOPBACK:
		return DLT_EN10MB;
		break;
	case ARPHRD_PPP:
		return DLT_LINUX_SLL;
		break;
	case ARPHRD_NONE:
		return DLT_RAW;
		break;
	}

	return DLT_UNSUPP;
}

int cmd_iflist(struct sock *s, const struct catnip_msg *omsg)
{
	struct ifaddrs *ifaddr, *ifa;
	struct catnip_msg msg;
	struct catnip_iflist *iflist;
	
	if (getifaddrs(&ifaddr) == -1) {
		PERROR("getifaddrs");
		return -errno;
	}

	msg.payload.iflist.num = 0;
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family != AF_LINK)
			continue;

		if (!(ifa->ifa_flags & IFF_UP))
			continue;

		msg.payload.iflist.num++;
	}

	iflist = calloc(msg.payload.iflist.num, sizeof(struct catnip_iflist));
	if (msg.payload.iflist.num && !iflist) {
		PERROR("calloc");
		return -EX_OSERR;
	}

	msg.payload.iflist.num = 0;
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		int type;

		if (ifa->ifa_addr && ifa->ifa_addr->sa_family != AF_LINK)
			continue;

		if (!(ifa->ifa_flags & IFF_UP))
			continue;

		strncpy(iflist[msg.payload.iflist.num].name, ifa->ifa_name,
				MIN(CATNIP_IFNAMSIZ, IFNAMSIZ));

		type = get_arphrd_type(ifa->ifa_name);
		iflist[msg.payload.iflist.num].type = map_arphrd_to_dlt(type);

		msg.payload.iflist.num++;
	}

	freeifaddrs(ifaddr);

	msg.code = CATNIP_MSG_IFLIST;
	wr(s, &msg, sizeof(msg));
	if (msg.payload.iflist.num)
		wr(s, iflist, msg.payload.iflist.num*sizeof(struct catnip_iflist));

	free(iflist);

	return EX_OK;
}

int set_promisc(const int sock, const char *interface, int state) {
	struct ifreq ifr;

	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		PERROR("ioctl[SIOCGIFFLAGS]");
		return -EX_OSERR;
	}

	/* if already IFF_PROMISC then do nothing */
	if (ifr.ifr_flags & IFF_PROMISC)
		return 0;
	else {
		if (state)
			ifr.ifr_flags |= IFF_PROMISC;
		else
			ifr.ifr_flags &= ~IFF_PROMISC;

		if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			PERROR("ioctl[SIOCSIFFLAGS]");
			return -EX_OSERR;
		}
	}

	return 1;
}

/* alot gleened from http://www.linuxjournal.com/article/4659 */
int open_sock(struct sock *s, const struct catnip_msg *omsg) {
	struct sock_fprog		fp = {
		.len	= ntohs(omsg->payload.mirror.bf_len),
	};
	struct catnip_sock_filter	fpins;
	char				drain[1];
	struct sock_filter		total_insn = BPF_STMT(BPF_RET | BPF_K, 0);
	struct sock_fprog 		total_fcode = { 1, &total_insn };
	int				i;
	struct ifreq			ifr;
	struct sockaddr_ll		sa_ll;
	int				flags, sock;
	int				sock_type;

	/* if we are capturing on 'any' then SOCK_RAW is meaningless */
	sock_type = (omsg->payload.mirror.interface[0] != '\0') ? SOCK_RAW : SOCK_DGRAM;

	if ((sock = socket(PF_PACKET, sock_type, htons(ETH_P_ALL))) < 0) {
		PERROR("socket error");
		return -EX_OSERR;
	}

	fp.filter = calloc(fp.len, sizeof(struct catnip_sock_filter));
	if (!fp.filter) {
		PERROR("calloc [fp.filter]");
		return -EX_OSERR;
	}

	for (i = 0; i<fp.len; i++) {
		if (rd(s, &fpins, sizeof(struct catnip_sock_filter)) < 0) {
			PERROR("unable to rd bf program");
			return -EX_SOFTWARE;
		}

		fp.filter[i].code	= ntohs(fpins.code);
		fp.filter[i].jt		= fpins.jt;
		fp.filter[i].jf		= fpins.jf;
		fp.filter[i].k		= ntohl(fpins.k);
	}

	/* deal with socket() -> filter() race */
	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
			&total_fcode, sizeof(total_fcode)) < 0) {
		PERROR("setsockopt[SO_ATTACH_FILTER-total]");
		free(fp.filter);
		close(sock);
		return -EX_OSERR;
	}
	while (recv(sock, &drain, sizeof(drain), MSG_TRUNC|MSG_DONTWAIT) >= 0)
		;

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &fp, sizeof(fp)) < 0) {
		PERROR("setsockopt[SO_ATTACH_FILTER]");
		free(fp.filter);
		close(sock);
		return -EX_OSERR;
	}

	free(fp.filter);

	if (omsg->payload.mirror.interface[0] != '\0') {
		strncpy(ifr.ifr_name, omsg->payload.mirror.interface, MIN(IFNAMSIZ,CATNIP_IFNAMSIZ));
		if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
			PERROR("ioctl[SIOCGIFINDEX]");
			close(sock);
			return -EX_OSERR;
		}

		memset(&sa_ll, 0, sizeof(sa_ll));

		sa_ll.sll_family	= AF_PACKET;
		sa_ll.sll_protocol	= htons(ETH_P_ALL);
		sa_ll.sll_ifindex	= ifr.ifr_ifindex;

		if ((bind(sock, (struct sockaddr *)&sa_ll, sizeof(sa_ll))) == -1) {
			PERROR("bind");
			close(sock);
			return -EX_OSERR;
		}

		if (omsg->payload.mirror.promisc) {
			int promisc = set_promisc(sock, omsg->payload.mirror.interface, 1);
			if (promisc < 0) {
				close(sock);
				return -promisc;
			}
		}
	}

	/* select()/poll() manpage says it is safer under Linux to use O_NONBLOCK */
	if ((flags = fcntl(sock, F_GETFL, 0)) == -1) {
		PERROR("fcntl[F_GETFL]");
		close(sock);
		return -EX_OSERR;
	}
	if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
		PERROR("fcntl[F_SETFL]");
		close(sock);
		return -EX_OSERR;
	}

	return sock;
}

int cmd_mirror(struct sock *s, const struct catnip_msg *omsg)
{
	int pfd, cfd, rc;
	struct sockaddr addr;
	socklen_t addrlen = sizeof(addr);
	fd_set rfds;
	int running = 1;
	char *buf[64*1024];

	cfd = open_sock(s, omsg);
	if (cfd < 0)
		return -cfd;

	if (getsockname(s->fd, &addr, &addrlen) < 0) {
		PERROR("getsockname");
		return -EX_OSERR;
	}
	if (addr.sa_family == AF_INET) {
		((struct sockaddr_in*)&addr)->sin_port = 0;
	} else {
		((struct sockaddr_in6*)&addr)->sin6_port = 0;
	}

	pfd = socket(addr.sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (pfd < 0) {
		PERROR("socket");
		return -EX_UNAVAILABLE;
	}
	if (bind(pfd, &addr, addrlen)) {
		PERROR("bind");
		return -EX_UNAVAILABLE;
	}

	if (getpeername(s->fd, &addr, &addrlen) < 0) {
		PERROR("getsockname");
		return -EX_OSERR;
	}
	if (addr.sa_family == AF_INET) {
		((struct sockaddr_in*)&addr)->sin_port = omsg->payload.mirror.port;
	} else {
		((struct sockaddr_in6*)&addr)->sin6_port = omsg->payload.mirror.port;
	}
	if (connect(pfd, &addr, addrlen)) {
		PERROR("connect");
		return -EX_UNAVAILABLE;
	}

	FD_ZERO(&rfds);
	while (running) {
		FD_SET(s->fd, &rfds);
		FD_SET(cfd, &rfds);
		rc = select(cfd+1, &rfds, NULL, NULL, NULL);

		if (rc == -1) {
			if (errno == EINTR)
				continue;

			PERROR("select");
			running = 0;
			continue;
		}

		if (FD_ISSET(s->fd, &rfds)) {
			running = 0;
			continue;
		}

		if (FD_ISSET(cfd, &rfds)) {
			rc = read(cfd, buf, 64*1024);
			if (rc < 0) {
				running = 0;
				continue;
			} else if (rc > 64*1024 - 4) {
				dprintf(STDERR_FILENO, "received too large a packet, truncating\n");
				rc = 64*1024 - 4;
			}

			send(pfd, buf, rc, MSG_DONTWAIT);
		}
	}

	return EX_OK;
}

int main(int argc, char **argv)
{
	int rc;
	struct catnip_msg msg;
	struct sock s = {
		.fd	= STDIN_FILENO,
	};

	rc = parse_args(argc, argv);
	if (rc < 0)
		return -rc;

	while (1) {
		rc = rd(&s, &msg, sizeof(msg));
		if (rc)
			break;

		switch (msg.code) {
		case CATNIP_MSG_IFLIST:
			dprintf(STDERR_FILENO, "recv CATNIP_MSG_IFLIST\n");
			rc = cmd_iflist(&s, &msg);
			if (rc) {
				memset(&msg, 0, sizeof(msg));
				msg.code = CATNIP_MSG_ERROR;
				msg.payload.error.sysexit = rc;
				wr(&s, &msg, sizeof(msg));
			}
			break;
		case CATNIP_MSG_MIRROR:
			dprintf(STDERR_FILENO, "recv CATNIP_MSG_MIRROR\n");
			rc = cmd_mirror(&s, &msg);
			if (rc) {
				memset(&msg, 0, sizeof(msg));
				msg.code = CATNIP_MSG_ERROR;
				msg.payload.error.sysexit = rc;
				wr(&s, &msg, sizeof(msg));
			}
			break;
		default:
			dprintf(STDERR_FILENO, "unknown code: %d\n", msg.code);
			memset(&msg, 0, sizeof(msg));
			msg.code = CATNIP_MSG_ERROR;
			msg.payload.error.sysexit = EX_PROTOCOL;
			rc = EX_PROTOCOL;
			wr(&s, &msg, sizeof(msg));
		}
	}

	close(s.fd);

	return rc;
}
