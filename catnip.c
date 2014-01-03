/*
 * catnip - remote packet mirroring client with BPF support
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

#ifdef __linux__
#	include <linux/filter.h>
#else
#	include <net/bpf.h>
#endif

#include <errno.h>
#include <sysexits.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pcap.h>
#include <sys/select.h>
#include <signal.h>

#include "catnip.h"

extern char		*hostname;
extern char		*port;
extern int		listif;
extern char		*interface;
extern int		promisc;
extern unsigned int	snaplen;
extern int		optimize;
extern char		*filter;

int running = 1;
void sighandler(int signum)
{
	running = 0;
}

int hookup(struct sock *s, char *hostname, char *port) {
	struct addrinfo hints = {
		.ai_family	= AF_UNSPEC,
		.ai_socktype	= SOCK_STREAM,
		.ai_flags	= 0,
		.ai_protocol	= IPPROTO_TCP,
	};
	struct addrinfo *result, *rp;
	int rc = EX_OK;

	rc = getaddrinfo(hostname, port, &hints, &result);
	if (rc != 0) {
		PERROR("getaddrinfo");
		return -EX_NOHOST;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		s->fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

		if (s->fd == -1)
			continue;

		if (connect(s->fd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;

		close(s->fd);
	}

	if (!rp) {
		PERROR("socket/connect");
		freeaddrinfo(result);
		return -EX_UNAVAILABLE;
	}

	s->addrlen = rp->ai_addrlen;
	memcpy(&s->addr, rp->ai_addr, sizeof(struct sockaddr));
	if (rp->ai_family == AF_INET) {
		((struct sockaddr_in*)&s->addr)->sin_port = 0;
	} else {
		((struct sockaddr_in6*)&s->addr)->sin6_port = 0;
	}

	freeaddrinfo(result);

	return EX_OK;
}

int do_iflist(struct sock *s)
{
	struct catnip_msg msg = {
		.code	= CATNIP_MSG_IFLIST,
	};
	struct catnip_iflist *iflist;
	int i;
	int rc;

	rc = wr(s, &msg, sizeof(msg));
	if (rc)
		return -rc;

	rc = rd(s, &msg, sizeof(msg));
	if (rc)
		return -rc;

	if (msg.code == CATNIP_MSG_ERROR) {
		dprintf(STDERR_FILENO, "error: sysexit code %d\n", msg.payload.error.sysexit);
		return -EX_SOFTWARE;
	}

	if (msg.code != CATNIP_MSG_IFLIST) {
		dprintf(STDERR_FILENO, "response is different msg.code\n");
		return -EX_PROTOCOL;
	}

	iflist = calloc(msg.payload.iflist.num, sizeof(struct catnip_iflist));
	if (!iflist) {
		PERROR("calloc");
		return -EX_OSERR;
	}

	if (msg.payload.iflist.num) {
		rc = rd(s, iflist, msg.payload.iflist.num*sizeof(struct catnip_iflist));
		if (rc) {
			free(iflist);
			return -rc;
		}
	}

	for (i = 0; i < msg.payload.iflist.num; i++) {
		dprintf(STDOUT_FILENO, "%d.%s\n", i+1, iflist[i].name);

		iflist[i].type	= ntohs(iflist[i].type);
		iflist[i].flags	= ntohl(iflist[i].flags);
	}
	dprintf(STDOUT_FILENO, "%d.any (Pseudo-device that captures on all interfaces)\n", i+1);

	free(iflist);

	return EX_OK;
}

int do_capture(struct sock *s) {
	struct catnip_msg msg = {
		.code		= CATNIP_MSG_MIRROR,
		.payload	= {
			.mirror	= {
				.promisc	= promisc,
			}
		}
	};
	pcap_t *p;
	struct bpf_program fp;
	struct catnip_sock_filter *fpinsn;
	int i, pfd, rc;
	struct sockaddr addr;
	socklen_t addrlen = sizeof(addr);
	fd_set rfds;
	char *buf[64*1024];
	struct sigaction sigact;

	pfd = socket(s->addr.sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (pfd < 0) {
		PERROR("socket");
		return -EX_UNAVAILABLE;
	}
	if (bind(pfd, &s->addr, s->addrlen)) {
		PERROR("bind");
		return -EX_UNAVAILABLE;
	}
	if (getsockname(pfd, &addr, &addrlen) < 0) {
		PERROR("getsockname");
		return -EX_OSERR;
	}
	msg.payload.mirror.port = (s->addr.sa_family == AF_INET)
		? htons(((struct sockaddr_in*)&addr)->sin_port)
		: htons(((struct sockaddr_in6*)&addr)->sin6_port);

	strncpy(msg.payload.mirror.interface, interface, CATNIP_IFNAMSIZ);

	p = pcap_open_dead(DLT_NULL, snaplen);

	if (pcap_compile(p, &fp, filter, optimize, PCAP_NETMASK_UNKNOWN) == -1) {
		dprintf(STDERR_FILENO, "pcap_perror: %s\n", pcap_geterr(p));
		pcap_close(p);
		return -EX_DATAERR;
	}

	pcap_close(p);
		
	fpinsn = calloc(fp.bf_len, sizeof(struct catnip_sock_filter));
	if (!fpinsn) {
		PERROR("calloc");
		pcap_freecode(&fp);
		return -EX_OSERR;
	}

	msg.payload.mirror.bf_len = htons(fp.bf_len);

	for (i = 0; i<fp.bf_len; i++) {
		fpinsn[i].code	= htons(fp.bf_insns[i].code);
		fpinsn[i].jt	= fp.bf_insns[i].jt;
		fpinsn[i].jf	= fp.bf_insns[i].jf;
		fpinsn[i].k	= htonl(fp.bf_insns[i].k);
	}

	pcap_freecode(&fp);

	wr(s, &msg, sizeof(msg));
	if (fp.bf_len)
		wr(s, fpinsn, fp.bf_len*sizeof(struct catnip_sock_filter));

	if (fp.bf_len)
		free(fpinsn);

	sigact.sa_handler = sighandler;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigaction(SIGINT, &sigact, NULL);

	FD_ZERO(&rfds);
	FD_SET(s->fd, &rfds);
	FD_SET(pfd, &rfds);
	while (running) {
		rc = select(pfd+1, &rfds, NULL, NULL, NULL);

		if (rc == -1) {
			if (errno == EINTR)
				continue;

			PERROR("select");
			running = 0;
			continue;
		}

		if (FD_ISSET(s->fd, &rfds)) {
			running = 0;

			rc = rd(s, &msg, sizeof(msg));
			if (rc)
				return -rc;

			if (msg.code == CATNIP_MSG_ERROR) {
				dprintf(STDERR_FILENO, "error: sysexit code %d\n", msg.payload.error.sysexit);
				return -EX_SOFTWARE;
			}

			continue;
		}

		if (FD_ISSET(pfd, &rfds)) {
			rc = read(pfd, buf, 64*1024);
		}
	}

	return EX_OK;
}

int main(int argc, char **argv)
{
	int rc;
	struct sock s;

	rc = parse_args(argc, argv);
	if (rc)
		return rc;

	rc = hookup(&s, hostname, port);
	if (rc < 0)
		return -rc;

	if (listif) {
		rc = do_iflist(&s);
	} else {
		rc = do_capture(&s);
	}

	close(s.fd);

	return -rc;
}
