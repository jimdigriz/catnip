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

#include <errno.h>
#include <sysexits.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "catnip.h"

extern char	*hostname;
extern char	*port;
extern bool	listif;
extern bool	promisc;
extern int	snaplen;

int hookup(char *hostname, char *port) {
	struct addrinfo hints = {
		.ai_family	= AF_UNSPEC,
		.ai_socktype	= SOCK_STREAM,
		.ai_flags	= 0,
		.ai_protocol	= IPPROTO_TCP,
	};
	struct addrinfo *result, *rp;
	int sfd, s;

	s = getaddrinfo(hostname, port, &hints, &result);
	if (s != 0) {
		PERROR("getaddrinfo");
		return -EX_NOHOST;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

		if (sfd == -1)
			continue;

		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;

		close(sfd);
	}

	if (!rp) {
		PERROR("socket/connect");
		return -EX_UNAVAILABLE;
	}

	freeaddrinfo(result);

	return sfd;
}

int do_iflist(int s)
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

	if (msg.code != CATNIP_MSG_IFLIST) {
		dprintf(STDERR_FILENO, "response is different msg.code\n");
		return -EX_PROTOCOL;
	}

	iflist = malloc(msg.payload.iflist.num*sizeof(struct catnip_iflist));
	if (!iflist) {
		PERROR("malloc");
		return -EX_OSERR;
	}

	rc = rd(s, iflist, msg.payload.iflist.num*sizeof(struct catnip_iflist));
	if (rc) {
		free(iflist);
		return -rc;
	}

	for (i = 0; i < msg.payload.iflist.num; i++) {
		dprintf(STDOUT_FILENO, "%d.%s\n", i+1, iflist[i].name);
	}
	dprintf(STDOUT_FILENO, "%d.any (Pseudo-device that captures on all interfaces)\n", i+1);

	free(iflist);

	return EX_OK;
}

int main(int argc, char **argv)
{
	int rc;
	int s;

	rc = parse_args(argc, argv);
	if (rc)
		return rc;

	s = hookup(hostname, port);
	if (s < 0)
		return -s;

	if (listif) {
		rc = do_iflist(s);
	}

	if (s > 0)
		close(s);

	return rc;
}

