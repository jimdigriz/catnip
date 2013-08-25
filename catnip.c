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
extern char	*auth;
extern bool	listif;
extern bool	nopromisc;
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

	iflist = calloc(msg.payload.iflist.num, sizeof(struct catnip_iflist));
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

int do_auth(int s)
{
	struct catnip_msg msg = {
		.code			= CATNIP_MSG_AUTH,
		.payload.auth.salt	= "$1$........",
	};
	int i;
	int rc;
	unsigned int seed[2];
	int fd;
	const char *const seedchars =
		"./0123456789ABCDEFGHIJKLMNOPQRST"
		"UVWXYZabcdefghijklmnopqrstuvwxyz";
	char *token;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		PERROR("open(/dev/urandom)");
		return errno;
	}

	rc = rd(fd, &seed, sizeof(seed));
	if (rc) {
		close(fd);
		return -rc;
	}

	close(fd);

	srand(seed[0]);
	seed[0] = rand();
	seed[1] = rand();

	for (i = 0; i < 8; i++)
		msg.payload.auth.salt[3+i] = seedchars[(seed[i/5] >> (i%5)*6) & 0x3f];

	if (!auth)
		auth = "\0";

	token = crypt(auth, msg.payload.auth.salt);
	strncpy(msg.payload.auth.token, token, sizeof(msg.payload.auth.token));

	rc = wr(s, &msg, sizeof(msg));
	if (rc)
		return -rc;

	rc = rd(s, &msg, sizeof(msg));
	if (rc)
		return -rc;

	if (msg.code != CATNIP_MSG_ERROR) {
		dprintf(STDERR_FILENO, "response is different msg.code\n");
		return -EX_PROTOCOL;
	}

	if (msg.payload.error.sysexit != EX_OK) {
		dprintf(STDERR_FILENO, "auth failed\n");
		return -msg.payload.error.sysexit;
	}
	
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

	rc = do_auth(s);
	if (rc)
		return -rc;

	if (listif) {
		rc = do_iflist(s);
	}

	if (s > 0)
		close(s);

	return rc;
}

