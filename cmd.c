/*
 * This file is part of:
 *      catnip - remote packet mirroring suite with BPF support
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
#	include <netpacket/packet.h>
#	define AF_LINK AF_PACKET
#else
#	include <sys/socket.h>
#	include <net/if_dl.h>
#endif

#include <errno.h>
#include <sysexits.h>
#include <stdio.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <alloca.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <stdlib.h>

#include "catnip.h"

int wr(int s, void *data, size_t size)
{
	int count;

	do {
		count = write(s, data, size);

		if (count < 0) {
			if (errno == EINTR)
				continue;

			PERROR("write");
			return -EX_OSERR;
		}
	} while (count < 0);

	if (count == 0) {
		dprintf(STDERR_FILENO, "received EOF, exiting\n");
		return -EX_DATAERR;
	}
	if (count < size) {
		dprintf(STDERR_FILENO, "could not send out all data, exiting\n");
		return -EX_DATAERR;
	}

	return EX_OK;
}

int rd(int s, void *data, size_t size)
{
	int count;

	do {
		count = read(s, data, size);
	
		if (count < 0) {
			if (errno == EINTR)
				continue;

			PERROR("read");
			return -EX_OSERR;
		}
	} while (count < 0);

	if (count == 0) {
		dprintf(STDERR_FILENO, "received EOF, exiting\n");
		return -EX_DATAERR;
	}
	if (count < size) {
		dprintf(STDERR_FILENO, "could not read in all data, exiting\n");
		return -EX_DATAERR;
	}

	return EX_OK;
}

int respondcmd_iflist(void)
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
		int family = ifa->ifa_addr->sa_family;

		if (family != AF_LINK)
			continue;

		msg.payload.iflist.num++;
	}

	iflist = malloc(msg.payload.iflist.num*sizeof(struct catnip_iflist));
	if (msg.payload.iflist.num && !iflist) {
		PERROR("malloc");
		return -EX_OSERR;
	}

	msg.payload.iflist.num = 0;
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		int family = ifa->ifa_addr->sa_family;

		if (family != AF_LINK)
			continue;

		strncpy(iflist[msg.payload.iflist.num].name, ifa->ifa_name,
				MIN(CATNIP_IFNAMSIZ, IFNAMSIZ));

		if (ifa->ifa_flags & IFF_UP)
			iflist[msg.payload.iflist.num].flags |= (1<<CATNIP_IFF_UP);
		if (ifa->ifa_flags & IFF_LOOPBACK)
			iflist[msg.payload.iflist.num].flags |= (1<<CATNIP_IFF_LOOPBACK);
		if (ifa->ifa_flags & IFF_POINTOPOINT)
			iflist[msg.payload.iflist.num].flags |= (1<<CATNIP_IFF_POINTOPOINT);
		if (ifa->ifa_flags & IFF_NOARP)
			iflist[msg.payload.iflist.num].flags |= (1<<CATNIP_IFF_NOARP);
		if (ifa->ifa_flags & IFF_PROMISC)
			iflist[msg.payload.iflist.num].flags |= (1<<CATNIP_IFF_PROMISC);

		msg.payload.iflist.num++;
	}

	freeifaddrs(ifaddr);

	msg.code = CATNIP_MSG_IFLIST;
	write(STDOUT_FILENO, &msg, sizeof(msg));
	if (msg.payload.iflist.num)
		write(STDOUT_FILENO, iflist, msg.payload.iflist.num*sizeof(struct catnip_iflist));

	free(iflist);

	return EX_OK;
}
