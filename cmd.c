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

#include <errno.h>
#include <sysexits.h>
#include <stdio.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <alloca.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>

#ifdef AF_LINK
#	include <net/if_dl.h>
#elif __linux__
#	include <netpacket/packet.h>
#	define AF_LINK AF_PACKET
#else
#	error neither AF_LINK or AF_PACKET available, aborting
#endif

#include "catnip.h"

int sendcmd(int s, char cmd)
{
	return 0;
}

/*
 * uint8_t			number of items
 * struct catnip_iflist 	array of struct
 */
int respondcmd_iflist(int s)
{
	struct ifaddrs *ifaddr, *ifa;
	struct catnip_iflist *iflist;
	uint8_t num;
	
	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		return errno;
	}

	num = 0;
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		int family = ifa->ifa_addr->sa_family;

		if (family != AF_LINK)
			continue;

		num++;
	}

	iflist = alloca(num*sizeof(struct catnip_iflist));
	memset(iflist, 0, num*sizeof(struct catnip_iflist));

	num = 0;
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		int family = ifa->ifa_addr->sa_family;

		if (family != AF_LINK)
			continue;

		strncpy(iflist[num].name, ifa->ifa_name,
				MIN(CATNIP_IFNAMSIZ, IFNAMSIZ));

		if (ifa->ifa_flags & IFF_UP)
			iflist[num].flags |= (1<<CATNIP_IFF_UP);
		if (ifa->ifa_flags & IFF_LOOPBACK)
			iflist[num].flags |= (1<<CATNIP_IFF_LOOPBACK);
		if (ifa->ifa_flags & IFF_POINTOPOINT)
			iflist[num].flags |= (1<<CATNIP_IFF_POINTOPOINT);
		if (ifa->ifa_flags & IFF_NOARP)
			iflist[num].flags |= (1<<CATNIP_IFF_NOARP);
		if (ifa->ifa_flags & IFF_PROMISC)
			iflist[num].flags |= (1<<CATNIP_IFF_PROMISC);

		num++;
	}

	freeifaddrs(ifaddr);

	write(s, &num, 1);
	write(s, iflist, num*sizeof(struct catnip_iflist));

	return EX_OK;
}
