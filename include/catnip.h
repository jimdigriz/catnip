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

#include <stdint.h>

#define MAX(a,b) ((a) > (b) ? a : b)
#define MIN(a,b) ((a) < (b) ? a : b)

int parse_args(int argc, char **argv);

enum {
	CATNIP_CMD_IFLIST,
};

enum {
	CATNIP_IFF_UP,
	CATNIP_IFF_LOOPBACK,
	CATNIP_IFF_POINTOPOINT,
	CATNIP_IFF_NOARP,
	CATNIP_IFF_PROMISC,
};

#define	CATNIP_IFNAMSIZ	10
struct catnip_iflist {
	char	name[CATNIP_IFNAMSIZ];
	uint8_t	flags;
} __attribute__((packed));

int sendcmd(int, char);

int respondcmd_iflist(int);
