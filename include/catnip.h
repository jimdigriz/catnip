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
#include <string.h>

#define PERROR(x)	dprintf(STDERR_FILENO, "%s:%d: %s: %s\n", \
				__FILE__, __LINE__, x, strerror(errno))

#define MAX(a,b)	((a) > (b) ? a : b)
#define MIN(a,b)	((a) < (b) ? a : b)

#define	CATNIP_PORT	"34343"

/* message codes */
enum {
	CATNIP_MSG_ERROR,
	CATNIP_MSG_IFLIST,
};

struct catnip_msg {
	uint8_t		code;

	union {
		struct {
			uint8_t			sysexit;
		} error;

		struct {
			uint8_t			num;
			/* data of num*catnip_iflist follows */
		} iflist;
	}		payload;
} __attribute__((packed));

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

int parse_args(int, char **);

int msgsend(int, void *, size_t);
int msgrecv(int, void *, size_t);

int respondcmd_iflist(void);
