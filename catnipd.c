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

#include <sysexits.h>
#include <sys/types.h>
#include <errno.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "catnip.h"

extern int	verbose;

int main(int argc, char **argv)
{
	int rc;
	struct catnip_msg msg;
	struct sock s = {
		.rfd	= STDIN_FILENO,
		.wfd	= STDOUT_FILENO,
	};

	rc = parse_args(argc, argv);
	if (rc < 0)
		return -rc;

	rc = rd(&s, &msg, sizeof(msg));
	if (rc)
		return -rc;

	switch (msg.code) {
	case CATNIP_MSG_IFLIST:
		dprintf(STDERR_FILENO, "recv CATNIP_MSG_IFLIST\n");
		if (cmd_iflist(&s, &msg)) {
			msg.code = CATNIP_MSG_ERROR;
			msg.payload.error.sysexit = errno;
			rc = errno;
			wr(&s, &msg, sizeof(msg));
		}
		break;
	case CATNIP_MSG_MIRROR:
		dprintf(STDERR_FILENO, "recv CATNIP_MSG_MIRROR\n");
		if (cmd_mirror(&s, &msg)) {
			msg.code = CATNIP_MSG_ERROR;
			msg.payload.error.sysexit = errno;
			rc = errno;
			wr(&s, &msg, sizeof(msg));
		}
		break;
	default:
		dprintf(STDERR_FILENO, "unknown code: %d\n", msg.code);
		msg.code = CATNIP_MSG_ERROR;
		msg.payload.error.sysexit = EX_PROTOCOL;
		rc = EX_PROTOCOL;
		wr(&s, &msg, sizeof(msg));
	}
	
	/* need to deal with thie better one day */
	while (rd(&s, &msg, 1) > 0) { }

	close(s.rfd);
	close(s.wfd);

	return rc;
}
