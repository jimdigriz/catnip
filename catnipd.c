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

#include "catnip.h"

extern int	verbose;

int main(int argc, char **argv)
{
	int rc;

	rc = parse_args(argc, argv);

	while (rc == EX_OK) {
		struct catnip_msg msg;

		rc = msgrecv(STDIN_FILENO, &msg, sizeof(msg));
		if (rc)
			break;

		switch (msg.code) {
		case CATNIP_MSG_IFLIST:
			dprintf(STDERR_FILENO, "recv CATNIP_MSG_IFLIST\n");
			if (respondcmd_iflist()) {
				msg.code = CATNIP_MSG_ERROR;
				msg.payload.error.sysexit = errno;
				rc = errno;
				msgsend(STDOUT_FILENO, &msg, sizeof(msg));
			}
			break;
		default:
			dprintf(STDERR_FILENO, "unknown code: %d\n", msg.code);
			msg.code = CATNIP_MSG_ERROR;
			msg.payload.error.sysexit = EX_PROTOCOL;
			rc = EX_PROTOCOL;
			msgsend(STDOUT_FILENO, &msg, sizeof(msg));
		}
	}

	close(STDOUT_FILENO);

	return rc;
}
