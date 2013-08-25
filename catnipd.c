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

char		*auth;

int main(int argc, char **argv)
{
	int rc;

	rc = parse_args(argc, argv);

	auth = getenv("CATNIP_AUTH");

	while (rc == EX_OK) {
		struct catnip_msg msg;

		rc = rd(STDIN_FILENO, &msg, sizeof(msg));
		if (rc)
			break;

		if (msg.code != CATNIP_MSG_AUTH) {
			dprintf(STDERR_FILENO, "auth required\n");

			msg.code = CATNIP_MSG_ERROR;
			msg.payload.error.sysexit = EX_NOPERM;
			wr(STDOUT_FILENO, &msg, sizeof(msg));
			rc = EX_NOPERM;
			break;
		}

		switch (msg.code) {
		case CATNIP_MSG_AUTH:
			dprintf(STDERR_FILENO, "recv CATNIP_MSG_AUTH\n");
			if (!auth)
				auth = "\0";

			char *token = crypt(auth, msg.payload.auth.salt);
			if (strncmp(	token, msg.payload.auth.token,
					sizeof(msg.payload.auth.token))) {
				dprintf(STDERR_FILENO, "auth failed\n");
				msg.code = CATNIP_MSG_ERROR;
				msg.payload.error.sysexit = EX_NOPERM;
				wr(STDOUT_FILENO, &msg, sizeof(msg));
				rc = EX_NOPERM;
				break;	
			}

			auth = NULL;

			msg.code = CATNIP_MSG_ERROR;
			msg.payload.error.sysexit = EX_OK;
			wr(STDOUT_FILENO, &msg, sizeof(msg));

			break;
		case CATNIP_MSG_IFLIST:
			dprintf(STDERR_FILENO, "recv CATNIP_MSG_IFLIST\n");
			if (respondcmd_iflist()) {
				msg.code = CATNIP_MSG_ERROR;
				msg.payload.error.sysexit = errno;
				rc = errno;
				wr(STDOUT_FILENO, &msg, sizeof(msg));
			}
			break;
		default:
			dprintf(STDERR_FILENO, "unknown code: %d\n", msg.code);
			msg.code = CATNIP_MSG_ERROR;
			msg.payload.error.sysexit = EX_PROTOCOL;
			rc = EX_PROTOCOL;
			wr(STDOUT_FILENO, &msg, sizeof(msg));
		}
	}

	close(STDOUT_FILENO);

	return rc;
}
