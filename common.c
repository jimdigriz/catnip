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
#include <unistd.h>

#include "catnip.h"

int wr(struct sock *s, void *data, size_t size)
{
	int count;

	do {
		count = write(s->fd, data, size);

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

int rd(struct sock *s, void *data, size_t size)
{
	int count;

	do {
		count = read(s->fd, data, size);
	
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
