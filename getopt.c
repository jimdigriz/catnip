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

#include <stdio.h>
#include <unistd.h>
#include <sysexits.h>
#include <ctype.h>
#include <libgen.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

#include "catnip.h"

#ifdef DAEMON
#	define GETOPT	"vVh"
#else
#	define GETOPT	"H:P:Di:ps:OvVh"
#endif

#ifndef DAEMON
char		*hostname	= NULL;
char		*port		= CATNIP_PORT;
int		listif		= 0;
char		*interface	= NULL;
int		promisc		= 1;
unsigned int	snaplen		= 65535;
int		optimize	= 1;
char		*filter		= NULL;
#endif

int	verbose		= 0;

/* http://www.gnu.org/s/libc/manual/html_node/Getopt.html */
int parse_args(int argc, char **argv)
{
	int opt;
#ifndef DAEMON
	char *end;
	int index, len = 0;
#endif
     
	opterr = 0;

	while ((opt = getopt(argc, argv, GETOPT)) != -1)
	switch (opt) {
#ifndef DAEMON
	case 'H':
		hostname = optarg;
		break;
	case 'P':
		port = optarg;
		break;
	case 'D':
		listif = 1;
		break;
	case 'i':
		interface = optarg;
		break;
	case 'p':
		promisc = 0;
		break;
	case 's':
		snaplen = strtol(optarg, &end, 10);
		if (optarg == end || *end != '\0'
				|| snaplen < 0 || snaplen > 65535) {
			dprintf(STDERR_FILENO, "invalid snaplen %s\n", optarg);
			return -EX_USAGE;
		} else if (snaplen == 0)
			snaplen = 65535;
		break;
	case 'O':
		optimize = 0;
		break;
	case '?':
		switch (optopt) {
		case 'H':
		case 'P':
		case 'i':
		case 's':
			dprintf(STDERR_FILENO, "option -%c requires an argument\n", optopt);
			break;
		default:
			if (isprint(optopt))
				dprintf(STDERR_FILENO, "unknown option `-%c'\n", optopt);
			else
				dprintf(STDERR_FILENO, "unknown option character `\\x%x'\n", optopt);
		}
		return -EX_USAGE;
#endif
	case 'v':
		verbose++;
		break;
	case 'V':
		dprintf(STDERR_FILENO, "%s %s\n\n", basename(argv[0]), VERSION);
		dprintf(STDERR_FILENO,
			"Copyright (C) 2013  Alexander Clouter <alex@digriz.org.uk>\n"
			"License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n"
			"This is free software: you are free to change and redistribute it.\n"
			"There is NO WARRANTY, to the extent permitted by law.\n");
		return -EX_SOFTWARE;
	case 'h':
	default:
#ifdef DAEMON
		dprintf(STDERR_FILENO, "Usage: %s [options]\n", basename(argv[0]));
		dprintf(STDERR_FILENO, "Remote packet mirroring daemon with BPF support\n"
#else
		dprintf(STDERR_FILENO, "Usage: %s [options] [expr]\n", basename(argv[0]));
		dprintf(STDERR_FILENO, "Remote packet mirroring client with BPF support\n"
			"\n"
			"  -H		host to connect to\n"
			"  -P		port to connect to (default: " CATNIP_PORT ")\n"
			"  -D		Print the list of the network interfaces\n"
			"		available on the system\n"
			"  -i INTERFACE	Listen on interface\n"
			"  -p		Don't put the interface into promiscuous mode\n"
			"  -s SNAPLEN	Snarf snaplen bytes of data from each packet\n"
			"		rather than the default of 65535 bytes\n"
			"  -O		Do not run the packet-matching code optimizer\n"
#endif
			"\n"
			"  -v		increase verbosity\n"
			"\n"
			"  -h		display this help and exit\n"
			"  -V		print version information and exit\n");
		return -EX_SOFTWARE;
	}

#ifdef DAEMON
	if (optind != argc) {
		dprintf(STDERR_FILENO, "we do not accept any arguments\n");
		return -EX_USAGE;
	}
#else
	if (!hostname) {
		dprintf(STDERR_FILENO, "must supply a host to connect to\n");
		return -EX_USAGE;
	}

	/* concat argv array and put it into filter */
	if (argv[optind]) {
		for (index = optind; index < argc; index++)
			len += strlen(argv[index]) + 1;

		filter = calloc(1, len);
		if (!filter) {
			PERROR("calloc");
			return -EX_OSERR;
		}

		for (index = optind; index < argc; index++) {
			if (index != optind)
				filter[strlen(filter)] = ' ';
			strncpy(filter + strlen(filter), argv[index], strlen(argv[index]));
		}
	}
#endif

	return EX_OK;
}
