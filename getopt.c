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
#include <string.h>
#include <stdbool.h>

#include "catnip.h"

#ifdef DAEMON
#	define MODE	"daemon"
#	define GETOPT	"vVh"
#else
#	define MODE	"client"
#	define GETOPT	"H:P:A:Dps:vVh"
#endif

#ifndef DAEMON
char	*hostname	= NULL;
char	*port		= CATNIP_PORT;
char	*auth		= NULL;
bool	listif		= 0;
bool	nopromisc	= 0;
int	snaplen		= 65535;
#endif

int	verbose		= 0;

/* http://www.gnu.org/s/libc/manual/html_node/Getopt.html */
int parse_args(int argc, char **argv)
{
	extern char *optarg;
	extern int optind, opterr, optopt;
	int c;
     
	opterr = 0;

	while ((c = getopt(argc, argv, GETOPT)) != -1)
	switch (c) {
#ifndef DAEMON
	case 'H':
		hostname = optarg;
		break;
	case 'P':
		port = optarg;
		break;
	case 'A':
		auth = optarg;
		break;
	case 'D':
		listif = 1;
		break;
	case 'p':
		nopromisc = 1;
		break;
	case 's':
		snaplen = 1;
		break;
	case '?':
		switch (optopt) {
		case 'H':
		case 'P':
		case 'A':
		case 's':
			dprintf(STDERR_FILENO, "option -%c requires an argument.\n", optopt);
			break;
		default:
			if (isprint(optopt))
				dprintf(STDERR_FILENO, "unknown option `-%c'.\n", optopt);
			else
				dprintf(STDERR_FILENO, "unknown option character `\\x%x'.\n", optopt);
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
		dprintf(STDERR_FILENO, "Usage: %s [options]\n", basename(argv[0]));
		dprintf(STDERR_FILENO, "Remote packet mirroring %s with BPF support\n"
#ifndef DAEMON
			"\n"
			"  -H		host to connect to\n"
			"  -P		port to connect to (default: " CATNIP_PORT ")\n"
			"  -A KEY	authenticate using KEY\n"
			"  -D		Print the list of the network interfaces\n"
			"		available on the system\n"
			"  -p		Don't put the interface into promiscuous mode\n"
			"  -s		Snarf snaplen bytes of data from each packet\n"
			"		rather than the default of 65535 bytes\n"
#endif
			"\n"
			"  -v		increase verbosity\n"
			"\n"
			"  -h		display this help and exit\n"
			"  -V		print version information and exit\n", MODE);
		return -EX_SOFTWARE;
	}

	if (optind != argc) {
		dprintf(STDERR_FILENO, "we do not accept any arguments\n");
		return -EX_USAGE;
	}

#ifndef DAEMON
        if (!hostname) {
		dprintf(STDERR_FILENO, "must supply a host to connect to\n");
		return -EX_USAGE;
	}
#endif

	/* for (index = optind; index < argc; index++)
		dprintf(STDERR_FILENO, "Non-option argument %s\n", argv[index]); */

	return EX_OK;
}
