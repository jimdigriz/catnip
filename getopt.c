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

#ifdef DAEMON
#	define MODE	"daemon"
#else
#	define MODE	"client"
#endif

/* http://www.gnu.org/s/libc/manual/html_node/Getopt.html */
int parse_args(int argc, char **argv)
{
	extern char *optarg;
	extern int optind, opterr, optopt;
	int c;
     
	opterr = 0;

	while ((c = getopt(argc, argv, "Vh")) != -1)
	switch (c) {
/*	case 'w':
		wpath = optarg;
		break; */
	case '?':
		switch (optopt) {
/*		case 'w':
			fprintf(stderr, "option -%c requires an argument.\n", optopt);
			break; */
		default:
			if (isprint(optopt))
				fprintf(stderr, "unknown option `-%c'.\n", optopt);
			else
				fprintf(stderr, "unknown option character `\\x%x'.\n", optopt);
		}
		return -EX_USAGE;
	case 'V':
		printf("%s %s\n\n", basename(argv[0]), VERSION);
		printf(	"Copyright (C) 2013  Alexander Clouter <alex@digriz.org.uk>\n"
			"License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n"
			"This is free software: you are free to change and redistribute it.\n"
			"There is NO WARRANTY, to the extent permitted by law.\n");
		return -EX_SOFTWARE;
	case 'h':
	default:
		printf("Usage: %s [options] [(-q|-v)]\n", basename(argv[0]));
		printf(	"Remote packet mirroring %s with BPF support\n"
			"\n"
			"  -q		be quieter\n"
			"  -v		be more verbose\n"
			"\n"
			"  -h		display this help and exit\n"
			"  -V		print version information and exit\n", MODE);
		return -EX_SOFTWARE;
	}

	if (optind != argc) {
		fprintf(stderr, "we do not accept any arguments\n");
		return -EX_USAGE;
	}
	/* for (index = optind; index < argc; index++)
		printf("Non-option argument %s\n", argv[index]); */

	return EX_OK;
}
