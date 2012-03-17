/*
 * catnip - tiny non-libpcap based network packet capturing tool
 * Copyright (C) 2010  Alexander Clouter <alex@digriz.org.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/* compile with: gcc -Wall -O0 -g -o catnip catnip.c */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sysexits.h>
#include <signal.h>
#include <poll.h>

#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <linux/filter.h>

/* snippets from libpcap */
#define	DLT_EN10MB	  1	/* pcap/bpf.h */
#define	DLT_PPP		  9
#define	DLT_RAW		 12
#define	DLT_IEEE802_11	105
#define	DLT_LINUX_SLL	113	
#define	SLL_ADDRLEN	  8	/* pcap/sll.h */

/* http://wiki.wireshark.org/Development/LibpcapFileFormat */
struct pcap_hdr_s {
	uint32_t	magic_number;	/* magic number */
	uint16_t	version_major;	/* major version number */
	uint16_t	version_minor;	/* minor version number */
	int32_t		thiszone;	/* GMT to local correction */
	uint32_t	sigfigs;	/* accuracy of timestamps */
	uint32_t	snaplen;	/* max length of captured packets, in octets */
	uint32_t	network;	/* data link type */
} __attribute__((packed));
/* N.B. unable to use 'struct timeval' due to 64bit 'long' woes */
struct pcaprec_hdr_s {
	uint32_t	ts_sec;		/* timestamp seconds */
	uint32_t	ts_usec;	/* timestamp microseconds */
	uint32_t	incl_len;	/* number of octets of packet saved in file */
	uint32_t	orig_len;	/* actual length of packet */
} __attribute__((packed));

/* libpcap/sll.h */
struct sll_header {
	u_int16_t	sll_pkttype;		/* packet type */
	u_int16_t	sll_hatype;		/* link-layer address type */
	u_int16_t	sll_halen;		/* link-layer address length */
	u_int8_t	sll_addr[SLL_ADDRLEN];	/* link-layer address */
	u_int16_t	sll_protocol;		/* protocol */
} __attribute__((packed));

static struct pcap_hdr_s pcap_hdr = {
	.magic_number	= 0xa1b2c3d4,
	.version_major	= 2,
	.version_minor	= 4,
	.thiszone	= 0,
	.sigfigs	= 0,
};

unsigned int	snaplen	= 96;
char		*ifname	= NULL;
unsigned int	promisc	= 1;
unsigned int	pktbuf	= 0;
char		*fpath	= NULL;
char		*wpath	= "-";

int		sock;
unsigned int	running = 1;

int		ifidx, ifidx_lo;

void sig_handler(int sig)
{
	running = 0;
	signal(SIGTERM, SIG_DFL);
	signal(SIGPIPE, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
	signal(SIGKILL, SIG_DFL);
	signal(SIGINT, SIG_DFL);
}

/* http://www.gnu.org/s/libc/manual/html_node/Getopt.html */
int parse_args(int argc, char **argv)
{
	int c;
     
	opterr = 0;
     
	while ((c = getopt(argc, argv, "pUs:i:F:w:")) != -1)
	switch (c) {
	case 'p':
		promisc = 0;
		break;
	case 'U':
		pktbuf = 1;
		break;
	case 's':
		snaplen = strtoul(optarg, NULL, 10);
		if (snaplen == 0) {
			if (errno != 0) {
				fprintf(stderr, "snaplen must be a positive integer.\n");
				return -EX_USAGE;
			}

			snaplen = 65535;
		}
		if (snaplen > 65535) {
			fprintf(stderr, "max snaplen is 65535 bytes\n");
			return -EX_USAGE;
		}
		break;
	case 'i':
		ifname = optarg;
		break;
	case 'F':
		fpath = optarg;
		break;
	case 'w':
		wpath = optarg;
		break;
	case '?':
		if (optopt == 's' || optopt == 'i' || optopt == 'F' || optopt == 'w')
			fprintf(stderr, "option -%c requires an argument.\n", optopt);
		else if (isprint (optopt))
			fprintf(stderr, "unknown option `-%c'.\n", optopt);
		else
			fprintf(stderr, "unknown option character `\\x%x'.\n", optopt);
		return -EX_USAGE;
	default:
		return -EX_SOFTWARE;
	}

	if (optind != argc) {
		fprintf(stderr, "we do not accept any arguments\n");
		return -EX_USAGE;
	}
	/* for (index = optind; index < argc; index++)
		printf("Non-option argument %s\n", argv[index]); */

	if (!ifname) {
		fprintf(stderr, "must supply an interface name to sniff on\n");
		return -EX_USAGE;
	}

	if (!strcmp(ifname, "any")) {
		ifname = NULL;

		if (promisc) {
			fprintf(stderr, "ignoring promisc mode for interface 'any'\n");
			promisc = 0;
		}
	}

	return 0;
}

int cook_fprog(struct sock_fprog *fprog)
{
	FILE		*file;
	unsigned int	n, code, jt, jf, k;

	if (!strcmp(fpath, "-"))
		file = stdin;
	else {
		if (!(file = fopen(fpath, "r"))) {
			perror("fopen[filter]");
			return -EX_NOINPUT;
		}
	}

	fprog->len = 0;
	fprog->filter = NULL;
	while (1) {
		errno = 0;

		/* tcpdump -i lo -dd <filter> */
		n = fscanf(file, "{ 0x%2x, %u, %u, 0x%8x },\n", &code, &jt, &jf, &k);
		if (n == EOF)
			break;

		if (n == 4) {
			if (jt > 255 || jf > 255) {
				fprintf(stderr, "invalid data types in filter\n");
				free(fprog->filter);
				return -EX_DATAERR;
			}

			if (!(fprog->filter = realloc(fprog->filter,
					(fprog->len+1)*sizeof(struct sock_filter)))) {
				perror("realloc[filter]");
				free(fprog->filter);
				return -EX_SOFTWARE;
			}

			fprog->filter[fprog->len].code	= code;
			fprog->filter[fprog->len].jt	= jt;
			fprog->filter[fprog->len].jf	= jf;
			fprog->filter[fprog->len].k	= k;

			/* fixups */
			switch (BPF_CLASS(code)) {
			/* http://marc.info/?l=tcpdump-workers&m=96542058228629&w=2 */
			case BPF_RET:
				if (k)
					fprog->filter[fprog->len].k = 65535;
				break;
			/* ld/st's for DLT_LINUX_SLL are +2 compared to lo */
			case BPF_LD:
			case BPF_LDX:
			case BPF_ST:
			case BPF_STX:
				if (pcap_hdr.network == DLT_LINUX_SLL)
					fprog->filter[fprog->len].k += 2;
				break;
			}

			fprog->len++;
		}
		else if (errno != 0) {
			perror("fscanf");
			free(fprog->filter);
			return -EX_DATAERR;
		}
		else {
			fprintf(stderr, "malformed filter\n");
			free(fprog->filter);
			return -EX_DATAERR;
		}
	}

	fclose(file);

	if (fprog->len == 0) {
		fprintf(stderr, "filter is empty\n");
		return -EX_DATAERR;
	}

	return 0;
}

int set_promisc(unsigned int state) {
	struct ifreq ifr;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		perror("ioctl[SIOCGIFFLAGS]");
		return -EX_OSERR;
	}

	/* if already IFF_PROMISC then do nothing */
	if (ifr.ifr_flags & IFF_PROMISC)
		promisc = 0;
	else {
		if (state)
			ifr.ifr_flags |= IFF_PROMISC;
		else
			ifr.ifr_flags &= ~IFF_PROMISC;

		if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
			perror("ioctl[SIOCSIFFLAGS]");
			return -EX_OSERR;
		}
	}

	return 0;
}

int get_phys(void) {
	struct ifreq	ifr;
	int 		ret;

	/* get the interface type */
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
		perror("ioctl[SIOCGIFHWADDR]");
		return -EX_OSERR;
	}

	/* consult libpcap/pcap-linux.c:map_arphrd_to_dlt() for wisdom */
	switch (ifr.ifr_hwaddr.sa_family) {
	case ARPHRD_ETHER:
	case ARPHRD_LOOPBACK:
		ret = DLT_EN10MB;
		break;
	case ARPHRD_IEEE80211:
		ret = DLT_IEEE802_11;
		break;
	case ARPHRD_PPP:
		ret = DLT_LINUX_SLL;
		break;
	case ARPHRD_NONE:
		ret = DLT_RAW;
		break;
	default:
		fprintf(stderr, "unknown interface type\n");
		ret = -EX_SOFTWARE;
	}

	return ret;
}

/* alot gleened from http://www.linuxjournal.com/article/4659 */
int open_sock(void) {
	struct ifreq		ifr;
	struct sockaddr_ll	sa_ll;
	struct sock_fprog	fprog;
	int			ret, flags;
	unsigned int		sock_type;
	char			drain[1];
	struct sock_filter	total_insn	= BPF_STMT(BPF_RET | BPF_K, 0);
	struct sock_fprog	total_fcode	= { 1, &total_insn };

	if (getuid()) {
		fprintf(stderr, "must run as root\n");
		return -EX_NOPERM;
	}

	/* if we are capturing on 'any' then SOCK_RAW is meaningless */
	sock_type = (ifname) ? SOCK_RAW : SOCK_DGRAM;

	if ((sock = socket(PF_PACKET, sock_type, htons(ETH_P_ALL))) < 0) {
		perror("socket error");
		return -EX_OSERR;
	}

	if (ifname) {
		if ((pcap_hdr.network = get_phys()) < 0) {
			close(sock);
			return pcap_hdr.network;
		}
	}
	else
		pcap_hdr.network = DLT_LINUX_SLL;
	pcap_hdr.snaplen = snaplen;

	if (fpath) {
		if ((ret = cook_fprog(&fprog))) {
			close(sock);
			return -ret;
		}

		/* deal with socket() -> filter() race */
		if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
		       		&total_fcode, sizeof(total_fcode)) < 0) {
			perror("setsockopt[SO_ATTACH_FILTER-total]");
			free(fprog.filter);
			close(sock);
			return -EX_OSERR;
		}
		while (recv(sock, &drain, sizeof(drain), MSG_TRUNC|MSG_DONTWAIT) >= 0)
			;

		if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0) {
			perror("setsockopt[SO_ATTACH_FILTER]");
			free(fprog.filter);
			close(sock);
			return -EX_OSERR;
		}

		free(fprog.filter);
	}

	if (ifname) {
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
		if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
			perror("ioctl[SIOCGIFINDEX]");
			close(sock);
			return -EX_OSERR;
		}

		memset(&sa_ll, 0, sizeof(sa_ll));

		sa_ll.sll_family	= AF_PACKET;
		sa_ll.sll_protocol	= htons(ETH_P_ALL);
		sa_ll.sll_ifindex	= ifr.ifr_ifindex;

		/* FIXME we need this later */
		ifidx = ifr.ifr_ifindex;

		if ((bind(sock, (struct sockaddr *)&sa_ll, sizeof(sa_ll))) == -1) {
			perror("bind");
			close(sock);
			return -EX_OSERR;
		}
	}

	if (promisc)
		if ((ret = set_promisc(1))) {
			close(sock);
			return ret;
		}

	/* select()/poll() manpage says it is safer under Linux to use O_NONBLOCK */
	if ((flags = fcntl(sock, F_GETFL, 0)) == -1) {
		perror("fcntl[F_GETFL]");
		close(sock);
		return -EX_OSERR;
	}
	if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
		perror("fcntl[F_SETFL]");
		close(sock);
		return -EX_OSERR;
	}

	/* FIXME we need the loopback ifindex to do filtering in the main loop */
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
	if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
		perror("ioctl[SIOCGIFINDEX-lo]");
		close(sock);
		return -EX_OSERR;
	}
	ifidx_lo = ifr.ifr_ifindex;

	return 0;
}

int main(int argc, char **argv)
{
	int			ret, n;
	FILE			*file;
	struct pollfd		pollfd;
	void			*buf;
	struct timeval		tv;
	struct pcaprec_hdr_s	pcaprec_hdr;
	struct sll_header	hdrp;
	struct sockaddr_ll	from;
	socklen_t		fromlen = sizeof(from);

	if ((ret = parse_args(argc, argv)))
		return -ret;

	if (!(buf = malloc(snaplen))) {
		perror("malloc[buf]");
		return EX_SOFTWARE;
	}

	/* FIXME in case of error, remove promisc between here at the loop */
	if ((ret = open_sock()))
		return -ret;

	if (!strcmp(wpath, "-"))
		file = stdout;
	else {
		if (!(file = fopen(wpath, "w"))) {
			perror("fopen[write]");
			close(sock);
			return EX_OSFILE;
		}
	}

	fwrite(&pcap_hdr, sizeof(pcap_hdr), 1, file);
	if (ferror(file)) {
		perror("fwrite[hdr]");
		close(sock);
		fclose(file);
		return EX_OSERR;
	}
	fflush(file);

	if (signal(SIGTERM, sig_handler) == SIG_ERR
			|| signal(SIGPIPE, sig_handler) == SIG_ERR
			|| signal(SIGQUIT, sig_handler) == SIG_ERR
			|| signal(SIGHUP, sig_handler) == SIG_ERR	/* TODO */
			|| signal(SIGINT, sig_handler) == SIG_ERR) {
		perror("signal");
		close(sock);
		fclose(file);
		return EX_OSERR;
	}

	ret = EX_OK;
	pollfd.fd	= sock;
	pollfd.events	= POLLIN;
	while (running) {
		/* 
		 * we have to use select() as a blocking recvfrom() will not
		 * return -EINTR upon receiving a signal
		 */
		if (poll(&pollfd, 1, -1) == -1) {
			if (errno == EINTR)
				continue;
			perror("poll");
			ret = EX_OSERR;
			kill(getpid(), SIGQUIT);
		}

		if ((n = recvfrom(sock, buf, snaplen, MSG_TRUNC,
				(struct sockaddr *)&from, &fromlen)) == -1) {
			perror("recvfrom");
			ret = EX_OSERR;
			kill(getpid(), SIGQUIT);
		}

		/* HACK handle race between socket() and bind() */
		if (ifname && from.sll_ifindex != ifidx)
			continue;

		/* drop egress loopback traffic as we see it at the ingress point */
		if (from.sll_ifindex == ifidx_lo
				&& from.sll_pkttype == PACKET_OUTGOING)
			continue;

		if (ioctl(sock, SIOCGSTAMP, &tv) == -1) {
			perror("ioctl[SIOCGSTAMP]");
			ret = EX_OSERR;
			kill(getpid(), SIGQUIT);
		}

		/* FIXME Y2038 problem (also 64bit tv -> 32bit) */
		pcaprec_hdr.ts_sec	= tv.tv_sec;
		pcaprec_hdr.ts_usec	= tv.tv_usec;
		pcaprec_hdr.incl_len	= (n > snaplen) ? snaplen : n;
		pcaprec_hdr.orig_len	= n;
	
		if (pcap_hdr.network == DLT_LINUX_SLL)
			pcaprec_hdr.incl_len	+= sizeof(hdrp);

		fwrite(&pcaprec_hdr, sizeof(pcaprec_hdr), 1, file);
		if (ferror(file)) {
			perror("fwrite[rec_hdr]");
			ret = EX_OSERR;
			kill(getpid(), SIGQUIT);
		}
		if (pcap_hdr.network == DLT_LINUX_SLL) {
			hdrp.sll_pkttype	= htons(from.sll_pkttype);
			hdrp.sll_hatype		= htons(from.sll_hatype);
			hdrp.sll_halen		= htons(from.sll_halen);
			memcpy(hdrp.sll_addr, from.sll_addr,
				(from.sll_halen > SLL_ADDRLEN)
					? SLL_ADDRLEN : from.sll_halen);
			hdrp.sll_protocol	= from.sll_protocol;

			fwrite(&hdrp, sizeof(hdrp), 1, file);
			if (ferror(file)) {
				perror("fwrite[hdrp]");
				ret = EX_OSERR;
				kill(getpid(), SIGQUIT);
			}
		}
		fwrite(buf, (n > snaplen) ? snaplen : n, 1, file);
		if (ferror(file)) {
			perror("fwrite[buf]");
			ret = EX_OSERR;
			kill(getpid(), SIGQUIT);
		}

		if (pktbuf)
			fflush(file);
	}

	if (promisc)
		ret = -set_promisc(0);

	close(sock);
	fclose(file);

	return ret;
}
