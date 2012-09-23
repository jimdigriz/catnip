/* snippets from pcap/sll.h */

#define SLL_ADDRLEN		8
#define SLL_HDR_LEN		16

struct sll_header {
	u_int16_t	sll_pkttype;		/* packet type */
	u_int16_t	sll_hatype;		/* link-layer address type */
	u_int16_t	sll_halen;		/* link-layer address length */
	u_int8_t	sll_addr[SLL_ADDRLEN];	/* link-layer address */
	u_int16_t	sll_protocol;		/* protocol */
};
