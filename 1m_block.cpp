#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>                 // for strstr
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "libnet-headers.h"
#include <string>
#include <bits/stdc++.h>

using namespace std;

unordered_set<string> host_list;

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}

void usage()
{
	printf("syntax : 1m-block <site list file>\n");
	printf("sample : 1m-block top-1m.txt\n");
}

int flag=0;

int check_url(unsigned char *data, int ret){
    struct libnet_ipv4_hdr *ip_h;
    struct libnet_tcp_hdr *tcp_h;

    ip_h=(struct libnet_ipv4_hdr *)data;
    if(ip_h->ip_p != 0x06){
        return 0;
    }

    int ip_header_len = ((int)ip_h->ip_hl)*4;
    tcp_h = (struct libnet_tcp_hdr *)(data+ip_header_len);

    int tcp_header_len = ((int)tcp_h->th_off)*4;
    int http_data_size = ret - ip_header_len - tcp_header_len;

    if(http_data_size == 0){
        printf("No HTTP data\n\n");
        return 0;
    }

    char *http_data;
    http_data = (char *)(data+ip_header_len+tcp_header_len);

    string h(http_data, http_data_size);

    if( !memcmp(http_data, "GET", 3) || !memcmp(http_data, "HEAD", 4) || !memcmp(http_data, "POST", 4) || !memcmp(http_data, "PUT", 3) || !memcmp(http_data, "DELETE", 6) || !memcmp(http_data, "OPTIONS", 7) || !memcmp(http_data, "CONNECT", 7))
    {
        size_t h_ptr = h.find("Host: ");
        if(h_ptr != std::string::npos){ //When "Host: " exist
            string t_host = h.substr(h_ptr+6);
            size_t rn = t_host.find("\r\n");
            t_host = t_host.substr(0, rn);
            if(host_list.find(t_host) != host_list.end()) return 1;
        }
    }
    return 0;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data); //data = ip header's address

	if (ret >= 0) printf("payload_len=%d ", ret);
	
	fputc('\n', stdout);

    flag = check_url(data, ret);
	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if(flag) {
        flag=0;
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL); //test.gilgil.net에 들어갈 때는 NF_DROP 사용
	}
	else return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	if(argc != 2) {
		usage();
		return 0;
	}

    FILE *fp;
    char file[100]="./";
    strcat(file, argv[1]);
    fp = fopen(file, "r");
    if(fp==NULL){
        printf("FILE OPEN ERR!\n");
        return -1;
    }

    char temp[100];
    while(!feof(fp))
    {
        fscanf(fp, "%s\n", temp);
        char *ptr = strtok(temp, "\t");
        ptr = strtok(NULL, "\t");
        string host(ptr);
        host_list.insert(host);
    }

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}