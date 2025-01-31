/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include <net/if.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <math.h>
#include <getopt.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include <sys/resource.h>
#include <net/ethernet.h>
#include "xdp_metadata.h"

#include "../common/common_params.h"

struct config {
	enum xdp_attach_mode attach_mode;
	__u32 xdp_flags;
	int ifindex;
	char *ifname;
	bool do_unload;
	char filename[512];
	__u16 xsk_bind_flags;
	int xsk_if_queue;
    bool unload_all;

};

struct option lgopts[] = {
        {"eth dev", required_argument, 0, 'e'}, // Ethernet NIC used for packet switching <ifname>

        {"wifi dev", required_argument, 0, 'w'}, // WiFi NIC used for packet switching <ifname>

		{"sleep duration", required_argument, 0, 's'}, // Get sleep duration from <value>

        {"timeout duration", required_argument, 0, 't'}, // Maximum timeout from <value>

        {"native-mode", no_argument, NULL, 'n'}, // Attach XDP Redirect program in native mode

        {"generic-mode",	 no_argument, NULL, 'g' }, // Attach XDP Redirect program in generic mode

        {"filename", required_argument, 0, 'f'}, //Load XDP kernel program from <file>

		{ NULL,  0, 0, 0 }
	};

#define EXIT_OK 		 0
#define EXIT_FAIL_OPTION	 2

#define NUM_DESC 			131072

#define NUM_FRAMES         NUM_DESC // Total number of frames in UMEM
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE //Size of each frame in UMEM

#define XSK_CONS_AMOUNT			NUM_DESC // Number of descriptors in RX queue and Completion queue
#define XSK_PROD_AMOUNT		    NUM_DESC // Number of descriptors in the TX queue and Fill queue

#define BATCH_SIZE		    32 

static struct xdp_program *wifi_prog, *eth_prog;
struct config wifi_cfg, eth_cfg; 
struct xsk_socket_info *wifi_socket, *eth_socket;
int wifi_xsk_map_fd, eth_xsk_map_fd;
bool wifi_custom_xsk = true, eth_custom_xsk = true;

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_umem {
	struct xsk_ring_prod *fill_save;
	struct xsk_ring_cons *comp_save;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;
};

struct ThreadArgs {
    struct xsk_socket_info *wifi_socket, *eth_socket;
};

// static const struct option_wrapper long_options[] = {

// 	{{"eth dev",	 required_argument,	NULL, 'e' },
// 	 "Ethernet NIC used for packet switching <ifname>", "<ifname>", true},

//     {{"wifi dev",	 required_argument,	NULL, 'w' },
// 	 "WiFi NIC used for packet switching <ifname>", "<ifname>", true},

// 	{{"filename",    required_argument,	NULL,  'f'  },
// 	 "Load XDP kernel program from <file>", "<file>"},

//     {{"native-mode", no_argument,		NULL, 'n' },
// 	 "Attach XDP Redirect program in native mode"},

//     {{"generic-mode",	 no_argument,		NULL, 'g' },
// 	 "Attach XDP Redirect program in generic mode"},

// 	{{"sleep duration",	 required_argument,	NULL,  's'  },
// 	 "Get sleep duration from <value>", "<value>"},

//     {{"timeout duration ",	 required_argument,	NULL,  't'  },
// 	 "Maximum wait time from <value>", "<value>"},

// 	{{0, 0, NULL,  0 }, NULL, false}
// };

volatile sig_atomic_t global_exit = 0;


struct pack_desc {
	uint64_t addr[XSK_CONS_AMOUNT];
	uint32_t len[XSK_CONS_AMOUNT];
	uint32_t n_pkts_rear;
	uint32_t n_pkts_front;
	uint32_t size;
	long long dq_time[XSK_CONS_AMOUNT];
};

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
	struct xsk_umem_info *umem;
	struct xsk_umem_config cfg_umem = {
		.fill_size = XSK_PROD_AMOUNT,
		.comp_size = XSK_CONS_AMOUNT,
		.frame_size = FRAME_SIZE,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = 0
	};
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return NULL;

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       &cfg_umem);

	if (ret) {
		errno = -ret;
		return NULL;
	}

	umem->buffer = buffer;
	return umem;
}

static struct xsk_socket_info *xsk_configure_wifi_socket(struct config *cfg,
						    struct xsk_umem_info *wifi_umem)
{
	struct xsk_socket_config xsk_cfg;
	struct xsk_socket_info *xsk_info;
	uint32_t idx;
	int i;
	int ret;

	xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	xsk_info->umem = wifi_umem;
	xsk_cfg.rx_size = XSK_CONS_AMOUNT;
	xsk_cfg.tx_size = XSK_PROD_AMOUNT;
	xsk_cfg.xdp_flags = cfg->xdp_flags;
	xsk_cfg.bind_flags = cfg->xsk_bind_flags | XDP_USE_NEED_WAKEUP;
	xsk_cfg.libbpf_flags = (wifi_custom_xsk) ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD: 0;
	ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
				 cfg->xsk_if_queue, wifi_umem->umem, &xsk_info->rx,
				 &xsk_info->tx, &xsk_cfg);
	if (ret)
		goto error_exit;

    if(wifi_custom_xsk){
        ret = xsk_socket__update_xskmap(xsk_info->xsk, wifi_xsk_map_fd);
        if (ret)
            goto error_exit;
    }
    

	ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
				     XSK_PROD_AMOUNT,
				     &idx);
					 
	if (ret != XSK_PROD_AMOUNT)
		goto error_exit;

	for (i = 0; i < XSK_PROD_AMOUNT; i ++)
		*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) = i * FRAME_SIZE;

	xsk_ring_prod__submit(&xsk_info->umem->fq,
			      XSK_PROD_AMOUNT);

	return xsk_info;

error_exit:
	errno = -ret;
	return NULL;
}

static struct xsk_socket_info *xsk_configure_eth_socket(struct config *cfg,
						    struct xsk_umem_info *wifi_umem, struct xsk_umem_info *eth_umem)
{
	struct xsk_socket_config xsk_cfg;
	struct xsk_socket_info *xsk_info;
	uint32_t idx;
	int i;
	int ret;

	xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	xsk_info->umem = eth_umem;
	xsk_cfg.rx_size = XSK_CONS_AMOUNT;
	xsk_cfg.tx_size = XSK_PROD_AMOUNT;
	xsk_cfg.xdp_flags = cfg->xdp_flags ;
	xsk_cfg.bind_flags = cfg->xsk_bind_flags | XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY;
	xsk_cfg.libbpf_flags = (eth_custom_xsk) ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD: 0;
	ret = xsk_socket__create_shared(&xsk_info->xsk, cfg->ifname,
				 cfg->xsk_if_queue, wifi_umem->umem, &xsk_info->rx,
				 &xsk_info->tx, eth_umem->umem->fill_save, eth_umem->umem->comp_save, &xsk_cfg);
				 
	if (ret)
		goto error_exit;


    if(eth_custom_xsk){
        ret = xsk_socket__update_xskmap(xsk_info->xsk, eth_xsk_map_fd);
        if (ret){
            goto error_exit;
        }
    }

	ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,XSK_PROD_AMOUNT,&idx);

	if (ret != XSK_PROD_AMOUNT)
		goto error_exit;

	for (i = 0; i < XSK_PROD_AMOUNT; i ++)
		*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) = i * FRAME_SIZE;

	xsk_ring_prod__submit(&xsk_info->umem->fq,
			      XSK_PROD_AMOUNT);

	return xsk_info;

error_exit:
	errno = -ret;
	return NULL;
}

long sleep_duration = 0;
long long timeout = 0;

#define NANOSEC_PER_SEC 1000000000 /* 1s */
#define TARGET 5000000 /* 5ms */
#define INTERVAL 100000000 /* 100 ms */ 

// --------------------------------------------
// Wireless to Ethernet packet switching thread
// --------------------------------------------
static void *wifi_to_eth(void *args)
{
	struct ThreadArgs* threadArgs = (struct ThreadArgs*)args;
	struct pack_desc b = {0};
	b.n_pkts_rear = XSK_CONS_AMOUNT - 1;
	struct timespec req, rem;

    req.tv_sec = sleep_duration / NANOSEC_PER_SEC;
    req.tv_nsec = (sleep_duration % NANOSEC_PER_SEC);

	unsigned char src_mac[ETH_ALEN];
	unsigned char dst_mac[ETH_ALEN];

	src_mac[0]=0x08;
	src_mac[1]=0xc0;
	src_mac[2]=0xeb;
	src_mac[3]=0xbe;
	src_mac[4]=0x9a;
	src_mac[5]=0xae;

	dst_mac[0]=0x08;
	dst_mac[1]=0xc0;
	dst_mac[2]=0xeb;
	dst_mac[3]=0xbe;
	dst_mac[4]=0x9d;
	dst_mac[5]=0x2e;

	cpu_set_t cpu_cores;

	CPU_ZERO(&cpu_cores);
	CPU_SET(2, &cpu_cores);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);
	
	uint32_t rcvd_in_rx_queue, rcvd_actual, tx_avail, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	uint32_t completed = 0, fq_reserve = 0, dropped = 0;
	uint32_t idx_cq = 0;
	uint32_t tx_idx = 0;
	bool send_flag = false;
	uint32_t stat_tot_freed_from_CQ = 0;
	uint32_t stat_tot_received_in_TX  = 0;

	void *pkt = 0;	
	struct ethhdr *eth = 0;
	struct xdp_meta *meta;

	//Time Based Batching 
	struct timespec cT;
	long long nextpeek = 0, dequeue_time = 0;

	//CoDel Algorithm
	bool first_delay = false;
	int count = 0;
	struct timespec codel_interval;
	long long start, end, interval = INTERVAL;

	while(!global_exit) {

		rcvd_in_rx_queue = 0, rcvd_actual = 0, tx_avail = 0, i = 0;
		idx_rx = 0, idx_fq = 0;
		completed = 0, fq_reserve = 0, dropped = 0;
		idx_cq = 0;
		tx_idx = 0;
		send_flag = false;

		do
		{
            //SR STAGE
			if(stat_tot_received_in_TX != stat_tot_freed_from_CQ){
				sendto(xsk_socket__fd(threadArgs->eth_socket->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

				completed = xsk_ring_cons__peek(&threadArgs->eth_socket->umem->cq, XSK_CONS_AMOUNT, &idx_cq);

				if(completed > 0){
					stat_tot_freed_from_CQ += completed;

					xsk_ring_cons__release(&threadArgs->wifi_socket->rx, completed);
					fq_reserve = xsk_ring_prod__reserve(&threadArgs->wifi_socket->umem->fq, completed, &idx_fq);
					
					if (fq_reserve != completed){
						printf("\n\nERROR!: fq_reserve != completed\n");
						global_exit =  true;
					}
					
					for (i = 0; i < completed; ++i){
						*xsk_ring_prod__fill_addr(&threadArgs->wifi_socket->umem->fq, idx_fq) = *xsk_ring_cons__comp_addr(&threadArgs->eth_socket->umem->cq, idx_cq);
						++idx_fq;
						++idx_cq;
					}

					xsk_ring_cons__release(&threadArgs->eth_socket->umem->cq, completed);

					xsk_ring_prod__submit(&threadArgs->wifi_socket->umem->fq, completed);
				}
			}

            //SL STAGE
			if(b.size < 32)
				clock_nanosleep(CLOCK_MONOTONIC,0, &req, &rem);

            //PB STAGE
			rcvd_in_rx_queue = xsk_ring_cons__peek(&threadArgs->wifi_socket->rx, XSK_CONS_AMOUNT, &idx_rx);

			if(rcvd_in_rx_queue > 0){

				for (i = 0; i < rcvd_in_rx_queue; i++) {
					b.n_pkts_rear = (b.n_pkts_rear + 1) % XSK_CONS_AMOUNT;

					b.addr[b.n_pkts_rear] = xsk_ring_cons__rx_desc(&threadArgs->wifi_socket->rx, idx_rx)->addr;
					b.len[b.n_pkts_rear] = xsk_ring_cons__rx_desc(&threadArgs->wifi_socket->rx, idx_rx)->len;

					clock_gettime(CLOCK_MONOTONIC, &cT);
					dequeue_time = cT.tv_sec * NANOSEC_PER_SEC + cT.tv_nsec;

					b.dq_time[b.n_pkts_rear] = dequeue_time;
					++idx_rx;
					++b.size;
				}
			}

			tx_avail = xsk_prod_nb_free(&threadArgs->eth_socket->tx, XSK_PROD_AMOUNT);

			clock_gettime(CLOCK_MONOTONIC, &cT);
			nextpeek = cT.tv_sec * NANOSEC_PER_SEC + cT.tv_nsec;

            //BA STAGE
			if(tx_avail > 0 && b.size > 0){
				if((b.size >= BATCH_SIZE) || ((nextpeek - b.dq_time[b.n_pkts_front]) > timeout))
					send_flag = true;
			}

		} while(!send_flag && !global_exit);

		if (global_exit){
            printf("TOTAL IN TX FOR W2E %d\n", stat_tot_received_in_TX);
			continue;
		}

        //CS STAGE
		rcvd_actual = (tx_avail < b.size) ? tx_avail : b.size;
		rcvd_actual = (rcvd_actual < BATCH_SIZE) ? rcvd_actual : BATCH_SIZE;
		dropped = 0;

		
		for (i = 0; i < rcvd_actual; i++) {
			pkt = xsk_umem__get_data(threadArgs->wifi_socket->umem->buffer, b.addr[b.n_pkts_front]);  
			meta = pkt - sizeof(*meta);

			clock_gettime(CLOCK_MONOTONIC, &cT);
			nextpeek = cT.tv_sec * NANOSEC_PER_SEC + cT.tv_nsec;

			if(!(nextpeek - meta->rx_timestamp > TARGET)){
				int tq_reserve;
				tq_reserve = xsk_ring_prod__reserve(&threadArgs->eth_socket->tx, 1, &tx_idx);

				if(tq_reserve != 1){
					printf("\n\nERROR!: tq_reserve != 1\n");
					global_exit =  true;
				}

				eth = (struct ethhdr *) pkt;
				
				memcpy(eth->h_dest, dst_mac, ETH_ALEN);
				memcpy(eth->h_source, src_mac, ETH_ALEN);

				xsk_ring_prod__tx_desc(&threadArgs->eth_socket->tx, tx_idx)->addr = b.addr[b.n_pkts_front];
				xsk_ring_prod__tx_desc(&threadArgs->eth_socket->tx, tx_idx)->len = b.len[b.n_pkts_front];
				stat_tot_received_in_TX++;

				if(first_delay){
					first_delay = false;
					interval = INTERVAL;
					count = 0;
				}
			}
			else{
				if(first_delay){
					clock_gettime(CLOCK_MONOTONIC, &codel_interval);
					end = codel_interval.tv_sec * NANOSEC_PER_SEC + codel_interval.tv_nsec;

					if(end - start >= interval){
						
						fq_reserve = xsk_ring_prod__reserve(&threadArgs->wifi_socket->umem->fq, 1, &idx_fq);
						if(fq_reserve != 1){
							printf("\n\nERROR!: fq_reserve != 1\n");
							global_exit =  true;
						}

						*xsk_ring_prod__fill_addr(&threadArgs->wifi_socket->umem->fq, idx_fq) = b.addr[b.n_pkts_front];

						xsk_ring_cons__release(&threadArgs->wifi_socket->rx, 1);
						xsk_ring_prod__submit(&threadArgs->wifi_socket->umem->fq, 1);
						dropped++;

						printf("Packet is Dropped in W2E\n");

						count++;
						interval += INTERVAL/sqrt(count);
					}
					else{
						int tq_reserve;
						tq_reserve = xsk_ring_prod__reserve(&threadArgs->eth_socket->tx, 1, &tx_idx);

						if(tq_reserve != 1){
							printf("\n\nERROR!: tq_reserve != 1\n");
							global_exit =  true;
						}

						eth = (struct ethhdr *) pkt;
						
						memcpy(eth->h_dest, dst_mac, ETH_ALEN);
						memcpy(eth->h_source, src_mac, ETH_ALEN);

						xsk_ring_prod__tx_desc(&threadArgs->eth_socket->tx, tx_idx)->addr = b.addr[b.n_pkts_front];
						xsk_ring_prod__tx_desc(&threadArgs->eth_socket->tx, tx_idx)->len = b.len[b.n_pkts_front];

						stat_tot_received_in_TX++;
					}
				}
				else{
					first_delay = true;
					clock_gettime(CLOCK_MONOTONIC, &codel_interval);
					start = codel_interval.tv_sec * NANOSEC_PER_SEC + codel_interval.tv_nsec;

					int tq_reserve;
					tq_reserve = xsk_ring_prod__reserve(&threadArgs->eth_socket->tx, 1, &tx_idx);

					if(tq_reserve != 1){
						printf("\n\nERROR!: tq_reserve != 1\n");
						global_exit =  true;
					}

					eth = (struct ethhdr *) pkt;
					
					memcpy(eth->h_dest, dst_mac, ETH_ALEN);
					memcpy(eth->h_source, src_mac, ETH_ALEN);

					xsk_ring_prod__tx_desc(&threadArgs->eth_socket->tx, tx_idx)->addr = b.addr[b.n_pkts_front];
					xsk_ring_prod__tx_desc(&threadArgs->eth_socket->tx, tx_idx)->len = b.len[b.n_pkts_front];
					stat_tot_received_in_TX++;
				}
			}
			b.n_pkts_front = (b.n_pkts_front + 1) % XSK_CONS_AMOUNT;
			--b.size;
		}
		xsk_ring_prod__submit(&threadArgs->eth_socket->tx, rcvd_actual - dropped);
	}
	return NULL;
}

// --------------------------------------------
// Ethernet to Wireless packet switching thread
// --------------------------------------------
static void *eth_to_wifi(void *args)
{
	struct ThreadArgs* threadArgs = (struct ThreadArgs*)args;
	struct pack_desc b = {0};
	b.n_pkts_rear = XSK_CONS_AMOUNT - 1;
	struct timespec req, rem;

    req.tv_sec = sleep_duration / NANOSEC_PER_SEC;
    req.tv_nsec = (sleep_duration % NANOSEC_PER_SEC);

	unsigned char src_mac[ETH_ALEN];
	unsigned char dst_mac[ETH_ALEN];

	src_mac[0]=0x3c;
	src_mac[1]=0xe9;
	src_mac[2]=0xf7;
	src_mac[3]=0x61;
	src_mac[4]=0x41;
	src_mac[5]=0x85;

	dst_mac[0]=0xe0;
	dst_mac[1]=0x07;
	dst_mac[2]=0x1b;
	dst_mac[3]=0x74;
	dst_mac[4]=0x9d;
	dst_mac[5]=0x11;

	cpu_set_t cpu_cores;

	CPU_ZERO(&cpu_cores);
	CPU_SET(2, &cpu_cores);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);

	uint32_t rcvd_in_rx_queue, rcvd_actual, tx_avail, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	uint32_t completed = 0, fq_reserve = 0, dropped = 0;
	uint32_t idx_cq = 0;
	uint32_t tx_idx = 0;
	bool send_flag = false;
	uint32_t stat_tot_freed_from_CQ = 0;
	uint32_t stat_tot_received_in_TX  = 0;

	void *pkt = 0;	
	struct ethhdr *eth = 0;
	struct xdp_meta *meta;

	//Time Based Batching 
	struct timespec cT;
	long long nextpeek = 0, dequeue_time;

	//CoDel Algorithm
	bool first_delay = false;
	int count = 0;
	struct timespec codel_interval;
	long long start, end, interval = INTERVAL;

	while(!global_exit) {
		rcvd_in_rx_queue = 0, rcvd_actual = 0, tx_avail = 0, i = 0;
		idx_rx = 0, idx_fq = 0;
		completed = 0, fq_reserve = 0, dropped = 0;
		idx_cq = 0;
		tx_idx = 0;
		send_flag = false;
		
		do
		{
            //SR STAGE
			if(stat_tot_received_in_TX != stat_tot_freed_from_CQ){
				sendto(xsk_socket__fd(threadArgs->wifi_socket->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

				completed = xsk_ring_cons__peek(&threadArgs->wifi_socket->umem->cq,XSK_CONS_AMOUNT,&idx_cq);
				
				if(completed>0){
					stat_tot_freed_from_CQ += completed;

					xsk_ring_cons__release(&threadArgs->eth_socket->rx, completed);
					fq_reserve = xsk_ring_prod__reserve(&threadArgs->eth_socket->umem->fq, completed, &idx_fq);

					if(fq_reserve != completed){
						printf("\n\nERROR!: fq_reserve != completed\n");
						global_exit =  true;
					}

					for (i = 0; i < completed; i++){
						*xsk_ring_prod__fill_addr(&threadArgs->eth_socket->umem->fq, idx_fq) = *xsk_ring_cons__comp_addr(&threadArgs->wifi_socket->umem->cq,idx_cq);
						++idx_fq;
						++idx_cq;
					}

					xsk_ring_cons__release(&threadArgs->wifi_socket->umem->cq, completed);
					xsk_ring_prod__submit(&threadArgs->eth_socket->umem->fq, completed);
				}
			}

            //SL STAGE
			if(b.size < 32)
				clock_nanosleep(CLOCK_MONOTONIC,0, &req, &rem);

            //PB STAGE
			rcvd_in_rx_queue = xsk_ring_cons__peek(&threadArgs->eth_socket->rx, XSK_CONS_AMOUNT, &idx_rx);

			if(rcvd_in_rx_queue > 0){
				for (i = 0; i < rcvd_in_rx_queue; i++) {
					b.n_pkts_rear = (b.n_pkts_rear + 1) % XSK_CONS_AMOUNT;

					b.addr[b.n_pkts_rear] = xsk_ring_cons__rx_desc(&threadArgs->eth_socket->rx, idx_rx)->addr;
					b.len[b.n_pkts_rear] = xsk_ring_cons__rx_desc(&threadArgs->eth_socket->rx, idx_rx)->len;

					clock_gettime(CLOCK_MONOTONIC, &cT);
					dequeue_time = cT.tv_sec * NANOSEC_PER_SEC + cT.tv_nsec;

					b.dq_time[b.n_pkts_rear] = dequeue_time;
					++idx_rx;
					++b.size;
				}
			}

            tx_avail = xsk_prod_nb_free(&threadArgs->wifi_socket->tx, XSK_PROD_AMOUNT);

			clock_gettime(CLOCK_MONOTONIC, &cT);
			nextpeek = cT.tv_sec * NANOSEC_PER_SEC + cT.tv_nsec;
			
            //BA STAGE
			if(tx_avail > 0 && b.size > 0){
				if((b.size >= BATCH_SIZE) || ((nextpeek - b.dq_time[b.n_pkts_front]) > timeout))
					send_flag = true;
			}

		} while(!send_flag && !global_exit);

		if (global_exit){
            printf("TOTAL IN TX FOR W2E %d\n", stat_tot_received_in_TX);
			continue;
		}

        //CS STAGE
		rcvd_actual = (tx_avail < b.size) ? tx_avail : b.size;
		rcvd_actual = (rcvd_actual < BATCH_SIZE) ? rcvd_actual : BATCH_SIZE;
		dropped = 0;

		for (i = 0; i < rcvd_actual; i++) {
			pkt = xsk_umem__get_data(threadArgs->eth_socket->umem->buffer, b.addr[b.n_pkts_front]);  
			meta = pkt - sizeof(*meta);

			clock_gettime(CLOCK_MONOTONIC, &cT);
			nextpeek = cT.tv_sec * NANOSEC_PER_SEC + cT.tv_nsec;

			if(!(nextpeek- meta->rx_timestamp > TARGET)){
				int tq_reserve;
				tq_reserve = xsk_ring_prod__reserve(&threadArgs->wifi_socket->tx, 1, &tx_idx);

				if(tq_reserve != 1){
					printf("\n\nERROR!: tq_reserve != 1\n");
					global_exit =  true;
				}

				eth = (struct ethhdr *) pkt;
				
				memcpy(eth->h_dest, dst_mac, ETH_ALEN);
				memcpy(eth->h_source, src_mac, ETH_ALEN);

				xsk_ring_prod__tx_desc(&threadArgs->wifi_socket->tx, tx_idx)->addr = b.addr[b.n_pkts_front];
				xsk_ring_prod__tx_desc(&threadArgs->wifi_socket->tx, tx_idx)->len = b.len[b.n_pkts_front];
				stat_tot_received_in_TX++;

				if(first_delay){
					first_delay = false;
					interval = INTERVAL;
					count = 0;
				}
			}
			else{
				if(first_delay){
					clock_gettime(CLOCK_MONOTONIC, &codel_interval);
					end = codel_interval.tv_sec * NANOSEC_PER_SEC + codel_interval.tv_nsec;

					if(end - start >= interval){
						fq_reserve = xsk_ring_prod__reserve(&threadArgs->eth_socket->umem->fq, 1, &idx_fq);
						if(fq_reserve != 1){
							printf("\n\nERROR!: fq_reserve != 1\n");
							global_exit =  true;
						}

						*xsk_ring_prod__fill_addr(&threadArgs->eth_socket->umem->fq, idx_fq) = b.addr[b.n_pkts_front];

						xsk_ring_cons__release(&threadArgs->eth_socket->rx, 1);
						xsk_ring_prod__submit(&threadArgs->eth_socket->umem->fq, 1);
						dropped++;

						printf("DROPPED \n");

						count++;
						interval += INTERVAL/sqrt(count);
					}
					else{
						int tq_reserve;
						tq_reserve = xsk_ring_prod__reserve(&threadArgs->wifi_socket->tx, 1, &tx_idx);

						if(tq_reserve != 1){
							printf("\n\nERROR!: tq_reserve != 1\n");
							global_exit =  true;
						}

						eth = (struct ethhdr *) pkt;
						
						memcpy(eth->h_dest, dst_mac, ETH_ALEN);
						memcpy(eth->h_source, src_mac, ETH_ALEN);

						xsk_ring_prod__tx_desc(&threadArgs->wifi_socket->tx, tx_idx)->addr = b.addr[b.n_pkts_front];
						xsk_ring_prod__tx_desc(&threadArgs->wifi_socket->tx, tx_idx)->len = b.len[b.n_pkts_front];

						stat_tot_received_in_TX++;
					}
				}
				else{
					first_delay = true;
					clock_gettime(CLOCK_MONOTONIC, &codel_interval);
					start = codel_interval.tv_sec * NANOSEC_PER_SEC + codel_interval.tv_nsec;

					int tq_reserve;
					tq_reserve = xsk_ring_prod__reserve(&threadArgs->wifi_socket->tx, 1, &tx_idx);

					if(tq_reserve != 1){
						printf("\n\nERROR!: tq_reserve != 1\n");
						global_exit =  true;
					}

					eth = (struct ethhdr *) pkt;
					
					memcpy(eth->h_dest, dst_mac, ETH_ALEN);
					memcpy(eth->h_source, src_mac, ETH_ALEN);

					xsk_ring_prod__tx_desc(&threadArgs->wifi_socket->tx, tx_idx)->addr = b.addr[b.n_pkts_front];
					xsk_ring_prod__tx_desc(&threadArgs->wifi_socket->tx, tx_idx)->len = b.len[b.n_pkts_front];

					stat_tot_received_in_TX++;
				}
			}
			b.n_pkts_front = (b.n_pkts_front + 1) % XSK_CONS_AMOUNT;
			--b.size;
		}
		xsk_ring_prod__submit(&threadArgs->wifi_socket->tx, rcvd_actual - dropped);
	}
	return NULL;
}

int do_unload(struct config *cfg)
{
	struct xdp_multiprog *mp = NULL;
	int err = EXIT_FAILURE;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);

	mp = xdp_multiprog__get_from_ifindex(cfg->ifindex);
	if (libxdp_get_error(mp)) {
		fprintf(stderr, "Unable to get xdp_dispatcher program: %s\n",
			strerror(errno));
		goto out;
	} else if (!mp) {
		fprintf(stderr, "No XDP program loaded on %s\n", cfg->ifname);
		mp = NULL;
		goto out;
	}

	if (cfg->unload_all) {
		err = xdp_multiprog__detach(mp);
		if (err) {
			fprintf(stderr, "Unable to detach XDP program: %s\n",
				strerror(-err));
			goto out;
		}
	}

out:
	xdp_multiprog__close(mp);
	return err ? EXIT_FAILURE : EXIT_SUCCESS;

}

static void exit_application(int signal)
{
	int err;

	wifi_cfg.unload_all = true;
	err = do_unload(&wifi_cfg);
	if (err) {
		fprintf(stderr, "Couldn't detach XDP program on iface '%s' : (%d)\n",
			wifi_cfg.ifname, err);
	}

	eth_cfg.unload_all = true;
	err = do_unload(&eth_cfg);
	if (err) {
		fprintf(stderr, "The XDP Redirect Program could not be detached from interface '%s' : (%d)\n",
			eth_cfg.ifname, err);
	}

	signal = signal;
	global_exit = true;
}

int main(int argc, char **argv)
{
	void *packet_buffer;
	uint64_t packet_buffer_size;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
	struct xsk_umem_info *wifi_umem, *eth_umem;
	int err;
	char errmsg[1024];

	int opt, option_index;

	/* Parse the input arguments. */
	for ( ; ;) {
		opt = getopt_long(argc, argv, "e:w:s:t:n:g:f:", lgopts, &option_index);
		if (opt == EOF)
			break;

		switch (opt) {
        case 'e':
            eth_cfg.ifname = optarg;
            eth_cfg.ifindex = if_nametoindex(eth_cfg.ifname);
            break;

		case 'w':
			wifi_cfg.ifname = optarg;
			wifi_cfg.ifindex = if_nametoindex(wifi_cfg.ifname);
			break;

		case 's':
            sleep_duration = atoi(optarg);
			break;
        
        case 'n':
            eth_cfg.attach_mode = XDP_MODE_NATIVE;
			break;

        case 'g':
            eth_cfg.attach_mode = XDP_MODE_SKB;
            wifi_cfg.attach_mode = XDP_MODE_SKB;
			break;

        case 't':
            timeout = atoi(optarg);
			break;

        case 'f':
            memcpy(wifi_cfg.filename, optarg, sizeof(wifi_cfg.filename));
            memcpy(eth_cfg.filename, optarg, sizeof(eth_cfg.filename));
			break;

		default:
			printf("Illegal argument.\n");
			break;

		}
	}

	/* Global shutdown handler */
	signal(SIGINT, exit_application);

	if (wifi_cfg.ifindex == -1 || eth_cfg.ifindex == -1) {
		fprintf(stderr, "ERROR: Required option --dev missing\n\n");
		return EXIT_FAIL_OPTION;
	}

	/* Load XDP Redirect Program if configured */
	if (wifi_cfg.filename[0] != 0) {
		struct bpf_map *wifi_map;

		wifi_custom_xsk = true;
		xdp_opts.open_filename = wifi_cfg.filename;
		xdp_opts.opts = &opts;

		wifi_prog = xdp_program__open_file(wifi_cfg.filename,
						  NULL, &opts);
		err = libxdp_get_error(wifi_prog);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "ERR: loading program: %s\n", errmsg);
			return err;
		}

		err = xdp_program__attach(wifi_prog, wifi_cfg.ifindex, wifi_cfg.attach_mode, 0);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n",
				wifi_cfg.ifname, errmsg, err);
			return err;
		}

		/* Load the xsk_map */
		wifi_map = bpf_object__find_map_by_name(xdp_program__bpf_obj(wifi_prog), "xsks_map");
		wifi_xsk_map_fd = bpf_map__fd(wifi_map);
		if (wifi_xsk_map_fd < 0) {
			fprintf(stderr, "ERROR: no xsks map found: %s\n",
				strerror(wifi_xsk_map_fd));
			exit(EXIT_FAILURE);
		}
	}

	if (eth_cfg.filename[0] != 0) {
		struct bpf_map *eth_map;

		eth_custom_xsk = true;
		xdp_opts.open_filename = eth_cfg.filename;
		xdp_opts.opts = &opts;

		eth_prog = xdp_program__open_file(eth_cfg.filename,
						  NULL, &opts);

		err = libxdp_get_error(eth_prog);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "ERR: loading program: %s\n", errmsg);
			return err;
		}

		err = xdp_program__attach(eth_prog, eth_cfg.ifindex, eth_cfg.attach_mode, 0);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n",
				eth_cfg.ifname, errmsg, err);
			return err;
		}

		/* We also need to load the xsks_map */
		eth_map = bpf_object__find_map_by_name(xdp_program__bpf_obj(eth_prog), "xsks_map");
		eth_xsk_map_fd = bpf_map__fd(eth_map);
		if (eth_xsk_map_fd < 0) {
			fprintf(stderr, "ERROR: no xsks1 map found: %s\n",
				strerror(eth_xsk_map_fd));
			exit(EXIT_FAILURE);
		}
	}

	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Allocate memory for frames in the UMEM */
	packet_buffer_size = (uint64_t)NUM_FRAMES * (uint64_t)FRAME_SIZE;
	if (posix_memalign(&packet_buffer,
			   getpagesize(), /* PAGE_SIZE aligned */
			   packet_buffer_size)) {
		fprintf(stderr, "ERROR: Can't allocate memory \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Create UMEM for the packet switching interfaces */
	wifi_umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
	if (wifi_umem == NULL) {
		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	eth_umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
	if (eth_umem == NULL) {
		fprintf(stderr, "ERROR: Can't create UMEM for WiFi \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Create XDP sockets for the packet switching interfaces */
	wifi_socket = xsk_configure_wifi_socket(&wifi_cfg, wifi_umem);
	if (wifi_socket == NULL) {
		fprintf(stderr, "ERROR: Can't create UMEM for Eth \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	eth_socket = xsk_configure_eth_socket(&eth_cfg, wifi_umem, eth_umem);
	if (eth_socket == NULL) {
		fprintf(stderr, "ERROR: Can't setup Eth socket \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct ThreadArgs* thread_arg = (struct ThreadArgs*)malloc(sizeof(struct ThreadArgs));
    thread_arg->wifi_socket = wifi_socket;
    thread_arg->eth_socket = eth_socket;

	pthread_t w2e, e2w;
    pthread_create(&w2e, NULL, wifi_to_eth, thread_arg);
	pthread_create(&e2w, NULL, eth_to_wifi, thread_arg);

	pthread_join(w2e, NULL);
	pthread_join(e2w, NULL);

	xsk_socket__delete(wifi_socket->xsk);
	xsk_umem__delete(wifi_umem->umem);
	xsk_socket__delete(eth_socket->xsk);
	xsk_umem__delete(eth_umem->umem);

	return EXIT_OK;
}