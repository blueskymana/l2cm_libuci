/*************************************************************************
	> File Name: l2_pcap.h
	> Author: 
	> Mail: 
	> Created Time: 2017年04月13日 星期四 15时08分36秒
 ************************************************************************/

#ifndef _L2_PCAP_H
#define _L2_PCAP_H

enum{
    Min = 0,
    eWire = 1,
    eConfig = 2,  // 配置信息
    eVis = 4,  // 拓扑信息
    eSave = 8,  // 使生效
    Max = 9
};

#define ETHER_TYPE_REQ 0x55aa
#define u_char unsigned char
#define u_short unsigned short

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */

};
#define MEMCPY_SAVE(d,s,size) do{memcpy(d, s, size); d += size;}while(0);

#define ASSEMBLY(p, str) do {\
    char in[64] = str;\
    MEMCPY_SAVE(p, in, strlen(in));\
    MEMCPY_SAVE(p, "=", 1);\
    char out[64] = {0};\
    Uci_get(in, out);\
    MEMCPY_SAVE(p, out, strlen(out))\
    *p++ = '\n';\
}while(0)



int l2_send(struct sniff_ethernet *ether, char type);
#endif
