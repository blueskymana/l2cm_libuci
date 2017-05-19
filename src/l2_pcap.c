
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "l2_pcap.h"
#include "l2_uci.h"
#include "l2_log.h"

static pcap_t *handle;				/* packet capture handle */
static int g_iFlag = 1;

u_char *getInterMac(char *inter)
{
    int s,i;
    static struct ifreq ifr = {0};

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (0 != strcmp(ifr.ifr_name, inter))
    {
        strcpy(ifr.ifr_name, inter);
        ioctl(s, SIOCGIFHWADDR, &ifr);
        //for (i=0; i<HWADDR_len; i++)
        //    mac[i] = ifr.ifr_hwaddr.sa_data[i];
    }
    close(s);
    return ifr.ifr_hwaddr.sa_data;
}

void l2_parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct sniff_ethernet *ethernet = NULL;
    unsigned char *payload = NULL;
    unsigned char *localMac = getInterMac("adhoc0");
    u_char f6[6] = {0xff, 0xff,0xff, 0xff, 0xff, 0x00};

    ethernet = (struct sniff_ethernet*)(packet);

    payload = packet + SIZE_ETHERNET;
    //print_payload (payload, 100);

    u_char type = *payload++;
    payload += 2;
    switch (type) {
        case eWire:
        //set bssid
        if (!memcmp(localMac, ethernet->ether_dhost, ETHER_ADDR_LEN)
            || !memcmp(f6, ethernet->ether_shost, ETHER_ADDR_LEN))
        {
            L2_uci_set(payload);
            //system("ubus call network restart");
            //system("reload_config");
            //usleep(100);
            //l2_send(ethernet, type);
        }
        break;
        case eSave:
        //reboot
        sleep(10);
        system("reboot -f");
        break;
        case eConfig://config set 
        if (!memcmp(localMac, ethernet->ether_shost, ETHER_ADDR_LEN))
        //if (!strncmp(localMac, ethernet->ether_shost, ETHER_ADDR_LEN))
        {
            L2_uci_set_for(payload);
            //system("ubus call network restart");
            //system("reload_config");
            //usleep(100);
            //l2_send(ethernet, type);
        }
        break;
        case 0x0a:
        l2_send(ethernet, *payload);
        break;
        default:
        printf("wrong type");
    }

    return;
}

int RemoveSpaces(char* source)
{
    char* i = source;
    char* j = source;
    while(*j != 0)
    {
        *i = *j++;
        if(*i != ' ')
            i++;
    }
    *i = 0;

    return (i - source);
}

int l2_send_type(u_char *sendbuf, u_char *p,int type)
{
    int iRet = 0;
    int sendlen = 17;
    static int num = 0;
    num++;

    *p++ = type;
    //*(unsigned short *)p = htons(0x256);
    unsigned short *usLen = (unsigned short *)p;
    p += 2;

    char *pcValue = p;

    switch (type)
    {
        case eWire:
        ASSEMBLY(p, "wireless.@wifi-iface[-1].bssid");
        break;
        case eConfig://config
        ASSEMBLY(p, "network.lan.ipaddr");
        //ASSEMBLY(p, "network.lan.netmask");
        //ASSEMBLY(p, "network.lan.type");
        //ASSEMBLY(p, "network.lan.ifname");
        //ASSEMBLY(p, "network.lan.proto");
        ASSEMBLY(p, "wireless.radio0.channel");
        ASSEMBLY(p, "wireless.radio0.txpower");
        ASSEMBLY(p, "wireless.radio0.htmode");
        ASSEMBLY(p, "wireless.@wifi-iface[0].ssid");
        ASSEMBLY(p, "system.@system[0].hostname");
        //ASSEMBLY(p, "");
        break;
        case eVis://vis
        //read_cmd("batadv-vis -f jsondoc", p);
        //printf("###################read_cmd %d", num);
        //read_cmd("batctl o | awk '/adhoc0]/ && $1 == $4 {print $1 \" \" $2 \" \" $3}'", p);
        read_cmd("batctl o | sed 's/*//' | awk '/0]/ && $1 == $4 {print $1 \" \" $2 \" \" $3}'", p);
        //printf("read_cmd###################################" );
        //iRet = RemoveSpaces(p);
        p += iRet;
        break;
        default:
        break;
    }

    *usLen = htons(strlen(pcValue));
    sendlen += *usLen ;// 17 = 14 + 1 + 2
    //sned
    printf("sendlen %d\n", sendlen);
    if (sendlen < 20)
        return 0;
    if (-1 == pcap_sendpacket(handle, sendbuf, sendlen))
    {
        printf("%s", pcap_geterr(handle));
    }
    print_payload(sendbuf, sendlen);

    memset(pcValue, 0, (1500 - 17));

    return 0;
}

int l2_send(struct sniff_ethernet *ether, char type)
{
    //tlv buf
    //pcap_sendpacket(pcap_t *p, const u_char *buf, int size);
    u_char buf[1500] = {0};
    unsigned char *p = buf;
    unsigned char *localMac = NULL;

    // dest mac
    MEMCPY_SAVE(p, ether->ether_shost, ETHER_ADDR_LEN);

    //src mac
    localMac = getInterMac("adhoc0");
    //localMac = getInterMac("eth1");   //不需要混杂模式
    MEMCPY_SAVE(p, localMac, ETHER_ADDR_LEN);
    //for (int i=0; i<6; i++)
    //printf("%02X",localMac[i]);

    // ether proto
    *p++ = 0x55;
    *p++ = 0xaa;

    if (g_iFlag)
    //默认
    {
        if (type & eConfig) {
            l2_send_type(buf, p, eConfig);
            usleep(15);
        }
        if (type & eVis) {
            l2_send_type(buf, p, eVis);
        }

        system("ip link show dev eth1 | grep 'UP mode' && ! pidof ethsend && /root/bin/ethsend eth1 &");
    }
    else
        //有线直连设置bssid
    {
        if (type & eWire) {
            l2_send_type(buf, p, eWire);
        }
    }

    return 0;
}

int main(int argc, char **argv)
{

    char *dev = "br-lan";			/* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */

    char filter_exp[] = "ether proto 0x55bb";		/* filter expression [3] */
    struct bpf_program fp;			/* compiled filter program (expression) */
    bpf_u_int32 mask;			/* subnet mask */
    bpf_u_int32 net;			/* ip */
    int num_packets = 0;			/* number of packets to capture */


    if (argc == 2) {
        /* find a capture device if not specified on command-line */
        dev = argv[1];
        if (!strcmp(argv[1], "eth1"))
        {
            g_iFlag = 0;
        }
    }

    /* print capture info */
    printf("Device: %s\n", dev);
    printf("Number of packets: %d\n", num_packets);
    printf("Filter expression: %s\n", filter_exp);

    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* now we can set our callback function */
    pcap_loop(handle, num_packets, l2_parse_packet, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}

