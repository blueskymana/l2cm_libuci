
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "l2_pcap.h"

static pcap_t *handle;				/* packet capture handle */

/*
*  * print data in rows of 16 bytes: offset   hex   ascii
*   *
*    * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
*     */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
        printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
    printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");

        }

    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
        printf("%c", *ch);
        else
        printf(".");
        ch++;

    }

    printf("\n");

    return;
}

/*
*  * print packet payload data (avoid printing binary data)
*   */
void print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16;/* number of bytes per line */
    int line_len;
    int offset = 0;/* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
    return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }

    }

    return;
}

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
    return ifr.ifr_hwaddr.sa_data;
}

void l2_parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct sniff_ethernet *ethernet = NULL;
    unsigned char *payload = NULL;

    ethernet = (struct sniff_ethernet*)(packet);

    payload = packet + SIZE_ETHERNET;
    printf("payload:#%s#\n", payload);



    return;
}

int read_cmd(char *out)
{
    int iRet = 0;
    FILE *file = NULL;
    file = popen("ls", "r");
    if (file)
    {
        fread(out, 1, 5000, file);
        printf("%s\n", out);
        iRet = strlen(out);
        pclose(file);
    }

    return iRet;
}
int test()
{
    FILE *file = NULL;
    char buf[1000];
    static int aa = 0;

    while (1)
    {
        aa++;
        //sleep(1);
        read_cmd(buf);
        printf("##%d", aa);
    }

}

int main(int argc, char **argv)
{

    test();
    return 0;
}

