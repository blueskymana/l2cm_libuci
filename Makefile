

TARGET=l2cm_libuci

DIR_BUILD=../../../build_dir/target-mips_34kc_uClibc-0.9.33.2

DIR_PCAP=$(DIR_BUILD)/libpcap-1.5.3/
DIR_ROOT=$(DIR_BUILD)/root-ar71xx/

DIR_INC=$(DIR_BUILD)/uci-2015-04-09.1/
DIR_SRC:=l2_pcap.c l2_uci.c l2_log.c


$(TARGET): l2_pcap.o l2_uci.o l2_log.o
	$(CC) $(LDFLAGS) -L$(DIR_ROOT)/lib -L$(DIR_ROOT)/usr/lib/ -luci -lubox -lpcap

l2_pcap.o:l2_pcap.c
	$(CC) $(CFLAGS) -I$(DIR_INC) -I$(DIR_PCAP) -c l2_pcap.c

l2_pcap.o:l2_uci.c
	$(CC) $(CFLAGS) -I$(DIR_INC) -I$(DIR_PCAP) -c l2_uci.c

l2_pcap.o:l2_log.c
	$(CC) $(CFLAGS) -I$(DIR_INC) -I$(DIR_PCAP) -c l2_log.c

clean:
	rm -rf *.o $(TARGET)

