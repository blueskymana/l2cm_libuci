

TARGET=ethsend

DIR_BUILD=../../../build_dir/target-mips_34kc_uClibc-0.9.33.2

DIR_PCAP=$(DIR_BUILD)/libpcap-1.5.3/
DIR_ROOT=$(DIR_BUILD)/root-ar71xx/

DIR_INC=$(DIR_BUILD)/uci-2015-04-09.1/
DIR_SRC:=l2_pcap.c l2_uci.c l2_log.c

$(TARGET):
	$(CC) $-o $(TARGET) $(DIR_SRC) -L$(DIR_ROOT)/lib -L$(DIR_ROOT)/usr/lib/ -I$(DIR_INC) -luci -lubox -lpcap -I$(DIR_PCAP)

clean:
	rm -rf *.o $(TARGET)

