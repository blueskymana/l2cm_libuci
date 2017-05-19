

TARGET=l2cm_libuci

LIBS=-luci -lubox -lpcap
SRCS=l2_pcap.c l2_uci.c l2_log.c
OBJS=$(SRCS:.c=.o)
	

$(TARGET):$(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

l2_pcap.o:l2_pcap.c
	$(CC) $(CFLAGS) -c $< 

l2_uci.o:l2_uci.c
	$(CC) $(CFLAGS) -c $< 

l2_uci.o:l2_uci.c
	$(CC) $(CFLAGS) -c $< 

clean:
	rm -rf *.o $(TARGET)

