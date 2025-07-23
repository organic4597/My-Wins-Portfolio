#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

typedef unsigned char u_char;

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    static int index = 0;
    printf("packet #%d\n", ++index );
    printf("Timestamp: %s", ctime((const time_t*)&pkthdr->ts.tv_sec));
    printf("Packet Length: %d bytes\n",pkthdr->len);

}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const char *filepath = "./pcap_log/test.pcap";
    
    handle = pcap_open_offline(filepath, errbuf);
    if (handle == NULL)
    {
        printf("pcap_open_offline() failed: %s\n", errbuf);
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);

}