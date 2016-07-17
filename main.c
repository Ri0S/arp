#include <sys/time.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#define DEBUG_LEVEL_	3

#ifdef  DEBUG_LEVEL_
#define dp(n, fmt, args...)	if (DEBUG_LEVEL_ <= n) fprintf(stderr, "%s:%d,"fmt, __FILE__, __LINE__, ## args)
#define dp0(n, fmt)		if (DEBUG_LEVEL_ <= n) fprintf(stderr, "%s:%d,"fmt, __FILE__, __LINE__)
#define _dp(n, fmt, args...)	if (DEBUG_LEVEL_ <= n) fprintf(stderr, " "fmt, ## args)
#else	/* DEBUG_LEVEL_ */
#define dp(n, fmt, args...)
#define dp0(n, fmt)
#define _dp(n, fmt, args...)
#endif	/* DEBUG_LEVEL_ */
int callback(const u_char *packet, u_char *t_mac);
int getIPAddress(char *ip_addr,char *dev);
int getMacAddress(u_char *mac, char *dev);

int main(int argc, char **argv){
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;
    struct pcap_pkthdr hdr;
    struct in_addr net_addr, mask_addr;
    struct ether_header *eptr;
    const u_char *packet;
    u_char *cp;
    u_char sp_buf[1024];
    u_char t_ip[16], s_ip[16], t_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff}, s_mac[6];

    struct bpf_program fp;

    pcap_t *pcd;  // packet capture descriptor

    dev = pcap_lookupdev(errbuf); // 디바이스 이름
    if (dev == NULL)    {
        printf("%s\n", errbuf);
        exit(1);
    }

    pcd = pcap_open_live(dev, BUFSIZ,  1, 1000, errbuf);
    if (pcd == NULL){
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("Target IP Adress: ");
    scanf("%s", t_ip);
    getIPAddress(s_ip, dev);
    getMacAddress(s_mac, dev);
    printf("Source MAC Adress: %s\n", s_mac);
    for(int i=0; i<5; i++)
        printf("%02x:",s_mac[i]);
    printf("%02x\n",s_mac[5]);


    printf("Source IP Adress: %s\n", s_ip);

    cp = sp_buf;

    struct ether_header etheh;
    memcpy(etheh.ether_dhost, t_mac, 12);
    memcpy(etheh.ether_shost, s_mac, 12);
    etheh.ether_type = htons(ETHERTYPE_ARP);
    memcpy(cp, &etheh, sizeof(struct ether_header));
    cp += sizeof(struct ether_header);

    struct ether_arp arph;
    memcpy(arph.arp_sha, s_mac, 12);
    inet_aton(s_ip, &(arph.arp_spa));
    memcpy(arph.arp_tha, t_mac, 12);
    inet_aton(t_ip, &(arph.arp_tpa));
    arph.ea_hdr.ar_hln = 6;
    arph.ea_hdr.ar_hrd = htons(1);
    arph.ea_hdr.ar_pln = 4;
    arph.ea_hdr.ar_pro = htons(0x0800);
    arph.ea_hdr.ar_op = htons(1);
    memcpy(cp, &arph, sizeof(struct ether_arp)); //arp 패킷 세팅

    pcap_inject(pcd,sp_buf,sizeof(struct ether_header)+sizeof(struct ether_arp));


    // 패킷이 캡쳐되면 callback함수를 실행한다.
    while(1){

        packet = pcap_next(pcd, &hdr);
        if(callback(packet) == 1)
            break;
    }

}
int callback(const u_char *packet, u_char * t_mac){
    struct ether_header *etheh; // Ethernet 헤더 구조체
    unsigned short ether_type;
    int chcnt =0;
    int length=pkthdr->len;

    // 이더넷 헤더를 가져온다.
    etheh = (struct ether_header *)packet;
    packet += sizeof(struct ether_header);
    // 네트워크 패킷은 big redian 이라서 little redian형식으로 바꿔준다.
    ether_type = ntohs(etheh->ether_type);

    if (ether_type == ETHERTYPE_ARP){
        struct ether_arp *arph; // arp 헤더 구조체
        arph = (struct ether_arp *)packet;
        packet += sizeof(struct ether_arp);
        if(arph->ea_hdr.ar_op = 2){
            memcpy(t_mac, arph->arp_sha, 12);
            return 1;
        }
    }
    return 0;
}
int getIPAddress(char *ip_addr, char *dev){
    int sock;
    struct ifreq ifr;
    struct sockaddr_in *sin;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0){
        dp(4, "socket");
        return 0;
    }


    strcpy(ifr.ifr_name, dev);
    if (ioctl(sock, SIOCGIFADDR, &ifr)< 0){
        dp(4, "ioctl() - get ip");
        close(sock);
        return 0;
    }

    sin = (struct sockaddr_in*)&ifr.ifr_addr;
    strcpy(ip_addr, inet_ntoa(sin->sin_addr));

    close(sock);
    return 1;
}
int getMacAddress(u_char *mac, char *dev){
    int sock;
    struct ifreq ifr;
    char mac_adr[18] = {0,};

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0){
        dp(4, "socket");
        return 0;
    }

    strcpy(ifr.ifr_name, dev);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0){
        dp(4, "ioctl() - get mac");
        close(sock);
        return 0;
    }

    //convert format ex) 00:00:00:00:00:00
    for(int i=0; i<6; i++)
        mac[i] = ifr.ifr_hwaddr.sa_data[i];

    close(sock);
    return 1;
}
