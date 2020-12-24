 #include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <fcntl.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <pcap.h>
#include <time.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <string.h>
int num_packet = 0;
char *ip_ftoa(int flag)
{
  static int  f[] = {'R', 'D', 'M'}; 
  static char str[17];              
  u_int mask = 0x8000;             
  int i;                  

  for (i = 0; i < 3; i++) {
    if (((flag<< i) & mask) != 0)
      str[i] = f[i];
    else
      str[i] = '0';
  }
  str[i] = '\0';

  return str;
}
char *ip_ttoa(int flag)
{
  static int  f[] = {'1', '1', '1', 'D', 'T', 'R', 'C', 'X'};
  static char str[17];     
  u_int mask = 0x80;       
  int i;                   

  for (i = 0; i < 8; i++) {
    if (((flag<< i) & mask) != 0)
      str[i] = f[i];
    else
      str[i] = '0';
  }
  str[i] = '\0';

  return str;
}
char *tcp_ftoa(int flag)
{
  static int  f[] = {'U', 'A', 'P', 'R', 'S', 'F'};
  static char str[17];    
  u_int mask = 1 << 5;    
  int i;                  

  for (i = 0; i < 6; i++) {
    if (((flag << i) & mask) != 0)
      str[i] = f[i];
    else
      str[i] = '0';
  }
  str[i] = '\0';

  return str;
}
char *mac_ntoa(u_char *d)
{
  static char str[50];

  sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
          d[0], d[1], d[2], d[3], d[4], d[5]);

  return str;
}

void show_time(const struct pcap_pkthdr * header){
   struct tm *ltime;
   char timestr[16];
   time_t local_tv_sec;
   local_tv_sec = header->ts.tv_sec;
   ltime = localtime(&local_tv_sec);
   strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
   printf("Time: %d/%d/%d %s.%.6d\n",ltime->tm_year + 1900,ltime->tm_mon+1,ltime->tm_mday,timestr, header->ts.tv_usec);
}
void got_packet(int want_id, const struct pcap_pkthdr *header,
	    const u_char *packet){
    num_packet++;
    int packet_size = header->len;
    struct ether_header * eheader = packet;
    char *p = packet + sizeof(struct ether_header);
    int type = ntohs(eheader->ether_type);
    if(want_id > 0 && want_id != num_packet)
        return 0;
    printf("\n====================封包編號：%d========================\n",num_packet);
    show_time(header);
    printf("Ethernet Type: 0x%x ",type);
    switch (type)
    {
    case ETHERTYPE_ARP:
        printf("ARP");
        break;
    case ETHERTYPE_IP:
        printf("IPv4");
        break;
    case ETHERTYPE_IPV6:
        printf("IPv6");
        break;
    case ETHERTYPE_REVARP:
        printf("REVARP");
        break;
    default:
        printf("未知的type");
    }
    printf(" %d bytes\n",packet_size);
    printf("MAC: %s -> ",mac_ntoa(eheader->ether_shost));
    printf("%s\n",mac_ntoa(eheader->ether_dhost));
    if(type == ETHERTYPE_IP){
        struct ip *ip= (struct ip *) p;
        struct iphdr *ip_header = (struct iphdr *) p;
        p = p+((int)(ip->ip_hl) <<2);
        if(ip->ip_p == IPPROTO_TCP){
            struct tcphdr *tcp = (struct tcphdr*) p;
            printf("TCP %s:%u ->",
                inet_ntoa(*(struct in_addr *)&(ip->ip_src)),ntohs(tcp->th_sport));
            printf(" %s:%u\n",
                inet_ntoa(*(struct in_addr *)&(ip->ip_dst)),ntohs(tcp->th_dport));
        }
        else if(ip->ip_p == IPPROTO_UDP){
            struct udphdr *udp = (struct udphdr *) p;
            printf("UDP %s:%u -> ",
                    inet_ntoa(*(struct in_addr *)&(ip->ip_src)),ntohs(udp->uh_sport));
            printf(" %s:%u\n",
                    inet_ntoa(*(struct in_addr *)&(ip->ip_dst)),ntohs(udp->uh_dport));
        }
    }
}
int main(int argc, char *argv[])
{
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[200] = "";	/* The filter expression */
    char filter_tmp[200] = "";
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */
    char c;
    char *IP;
    char *TYPE;
    int PORT;
    char tmp= '\0';
    IP = tmp;
    TYPE = tmp;
    PORT = -1;
    char t[50];
    int len;
    while((c = getopt(argc, argv, "I:T:P:")) != -1){
        switch (c)
        {
        case 'I':
            IP = optarg;
            sprintf(filter_tmp,"host %s",IP);
            break;
        
        case 'P':
            PORT = atoi(optarg);
            if(strlen(filter_tmp) != 0)
                sprintf(t," and port %d",PORT);
            else
                sprintf(t,"port %d",PORT);
            len = strlen(filter_tmp) + strlen(t);
            strcat(filter_tmp,t);
            filter_tmp[len+1] = '\0';
            break;
        case 'T':
            TYPE = optarg;
            if(strlen(filter_tmp) != 0)
                sprintf(t," and %s",TYPE);
            else
                sprintf(t,"%s",TYPE);
            len = strlen(filter_tmp) + strlen(t);
            strcat(filter_tmp,t);
            filter_tmp[len+1] = '\0';
            break;
        case '?':
            printf("????\n");
        }
    }
    sprintf(filter_exp,"%s",filter_tmp);

    printf("Filter = %s\n",filter_exp);
    /* Open the session in promiscuous mode */
    char *pcap_filename = argv[optind];
    printf("檢查檔案%s中......\n",pcap_filename);
    if(access(pcap_filename,0)<0){
        printf("檔案 %s 不存在\n",pcap_filename);
        exit(0);
    }    
    handle = pcap_open_offline(pcap_filename, errbuf);
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Filter %s 錯誤: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    pcap_loop(handle,-1,got_packet,0);
    printf("檔案：%s讀取結束\n",pcap_filename);
    pcap_close(handle);
    printf("Filter = %s\n",filter_exp);
    while (1)
    {
        printf("輸入想再次查看的封包編號：");
        int want_id;
        scanf("%d",&want_id);
        handle = pcap_open_offline(pcap_filename, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            return(2);
        }
        /* Compile and apply the filter */
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }
        num_packet = 0;
        pcap_loop(handle,want_id,got_packet,want_id);    
        pcap_close(handle);
    }
   
   return(0);
}
