#include <pcap.h>                   //pcap 라이브러리
#include <stdio.h>
#include <arpa/inet.h>              //IP 주소 변환 라이브러리
#include <netinet/in.h>             //인터넷 주소 구조체 정의
#include <netinet/ip.h>             //IP헤더 구조체 정의
#include <netinet/tcp.h>            //TCP 헤더 구조체 정의
#include <net/ethernet.h>           //이더넷 헤더 구조체 정의
#include <string.h>               
#include <ctype.h>                  // isprint() 사용 위한 라이브러리
#include <stdlib.h>                

#define MAX_PAYLOAD_PRINT 200        // payload를 최대 200바이트까지 출력하도록 정의

///////////////////////Ethernet Header 구조체 정의//////////////////////
struct ethheader {
    u_char  ether_dhost[6];          //목적지 MAC 주소
    u_char  ether_shost[6];          //출발지 MAC 주소
    u_short ether_type;              //IPv4인지 IPv6인지 확인 프로토콜 타입 
};


////////////////////////IP Header 구조체 정의////////////////////////////////
struct ipheader {
    u_char  ip_ihl:4,                //4비트 IP 헤더 길이
            ip_ver:4;                //(IPv4, IPv6)IP 버전 
    u_char  ip_tos;                  //QoS 관련
    u_short ip_len;                  //전체 패킷 길이
    u_short ip_id;                   //패킷 ID
    u_short ip_off;                  //fragmentation offset : IP패킷 커서 쪼개졌을 때 
																	    //원래 위치 알려줌
    u_char  ip_ttl;                  //TTL
    u_char  ip_p;                    //상위 프로토콜(TCP=6, UDP=17)
    u_short ip_sum;                  //체크섬- 오류 확인
    struct  in_addr ip_src, ip_dst;  //출발지, 목적지 IP 주소 
};


//////////////////////TCP Header 구조체 정의///////////////////////////
struct tcpheader {
    u_short th_sport;                //출발지 포트
    u_short th_dport;                //도착지 포트
    u_int   th_seq;                  //시퀀스 번호 : 데이터 순서대로 보내기 위해 바이트에 번호 매김
    u_int   th_ack;                  //ack 번호
    u_char  th_offx2;                //데이터 오프셋(TCP 헤더 길이) + 예약필드(확장가능성) 
																		//: 4bit씩
    u_char  th_flags;                //TCP 플래그(SYN, ACK FIN)
    u_short th_win;                  //윈도우 크기
    u_short th_sum;                  //체크섬
    u_short th_urp;                  //긴급 포인터 : 긴급한 데이터가 TCP 스트림에 있을 때
		                                 // 그 위치가 어디까진지 알려줌
};


///////////패킷 정보 출력 함수///////////
void print_packet_info(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader*)packet;                             //이더넷헤더 가져옴
    struct ipheader *ip = (struct ipheader*)(packet + sizeof(struct ethheader));   //IP 헤더 가져옴
    int ip_header_len = ip->ip_ihl * 4;                                            //IP 헤더 길이 계산
    struct tcpheader *tcp = (struct tcpheader*)(packet + sizeof(struct ethheader) + ip_header_len);    //TCP 헤더 가져옴
    int tcp_header_len = (tcp->th_offx2 >> 4) * 4;                                 //TCP 헤더 길이 계산

    //MAC주소 출력
    printf("Ethernet Header:\n");
    printf("  Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",               //수신지 MAC 주소
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], 
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("  Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",          //도착지 MAC 주소
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], 
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    //IP주소 출력
    printf("IP Header:\n");
    printf("  Source IP: %s\n", inet_ntoa(ip->ip_src));                  //수신지 IP주소 
    printf("  Destination IP: %s\n", inet_ntoa(ip->ip_dst));             //도착지 IP주소

    //TCP포트 출력
    printf("TCP Header:\n");
    printf("  Source Port: %d\n", ntohs(tcp->th_sport));                //수신지 TCP포트
    printf("  Destination Port: %d\n", ntohs(tcp->th_dport));           //도착지 TCP포트

    //HTTP메시지
    const char *payload = (const char *)(packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len);
    int payload_len = header->len - (sizeof(struct ethheader) + ip_header_len + tcp_header_len);

    if (payload_len > 0) {                        //payload 길이가 0보다 크면 MESSAGE 출력
        printf("\n----- HTTP MESSAGE -----\n");

        // HTTP GET/POST 확인
        if (strncmp(payload, "GET ", 4) == 0 || strncmp(payload, "POST ", 5) == 0 || strstr(payload, "HTTP/1.1") != NULL) {
            for (int i = 0; i < payload_len && i < MAX_PAYLOAD_PRINT; i++) {  // 최대 200바이트 출력
                if (isprint(payload[i]) || payload[i] == '\n' || payload[i] == '\r') {
                    printf("%c", payload[i]);
                }
            }
            printf("\n");
        } 
        else {
            printf("[Non-HTTP Data]\n");
        }
        printf("------------------------\n");
    }
}




int main() {
    char errbuf[PCAP_ERRBUF_SIZE];                             //error 메시지 저장 버퍼
    pcap_if_t *alldevs, *d;
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp and port 80";                     //HTTP 패킷 필터링
    bpf_u_int32 net, mask;
    char *dev = NULL;

    //사용 가능한 모든 장치 찾기
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    //유효 네트워크 장치 선택
    for (d = alldevs; d; d = d->next) {
        if (d->name && strncmp(d->name, "lo", 2) != 0) {        //루프백 제외
            dev = d->name;
            break;
        }
    }

	//네트워크 장치 없을 때
    if (dev == NULL) {
        fprintf(stderr, "No valid network device found\n");           
        pcap_freealldevs(alldevs);
        return 1;
    }

    //패킷 캡처 시작 
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // 필터 컴파일,
    //HTTP 트래픽만 캡쳐
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1 || pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    //10개 패킷 캡쳐, 출력
    pcap_loop(handle, 10, print_packet_info, NULL);

    // 자원 해제
    pcap_freecode(&fp);
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}
