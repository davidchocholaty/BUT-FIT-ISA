/**********************************************************/
/*                                                        */
/* File: pcap.c                                           */
/* Created: 2022-10-26                                    */
/* Last change: 2022-10-26                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: Pcap handling for the Netflow exporter    */
/*                                                        */
/**********************************************************/

#include "pcap.h"

#include <pcap.h>
#include <netinet/ether.h>
#include <time.h>

// TODO maybe later delete
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#include "netflow_v5.h"

#define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol


/*
 * TODO
 */
void run_packets_processing (netflow_recording_system_t netflow_records,
                             char* input_stream)
{
    unsigned int packet_number;
    int return_code;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char* packet;
    struct pcap_pkthdr* header; // Has to be pointer because of pcap_next_ex
    pcap_t* handle;                 // file/device handler

    struct ether_header* eptr;
    //struct ip* my_ip;
    //const struct tcphdr* my_tcp;    // pointer to the beginning of TCP header
    //const struct udphdr* my_udp;    // pointer to the beginning of UDP header
    //u_int size_ip;

    if (input_stream == NULL)
    {
        // The name "-" is a synonym for stdin.
        input_stream = "-";
    }

    // Open the input file.
    if ((handle = pcap_open_offline(input_stream, errbuf)) == NULL)
    {
        // TODO handle error
    }

    packet_number = 0;
/*
    while ((return_code = pcap_next_ex(handle, &header, &packet)) > 0)
    {

        packet_number++;

        // print the packet header data (pcap)
        printf("Packet no. %d:\n",packet_number);
        printf("\tLength %d B, received at %s", header->len, ctime((const time_t*)&header->ts.tv_sec));

        // read the Ethernet header
        eptr = (struct ether_header *) packet;
        printf("\tSource MAC: %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_shost)) ;
        printf("\tDestination MAC: %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_dhost)) ;



        switch (ntohs(eptr->ether_type)){               // see /usr/include/net/ethernet.h for types
            case ETHERTYPE_IP: // IPv4 packet
                printf("\tEthernet type is 0x%04x, i.e., IP packet \n", ntohs(eptr->ether_type));
                struct ip* my_ip = (struct ip*) (packet+SIZE_ETHERNET);        // skip Ethernet header
                u_int size_ip = my_ip->ip_hl*4;                           // length of IP header

                printf("\tIP: id 0x%x, hlen %d bytes, version %d, total length %d bytes, TTL %d\n",ntohs(my_ip->ip_id),size_ip,my_ip->ip_v,ntohs(my_ip->ip_len),my_ip->ip_ttl);
                printf("\tIP src = %s, ",inet_ntoa(my_ip->ip_src));
                printf("IP dst = %s",inet_ntoa(my_ip->ip_dst));

                switch (my_ip->ip_p){
                    case IPPROTO_ICMP: // ICMP protocol (ICMPv4)
                        printf(", protocol ICMP (%d)\n",my_ip->ip_p);
                        break;
                    case IPPROTO_TCP: // TCP protocol
                        printf(", protocol TCP (%d)\n",my_ip->ip_p);
                        const struct tcphdr* my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the TCP header
                        printf("\tSrc port = %d, dst port = %d, seq = %u",ntohs(my_tcp->th_sport), ntohs(my_tcp->th_dport), ntohl(my_tcp->th_seq));
                        if (my_tcp->th_flags & TH_SYN)
                            printf(", SYN");
                        if (my_tcp->th_flags & TH_FIN)
                            printf(", FIN");
                        if (my_tcp->th_flags & TH_RST)
                            printf(", RST");
                        if (my_tcp->th_flags & TH_PUSH)
                            printf(", PUSH");
                        if (my_tcp->th_flags & TH_ACK)
                            printf(", ACK");
                        printf("\n");
                        break;
                    case IPPROTO_UDP: // UDP protocol
                        printf(", protocol UDP (%d)\n",my_ip->ip_p);
                        const struct udphdr* my_udp = (struct udphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the UDP header
                        printf("\tSrc port = %d, dst port = %d, length = %d\n",ntohs(my_udp->uh_sport), ntohs(my_udp->uh_dport), ntohs(my_udp->uh_ulen));
                        break;
                    default:
                        printf(", protocol %d\n",my_ip->ip_p);
                }
                break;
            default:
                printf("\tEthernet type 0x%04x, i.e., not IP packet\n", ntohs(eptr->ether_type));
        }
    }
*/



    while ((return_code = pcap_next_ex(handle, &header, &packet)) > 0)
    {

        packet_number++;

        // print the packet header data (pcap)
        //printf("Packet no. %d:\n",packet_number);
        //printf("\tLength %d B, received at %s", header->len, ctime((const time_t*)&header->ts.tv_sec));

        // read the Ethernet header
        eptr = (struct ether_header *) packet;
        //printf("\tSource MAC: %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_shost)) ;
        //printf("\tDestination MAC: %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_dhost)) ;



        switch (ntohs(eptr->ether_type)){               // see /usr/include/net/ethernet.h for types
            case ETHERTYPE_IP: // IPv4 packet
                // TODO handle return code
                process_packet(netflow_records, header, packet);
                break;
            default:
                break;
        }
    }

    if (return_code != PCAP_ERROR_BREAK)
    {
        // TODO handle error
    }

    //printf("End of file reached ...\n");

    // close the capture device and deallocate resources
    pcap_close(handle);
}
