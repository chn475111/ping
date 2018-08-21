/**
 * @author lijk@infosec.com.cn
 * @version 0.0.1
 * @date 2018-8-21 16:15:16
**/
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

#define MAX_PACKET_SIZE 64

/*
 * in_cksum --
 *      Checksum routine for Internet Protocol family headers (C Version)
 */
static unsigned short in_cksum(unsigned short *addr, int len, unsigned short csum)
{
    unsigned short answer = 0;
    register int sum = csum;
    register int nleft = len;
    register unsigned short *w = addr;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w ;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);                     /* add carry */
    answer = ~sum;                          /* truncate to 16 bits */
    return (answer);
}

static int ipv4_icmp_request(int fd, char *ip)
{
    static unsigned short count = 0;

    struct sockaddr_in addr;
    socklen_t len = sizeof(struct sockaddr_in);
    memset(&addr, 0, sizeof(struct sockaddr_in));

    int i = 0;
    int ret = 0;
    unsigned char packet[MAX_PACKET_SIZE] = {0};
    struct icmp *icmp_hdr = (struct icmp*)packet;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);

    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_id = (unsigned short)getpid();
    icmp_hdr->icmp_seq = count++;

    gettimeofday((struct timeval*)&packet[8], NULL);
    for(i = 0; i < MAX_PACKET_SIZE-16; i++)
        packet[i+16] = (unsigned char)i;

    icmp_hdr->icmp_cksum = in_cksum((unsigned short*)packet, MAX_PACKET_SIZE, 0);
    ret = sendto(fd, (void*)packet, MAX_PACKET_SIZE, 0, (struct sockaddr*)&addr, len);
    if(ret < 0)
    {
        fprintf(stderr, "%s %s:%u - udp send icmp to \"%s\" failed - %d: %s\n", __FUNCTION__, __FILE__, __LINE__, ip, errno, strerror(errno));
        return -1;
    }

    fprintf(stdout, "%s %s:%u - udp send icmp to \"%s\" succeed\n", __FUNCTION__, __FILE__, __LINE__, ip);
    return 0;
}

static int ipv4_icmp_response(int fd, char *ip, int iplen)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(struct sockaddr_in);
    memset(&addr, 0, sizeof(struct sockaddr_in));

    int length = 0;
    unsigned char buffer[2*MAX_PACKET_SIZE] = {0};
    length = recvfrom(fd, (void*)buffer, 2*MAX_PACKET_SIZE, 0, (struct sockaddr*)&addr, &len);
    if(ip != NULL && iplen > 0) snprintf(ip, iplen, "%s", inet_ntoa(addr.sin_addr)); 
    if(length <= 0)
    {
        fprintf(stderr, "%s %s:%u - udp recv icmp from \"%s\" failed - %d: %s\n", __FUNCTION__, __FILE__, __LINE__, ip, errno, strerror(errno));
        return -1;
    }
    struct iphdr *ip_hdr = (struct iphdr*)buffer;
    unsigned char ip_hdrlen = ip_hdr->ihl*4;

    int icmp_len = length - ip_hdrlen;
    struct icmp *icmp_hdr = (struct icmp*)(buffer + ip_hdrlen);
    unsigned short cksum = icmp_hdr->icmp_cksum;

    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_cksum = in_cksum((unsigned short*)icmp_hdr, icmp_len, 0);
    if(cksum != icmp_hdr->icmp_cksum)
    {
        fprintf(stderr, "%s %s:%u - ipv4 icmp cksum \"0x%hx vs 0x%hx\" mismatch - %d: %s\n", __FUNCTION__, __FILE__, __LINE__, cksum, icmp_hdr->icmp_cksum, errno, strerror(errno));
        return -1;
    }

    fprintf(stdout, "%s %s:%u - udp recv icmp from \"%s\" succeed\n", __FUNCTION__, __FILE__, __LINE__, ip);
    return 0;
}

static int ipv4_icmp(char *ip)
{
    int i = 0;
    int fd = 0;
    int ret = 0;
    int num = 0;
    char ipaddr[32] = {0};

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(fd < 0)
    {
        fprintf(stderr, "%s %s:%u - ipv4 socket failed - %d: %s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
        return -1;
    }

    ret = ipv4_icmp_request(fd, ip);
    if(ret < 0)
    {
        fprintf(stderr, "%s %s:%u - ipv4 icmp request failed - %d: %s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
        goto ErrP;
    }

    int timeout = 1000;
    unsigned int nfds = 3;
    struct pollfd fds[3];
    fds[0].fd = fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    fds[1].fd = 0;
    fds[1].events = POLLIN;
    fds[1].revents = 0;

    fds[2].fd = 1;
    fds[2].events = POLLOUT;
    fds[2].revents = 0;

    num = poll(fds, nfds, timeout);
    if(num <= 0)
    {
        fprintf(stderr, "%s %s:%u - ipv4 poll failed - %d: %s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
        goto ErrP;
    }

    for(i = 0; i < nfds; i++)
    {
        if(fds[i].revents & POLLIN)
        {
            ret = ipv4_icmp_response(fd, ipaddr, 32);
            if(ret < 0)
            {
                fprintf(stderr, "%s %s:%u - ipv4 icmp response failed - %d: %s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
                goto ErrP;
            }
        }
        else if(fds[i].revents & POLLIN)
        {
            fprintf(stdout, "%s %s:%u - stdin readable: %d\n", __FUNCTION__, __FILE__, __LINE__, fds[i].fd);
        }
        else if(fds[i].revents & POLLOUT)
        {
            fprintf(stdout, "%s %s:%u - stdout writable: %d\n", __FUNCTION__, __FILE__, __LINE__, fds[i].fd);
        }
    }

    if(fd > 0) close(fd);
    return 0;
ErrP:
    if(fd > 0) close(fd);
    return -1;
}

int main(int argc, char *argv[])
{
    return ipv4_icmp(argv[1] ? argv[1] : "127.0.0.1");
}
