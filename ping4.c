#define _GNU_SOURCE     
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <netdb.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h> /* netinet/in.h needs it */
#include <netinet/in.h>
#include <net/if.h>
#include <sys/un.h>
#include <netinet/ip_icmp.h>
#include <sys/syscall.h>
#include <arpa/inet.h>

#define P_LOG(fmt, ...) \
    printf("[%s][%d]"fmt"\n", __func__, __LINE__, ##__VA_ARGS__)

enum {
    DEF_DATALEN = 56,
    MAXIPLEN = 60,
    MAXICMPLEN = 76,
    MAX_DUP_CHK = (8 * 128),
    MAXWAIT = 10,
    PINGINTERVAL = 1, /* 1 second */
    pingsock = 0,
};

static unsigned char rcvd_tbl[MAX_DUP_CHK / 8] = {0};
#define BYTE(bit)   rcvd_tbl[(bit)>>3]
#define MASK(bit)   (1 << ((bit) & 7))
#define SET(bit)    (BYTE(bit) |= MASK(bit))
#define CLR(bit)    (BYTE(bit) &= (~MASK(bit)))
#define TST(bit)    (BYTE(bit) & MASK(bit))

typedef struct pingopt_tag {
    int sock;
    int recv_len;
    int datalen;
    char *recv_pkt;
    int snd_len;
    char *snd_packet;
    int myid;
    struct sockaddr_in dest_addr;
    unsigned long ntransmitted;
}pingopt_t;

int setsockopt_int(int fd, int level, int optname, int optval)
{
    return setsockopt(fd, level, optname, &optval, sizeof(int));
}

int setsockopt_SOL_SOCKET_int(int fd, int optname, int optval)
{
    return setsockopt_int(fd, SOL_SOCKET, optname, optval);
}

int setsockopt_SOL_SOCKET_1(int fd, int optname)
{
    return setsockopt_SOL_SOCKET_int(fd, optname, 1);
}

int setsockopt_broadcast(int fd)
{
    return setsockopt_SOL_SOCKET_1(fd, SO_BROADCAST);
}


static void get_mono(struct timespec *ts)
{
    if (syscall(__NR_clock_gettime, CLOCK_MONOTONIC, ts))
        printf("clock_gettime(MONOTONIC) failed\n");
}

unsigned long long monotonic_ns(void)
{
    struct timespec ts;
    get_mono(&ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

unsigned long long monotonic_us(void)
{
    struct timespec ts;
    get_mono(&ts);
    return ts.tv_sec * 1000000ULL + ts.tv_nsec/1000;
}

#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
# define BB_BIG_ENDIAN 1
# define BB_LITTLE_ENDIAN 0
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
# define BB_BIG_ENDIAN 0
# define BB_LITTLE_ENDIAN 1
#elif defined(_BYTE_ORDER) && _BYTE_ORDER == _BIG_ENDIAN
# define BB_BIG_ENDIAN 1
# define BB_LITTLE_ENDIAN 0
#elif defined(_BYTE_ORDER) && _BYTE_ORDER == _LITTLE_ENDIAN
# define BB_BIG_ENDIAN 0
# define BB_LITTLE_ENDIAN 1
#elif defined(BYTE_ORDER) && BYTE_ORDER == BIG_ENDIAN
# define BB_BIG_ENDIAN 1
# define BB_LITTLE_ENDIAN 0
#elif defined(BYTE_ORDER) && BYTE_ORDER == LITTLE_ENDIAN
# define BB_BIG_ENDIAN 0
# define BB_LITTLE_ENDIAN 1
#elif defined(__386__)
# define BB_BIG_ENDIAN 0
# define BB_LITTLE_ENDIAN 1
#else
# error "Can't determine endianness"
#endif

uint16_t inet_cksum(uint16_t *addr, int nleft)
{
    unsigned sum = 0;
    while (nleft > 1) {
        sum += *addr++;
        nleft -= 2;
    }

    /* Mop up an odd byte, if necessary */
    if (nleft == 1) {
        if (BB_LITTLE_ENDIAN)
            sum += *(uint8_t*)addr;
        else
            sum += *(uint8_t*)addr << 8;
    }

    /* Add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);                     /* add carry */

    return (uint16_t)~sum;
}


static int send_ping_tail(pingopt_t *pingopt)
{
    int sz;

    CLR((uint16_t)pingopt->ntransmitted % MAX_DUP_CHK);
    pingopt->ntransmitted++;

    int size_pkt = ICMP_MINLEN + pingopt->datalen;

    sz = sendto(pingopt->sock, pingopt->snd_packet, size_pkt, 0, (struct sockaddr *)&pingopt->dest_addr, sizeof(pingopt->dest_addr));
    if (sz != size_pkt) {
        perror("sendto:");
        printf("sendto error\n");
        return -1;
    }

    return 0;
}

static int send_ping4(pingopt_t *pingopt)
{
    struct icmp *pkt = (struct icmp*)pingopt->snd_packet;

    memset(pkt, 0xA5, pingopt->snd_len);
    pkt->icmp_type = ICMP_ECHO;
    pkt->icmp_code = 0;
    pkt->icmp_cksum = 0; /* cksum is calculated with this field set to 0 */
    pkt->icmp_seq = htons(pingopt->ntransmitted); /* don't ++ here, it can be a macro */
    pkt->icmp_id = pingopt->myid;

    /* If pingopt->datalen < 4, we store timestamp _past_ the packet,
     *   * but it's ok - we allocated 4 extra bytes in xzalloc() just in case.
     *       */
    /*if (pingopt->datalen >= 4)*/
    /* No hton: we'll read it back on the same machine */
    *(uint64_t*)&pkt->icmp_dun = monotonic_us();

    pkt->icmp_cksum = inet_cksum((uint16_t *) pkt, pingopt->datalen + ICMP_MINLEN);

    return send_ping_tail(pingopt);
}

static const char *icmp_type_name(int id)
{
    switch (id) {
        case ICMP_ECHOREPLY:      return "Echo Reply";
        case ICMP_DEST_UNREACH:   return "Destination Unreachable";
        case ICMP_SOURCE_QUENCH:  return "Source Quench";
        case ICMP_REDIRECT:       return "Redirect (change route)";
        case ICMP_ECHO:           return "Echo Request";
        case ICMP_TIME_EXCEEDED:  return "Time Exceeded";
        case ICMP_PARAMETERPROB:  return "Parameter Problem";
        case ICMP_TIMESTAMP:      return "Timestamp Request";
        case ICMP_TIMESTAMPREPLY: return "Timestamp Reply";
        case ICMP_INFO_REQUEST:   return "Information Request";
        case ICMP_INFO_REPLY:     return "Information Reply";
        case ICMP_ADDRESS:        return "Address Mask Request";
        case ICMP_ADDRESSREPLY:   return "Address Mask Reply";
        default:                  return "unknown ICMP type";
    }
}

static int do_unpack4(pingopt_t *pingopt, int sz, struct sockaddr_in *from)
{
    struct icmp *icmppkt;
    struct iphdr *iphdr;
    int hlen;

    /* discard if too short */
    if (sz < (pingopt->datalen + ICMP_MINLEN)) {
        printf("error too short\n");
        return -1;
    }

    /* check IP header */
    iphdr = (struct iphdr *) pingopt->recv_pkt;
    hlen = iphdr->ihl << 2;
    sz -= hlen;
    icmppkt = (struct icmp *) (pingopt->recv_pkt + hlen);
    if (icmppkt->icmp_id != pingopt->myid) {
        printf("not our ping\n");
        return -1;             /* not our ping */
    }

    P_LOG("icmp_type:%d (%s)\n", icmppkt->icmp_type, icmp_type_name(icmppkt->icmp_type));
    if (icmppkt->icmp_type == ICMP_ECHOREPLY) {
        uint16_t recv_seq = ntohs(icmppkt->icmp_seq);
        uint32_t *tp = NULL;

        if (sz >= ICMP_MINLEN + sizeof(uint32_t))
            tp = (uint32_t *) icmppkt->icmp_data;

        uint64_t now_us = monotonic_us();
        uint64_t req_us = *(uint64_t*)&icmppkt->icmp_dun;
        printf("GOT ICMP_ECHOREPLY, req_us:%lld, now_us:%lld, time:%lld us\n", req_us, now_us, now_us - req_us);
    } else if (icmppkt->icmp_type != ICMP_ECHO) {
        printf("warning: got ICMP %d (%s)\n", icmppkt->icmp_type, icmp_type_name(icmppkt->icmp_type));
        return -1;
    }

    return 0;
}

static int pingopt_release(pingopt_t *pingopt)
{
    if (pingopt->sock >= 0) {
        close(pingopt->sock);
        pingopt->sock = -1;
    }

    if (pingopt->recv_pkt) {
        free(pingopt->recv_pkt);
        pingopt->recv_pkt = NULL;
    }

    if (pingopt->snd_packet) {
        free(pingopt->snd_packet);
        pingopt->snd_packet = NULL;
    }

    return 0;
}

static int set_host(pingopt_t *pingopt, const char *name)
{
    memset(&pingopt->dest_addr, 0, sizeof(pingopt->dest_addr));                                          
    pingopt->dest_addr.sin_family = AF_INET;                                                

    struct hostent *host;
    host = gethostbyname(name);
    if (host ==NULL) {                                     
        printf("[NetStatus]  error : Can't get serverhost info!\n"); 
        return -1;                                                                 
    }                                                                              

    memcpy((char*)&pingopt->dest_addr.sin_addr, (char*)host->h_addr, host->h_length);        

    printf("\tofficial: %s\n", host->h_name);

    char **pptr;
    char str[32];
    pptr = host->h_addr_list;
    for (; *pptr!=NULL; pptr++) {
        printf("\taddress: %s\n", inet_ntop(host->h_addrtype, host->h_addr, str, sizeof(str)));
    }

    return 0;
}

int pingopt_init(const char *name, int datalen, pingopt_t *pingopt)
{
    pingopt->myid = (uint16_t) getpid();
    pingopt->datalen = datalen;

    if (set_host(pingopt, name)) {
        printf("get host failed of %s\n", name);
        return -1;
    }

    pingopt->sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); /* 1 == ICMP */
    if (pingopt->sock < 0) {
        printf("socket failed.\n");
        return -1;
    }

    pingopt->recv_len = pingopt->datalen + MAXIPLEN + MAXICMPLEN;
    pingopt->recv_pkt = malloc(pingopt->recv_len);
    if (!pingopt->recv_pkt) {
        printf("oom.");
        return -1;
    }
    memset(pingopt->recv_pkt, 0, pingopt->recv_len);

    pingopt->snd_len = pingopt->datalen + ICMP_MINLEN + 4;
    pingopt->snd_packet = malloc(pingopt->snd_len);
    if (!pingopt->snd_packet) {
        printf("oom.");
        return -1;
    }
    memset(pingopt->snd_packet, 0, pingopt->snd_len);

    setsockopt_broadcast(pingopt->sock);

    int sockopt = 0;
    sockopt = (pingopt->datalen * 2) + 7 * 1024; /* giving it a bit of extra room */
    setsockopt_SOL_SOCKET_int(pingopt->sock, SO_RCVBUF, sockopt);

    return 0;
}

int recv_packet(pingopt_t *pingopt)
{           
    int n = 0;
    int ret = -1;
    int sret = 0;
    struct timeval tv;
    fd_set rfds;
    struct sockaddr_in from;
    socklen_t fromlen = (socklen_t) sizeof(from);

    FD_ZERO(&rfds);
    FD_SET(pingopt->sock, &rfds);

    tv.tv_sec = 1;
    tv.tv_usec = 0;
    while(1) {
        sret = select(pingopt->sock + 1, &rfds, NULL, NULL, &tv);
        if (sret == 0) {
            printf("time out\n");
            return -1;
        } else if (sret < 0) {
            printf("select error\n");
            return -1;
        }
        if (FD_ISSET(pingopt->sock,&rfds)) {  
            n = recvfrom(pingopt->sock, pingopt->recv_pkt, pingopt->recv_len, 0, (struct sockaddr *) &from, &fromlen);
            if(n <0) {   
                if(errno==EINTR)
                    return -1;
                perror("recvfrom error");
                return -2;
            }

            ret = do_unpack4(pingopt, n, &from);
        }

        if(ret == -1) {
            continue;
        }
        return ret;
    }
}


int try_ping(const char *name, int datalen)
{   
    pingopt_t pingopt = {0};

    if (pingopt_init(name, datalen, &pingopt)) {
        printf("pingopt init failed.\n");
        goto error;
    }

    if (send_ping4(&pingopt)) {
        printf("send ping failed.\n");
        goto error;
    }

    if (recv_packet(&pingopt)) {
        printf("recv ping ack failed.\n");
        goto error;
    }

    pingopt_release(&pingopt);

    return 0;

error:
    pingopt_release(&pingopt);
    return -1;
}

int main(void)
{
    int i = 1;
    struct icmp *pkt;
    printf("==== %ld ====\n", sizeof(pkt->icmp_dun));
    while(i--) {
        printf("==== %d ====\n", i);
        if (try_ping("172.31.0.1", 16)) {
            break;
        }
    }
}
