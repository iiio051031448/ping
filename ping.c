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



enum {
    DEFDATALEN = 56,
    MAXIPLEN = 60,
    MAXICMPLEN = 76,
    MAX_DUP_CHK = (8 * 128),
    MAXWAIT = 10,
    PINGINTERVAL = 1, /* 1 second */
    pingsock = 0,
};

unsigned char rcvd_tbl[MAX_DUP_CHK / 8] = {0};
#define BYTE(bit)   rcvd_tbl[(bit)>>3]
#define MASK(bit)   (1 << ((bit) & 7))
#define SET(bit)    (BYTE(bit) |= MASK(bit))
#define CLR(bit)    (BYTE(bit) &= (~MASK(bit)))
#define TST(bit)    (BYTE(bit) & MASK(bit))
unsigned tmin, tmax; /* in us */
unsigned long long tsum; /* in us, sum of all times */
unsigned long ntransmitted, nreceived, nrepeats;
int myid = 0;

struct sockaddr_in dest_addr,recv_addr;

union {
    struct sockaddr sa;
    struct sockaddr_in sin;
} pingaddr;


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
    /*
     * Our algorithm is simple, using a 32 bit accumulator,
     * we add sequential 16 bit words to it, and at the end, fold
     * back all the carry bits from the top 16 bits into the lower
     * 16 bits.
     */
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


static void sendping_tail(int sock, char *snd_packet, int size_pkt, int datalen)
{
    int sz;

    CLR((uint16_t)ntransmitted % MAX_DUP_CHK);
    ntransmitted++;

    size_pkt += datalen;

    /* sizeof(pingaddr) can be larger than real sa size, but I think
     *   * it doesn't matter */
    //sz = xsendto(pingsock, G.snd_packet, size_pkt, &pingaddr.sa, sizeof(pingaddr));
    sz = sendto(sock, snd_packet, size_pkt, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (sz != size_pkt) {
        perror("sendto:");
        printf("sendto error\n");
        return;
    }

    return;
}

static void sendping4(int sock, char *snd_packet, int snd_len, int datalen)
{
    struct icmp *pkt = (struct icmp*)snd_packet;

    memset(pkt, 0xA5, snd_len);
    pkt->icmp_type = ICMP_ECHO;
    /* pkt->icmp_code = 0; */
    pkt->icmp_code = 0;
    pkt->icmp_cksum = 0; /* cksum is calculated with this field set to 0 */
    pkt->icmp_seq = htons(ntransmitted); /* don't ++ here, it can be a macro */
    pkt->icmp_id = myid;

    /* If datalen < 4, we store timestamp _past_ the packet,
     *   * but it's ok - we allocated 4 extra bytes in xzalloc() just in case.
     *       */
    /*if (datalen >= 4)*/
    /* No hton: we'll read it back on the same machine */
    //*(uint32_t*)&pkt->icmp_dun = monotonic_us();

    pkt->icmp_cksum = inet_cksum((uint16_t *) pkt, datalen + ICMP_MINLEN);

    sendping_tail(sock, snd_packet, ICMP_MINLEN, datalen);
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

static void unpack_tail(int sz, uint32_t *tp,
        const char *from_str,
                uint16_t recv_seq, int ttl)
{
    unsigned char *b, m;
    const char *dupmsg = " (DUP!)";
    unsigned triptime = triptime; /* for gcc */

    if (tp) {
        /* (int32_t) cast is for hypothetical 64-bit unsigned */
        /* (doesn't hurt 32-bit real-world anyway) */
        triptime = (int32_t) ((uint32_t)monotonic_us() - *tp);
        tsum += triptime;
        if (triptime < tmin)
            tmin = triptime;
        if (triptime > tmax)
            tmax = triptime;
    }

    b = &BYTE(recv_seq % MAX_DUP_CHK);
    m = MASK(recv_seq % MAX_DUP_CHK);
    /*if TST(recv_seq % MAX_DUP_CHK):*/
    if (*b & m) {
        ++nrepeats;
    } else {
        /*SET(recv_seq % MAX_DUP_CHK):*/
        *b |= m;
        ++nreceived;
        dupmsg += 7;
    }

    printf("%d bytes from %s: seq=%u ttl=%d", sz,
            from_str, recv_seq, ttl);
    if (tp)
        printf(" time=%u.%03u ms", triptime / 1000, triptime % 1000);
    puts(dupmsg);
    fflush(NULL);
    return;
}

static void unpack4(char *buf, int sz, struct sockaddr_in *from, int datalen)
{
    struct icmp *icmppkt;
    struct iphdr *iphdr;
    int hlen;

    /* discard if too short */
    if (sz < (datalen + ICMP_MINLEN))
        return;

    /* check IP header */
    iphdr = (struct iphdr *) buf;
    hlen = iphdr->ihl << 2;
    sz -= hlen;
    icmppkt = (struct icmp *) (buf + hlen);
    if (icmppkt->icmp_id != myid)
        return;             /* not our ping */

    if (icmppkt->icmp_type == ICMP_ECHOREPLY) {
        uint16_t recv_seq = ntohs(icmppkt->icmp_seq);
        uint32_t *tp = NULL;

        if (sz >= ICMP_MINLEN + sizeof(uint32_t))
            tp = (uint32_t *) icmppkt->icmp_data;
        unpack_tail(sz, tp, inet_ntoa(*(struct in_addr *) &from->sin_addr.s_addr), recv_seq, iphdr->ttl);
    } else if (icmppkt->icmp_type != ICMP_ECHO) {
        printf("warning: got ICMP %d (%s)\n", icmppkt->icmp_type, icmp_type_name(icmppkt->icmp_type));
    }
}

int main(void)
{
    int sock = -1;
    int recv_len = 0;
    int datalen = 16;
    char *recv_pkt = NULL;
    int pingcount = 0;

    myid = (uint16_t) getpid();

    memset(&dest_addr, 0, sizeof(dest_addr));                                          
    dest_addr.sin_family = AF_INET;                                                

    struct hostent *host;
    host=gethostbyname("qq.com");
    if (host ==NULL) {                                     
        printf("[NetStatus]  error : Can't get serverhost info!\n"); 
        return -1;                                                                 
    }                                                                              

    //memcpy((char*)host->h_addr,(char*)&dest_addr.sin_addr, host->h_length);        
    memcpy((char*)&dest_addr.sin_addr, (char*)host->h_addr, host->h_length);        

    printf("\tofficial: %s\n", host->h_name);

    char **pptr;
    char str[32];
    pptr = host->h_addr_list;
    for (; *pptr!=NULL; pptr++) {
        printf("\taddress: %s\n",
                inet_ntop(host->h_addrtype, host->h_addr, str, sizeof(str)));
    }



    //sock = socket(AF_INET, SOCK_RAW, 1); /* 1 == ICMP */
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); /* 1 == ICMP */
    if (sock < 0) {
        perror("sock");
        printf("socket failed.\n");
        return -1;
    }

    recv_len = datalen + MAXIPLEN + MAXICMPLEN;

    recv_pkt = malloc(recv_len);
    if (!recv_pkt) {
    }
    memset(recv_pkt, 0, recv_len);

    int snd_len = datalen + ICMP_MINLEN + 4;
    char *snd_packet = malloc(snd_len);
    if (!snd_packet) {
    }
    memset(snd_packet, 0, snd_len);


    setsockopt_broadcast(sock);

    int sockopt = 0;
    sockopt = (datalen * 2) + 7 * 1024; /* giving it a bit of extra room */
    setsockopt_SOL_SOCKET_int(sock, SO_RCVBUF, sockopt);

    sendping4(sock, snd_packet, snd_len, datalen);

    //while (1) {
    do {
        struct sockaddr_in from;
        socklen_t fromlen = (socklen_t) sizeof(from);
        int c;

        printf("recvfrom ..... \n");
        c = recvfrom(sock, recv_pkt, recv_len, 0, (struct sockaddr *) &from, &fromlen);
        if (c < 0) {
            if (errno != EINTR) {
                printf("recvfrom error\n");
            }
            goto _continue;
        }
        unpack4(recv_pkt, c, &from, datalen);
        #if 0
        if (pingcount && nreceived >= pingcount)
            break;
        #endif
_continue:
        //sleep(1);
    } while(0);

    return 0;
}

