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

typedef struct popt_tag {
    int sock;
    int recv_len;
    int datalen;
    char *recv_pkt;
    int snd_len;
    char *snd_packet;
    int myid;
    struct sockaddr_in dest_addr;
    unsigned long ntransmitted;
}popt;

static popt g_popt = {0};

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


static int sendping_tail(void)
{
    int sz;

    CLR((uint16_t)g_popt.ntransmitted % MAX_DUP_CHK);
    g_popt.ntransmitted++;

    int size_pkt = ICMP_MINLEN + g_popt.datalen;

    sz = sendto(g_popt.sock, g_popt.snd_packet, size_pkt, 0, (struct sockaddr *)&g_popt.dest_addr, sizeof(g_popt.dest_addr));
    if (sz != size_pkt) {
        perror("sendto:");
        printf("sendto error\n");
        return -1;
    }

    return 0;
}

static int sendping4(int sock)
{
    struct icmp *pkt = (struct icmp*)g_popt.snd_packet;

    memset(pkt, 0xA5, g_popt.snd_len);
    pkt->icmp_type = ICMP_ECHO;
    pkt->icmp_code = 0;
    pkt->icmp_cksum = 0; /* cksum is calculated with this field set to 0 */
    pkt->icmp_seq = htons(g_popt.ntransmitted); /* don't ++ here, it can be a macro */
    pkt->icmp_id = g_popt.myid;

    /* If g_popt.datalen < 4, we store timestamp _past_ the packet,
     *   * but it's ok - we allocated 4 extra bytes in xzalloc() just in case.
     *       */
    /*if (g_popt.datalen >= 4)*/
    /* No hton: we'll read it back on the same machine */
    *(uint32_t*)&pkt->icmp_dun = monotonic_us();

    pkt->icmp_cksum = inet_cksum((uint16_t *) pkt, g_popt.datalen + ICMP_MINLEN);

    return sendping_tail();
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

static int unpack4(char *buf, int sz, struct sockaddr_in *from)
{
    struct icmp *icmppkt;
    struct iphdr *iphdr;
    int hlen;

    /* discard if too short */
    if (sz < (g_popt.datalen + ICMP_MINLEN))
        return -1;

    /* check IP header */
    iphdr = (struct iphdr *) buf;
    hlen = iphdr->ihl << 2;
    sz -= hlen;
    icmppkt = (struct icmp *) (buf + hlen);
    if (icmppkt->icmp_id != g_popt.myid)
        return -1;             /* not our ping */

    if (icmppkt->icmp_type == ICMP_ECHOREPLY) {
        uint16_t recv_seq = ntohs(icmppkt->icmp_seq);
        uint32_t *tp = NULL;

        if (sz >= ICMP_MINLEN + sizeof(uint32_t))
            tp = (uint32_t *) icmppkt->icmp_data;
        printf("GOT ICMP_ECHOREPLY\n");
    } else if (icmppkt->icmp_type != ICMP_ECHO) {
        printf("warning: got ICMP %d (%s)\n", icmppkt->icmp_type, icmp_type_name(icmppkt->icmp_type));
        return -1;
    }

    return 0;
}

static int popt_release(void)
{
    if (g_popt.sock >= 0) {
        close(g_popt.sock);
        g_popt.sock = -1;
    }

    if (g_popt.recv_pkt) {
        free(g_popt.recv_pkt);
        g_popt.recv_pkt = NULL;
    }

    if (g_popt.snd_packet) {
        free(g_popt.snd_packet);
        g_popt.snd_packet = NULL;
    }

    return 0;
}

static int set_host(const char *name)
{
    memset(&g_popt.dest_addr, 0, sizeof(g_popt.dest_addr));                                          
    g_popt.dest_addr.sin_family = AF_INET;                                                

    struct hostent *host;
    host = gethostbyname(name);
    if (host ==NULL) {                                     
        printf("[NetStatus]  error : Can't get serverhost info!\n"); 
        return -1;                                                                 
    }                                                                              

    memcpy((char*)&g_popt.dest_addr.sin_addr, (char*)host->h_addr, host->h_length);        

    printf("\tofficial: %s\n", host->h_name);

    char **pptr;
    char str[32];
    pptr = host->h_addr_list;
    for (; *pptr!=NULL; pptr++) {
        printf("\taddress: %s\n", inet_ntop(host->h_addrtype, host->h_addr, str, sizeof(str)));
    }

    return 0;
}

int popt_init(const char *name, int datalen)
{
    g_popt.myid = (uint16_t) getpid();
    g_popt.datalen = datalen;

    if (set_host(name)) {
        printf("get host failed of %s\n", name);
        return -1;
    }

    g_popt.sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); /* 1 == ICMP */
    if (g_popt.sock < 0) {
        printf("socket failed.\n");
        return -1;
    }

    g_popt.recv_len = g_popt.datalen + MAXIPLEN + MAXICMPLEN;
    g_popt.recv_pkt = malloc(g_popt.recv_len);
    if (!g_popt.recv_pkt) {
        printf("oom.");
        return -1;
    }
    memset(g_popt.recv_pkt, 0, g_popt.recv_len);

    g_popt.snd_len = g_popt.datalen + ICMP_MINLEN + 4;
    g_popt.snd_packet = malloc(g_popt.snd_len);
    if (!g_popt.snd_packet) {
        printf("oom.");
        return -1;
    }
    memset(g_popt.snd_packet, 0, g_popt.snd_len);

    setsockopt_broadcast(g_popt.sock);

    int sockopt = 0;
    sockopt = (g_popt.datalen * 2) + 7 * 1024; /* giving it a bit of extra room */
    setsockopt_SOL_SOCKET_int(g_popt.sock, SO_RCVBUF, sockopt);

    return 0;
}

int recv_packet(void)
{           
    int n = 0;
    int ret = -1;
    int sret = 0;
    struct timeval tv;
    fd_set rfds;
    struct sockaddr_in from;
    socklen_t fromlen = (socklen_t) sizeof(from);

    FD_ZERO(&rfds);
    FD_SET(g_popt.sock, &rfds);

    tv.tv_sec = 1;
    tv.tv_usec = 0;
    while(1) {
        sret = select(g_popt.sock + 1, &rfds, NULL, NULL, &tv);
        if (sret == 0) {
            printf("time out\n");
            return -1;
        } else if (sret < 0) {
            printf("select error\n");
            return -1;
        }
        if (FD_ISSET(g_popt.sock,&rfds)) {  
            n = recvfrom(g_popt.sock, g_popt.recv_pkt, g_popt.recv_len, 0, (struct sockaddr *) &from, &fromlen);
            if(n <0) {   
                if(errno==EINTR)
                    return -1;
                perror("recvfrom error");
                return -2;
            }

            ret = unpack4(g_popt.recv_pkt, n, &from);
        }

        if(ret == -1) {
            continue;
        }
        return ret;
    }
}


int try_ping(const char *name, int datalen)
{   
    if (popt_init(name, datalen)) {
        printf("popt init failed.\n");
        goto error;
    }

    if (sendping4(g_popt.sock)) {
        printf("send ping failed.\n");
        goto error;
    }

    if (recv_packet()) {
        printf("recv ping ack failed.\n");
        goto error;
    }

    popt_release();

    return 0;

error:
    popt_release();
    return -1;
}

int main(void)
{
    int i = 100;
    while(i--) {
        printf("==== %d ====\n", i);
        if (try_ping("127.0.0.1", 16)) {
            break;
        }
    }
}
