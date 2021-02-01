/*
 * Copyright (C) 2021 Vincent Sallaberry
 * vftp-proxy <https://github.com/vsallaberry/vftp-proxy>
 * Copyright (c) 2004, 2005 Camiel Dobbelaar, <cd@sentia.nl>
 *  see bsd copyright notive below.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * -------------------------------------------------------------------------
 * vftp-proxy pf filter interface, forked for support on osx 10.11
 */
/*
 * vftp-proxy is forked from FreeBSD ftp-proxy,
 * https://github.com/freebsd/freebsd
 *   contrib/pf/ftp-proxy (eb6f5408ecc27df916af9f862c55e90defe742c3)
 *  See FreeBSD ftp-proxy copyright notice below */
/*	$OpenBSD: filter.c,v 1.8 2008/06/13 07:25:26 claudio Exp $ */
/*
 * Copyright (c) 2004, 2005 Camiel Dobbelaar, <cd@sentia.nl>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#define VFTPPROXY_USE_PF_DEVICE 1
#define VFTPPROXY_IOCTL_FORK 1

#include <net/if.h>
#ifdef VFTPPROXY_USE_PF_DEVICE
# define PRIVATE 1
# include <net/pfvar.h>
# undef PRIVATE
#endif
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#ifdef VFTPPROXY_IOCTL_FORK
#include <sys/select.h>
#include <signal.h>
#include <stdlib.h>
#endif

#include <syslog.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "filter.h"

/* From netinet/in.h, but only _KERNEL_ gets them. */
#define satosin(sa)	((struct sockaddr_in *)(sa))
#define satosin6(sa)	((struct sockaddr_in6 *)(sa))

enum { TRANS_FILTER = 0, TRANS_NAT, TRANS_RDR, TRANS_SIZE };

int prepare_rule(u_int32_t, int, struct sockaddr *, struct sockaddr *,
    u_int16_t);
int server_lookup4(struct sockaddr_in *, struct sockaddr_in *,
    struct sockaddr_in *);
int server_lookup6(struct sockaddr_in6 *, struct sockaddr_in6 *,
    struct sockaddr_in6 *);

static struct pfioc_pooladdr	pfp;
static struct pfioc_rule	pfr;
static struct {
    struct pfioc_trans	pft;
    struct pfioc_trans_e pfte[TRANS_SIZE];
} pft_all;
static struct pfioc_trans * pft = &pft_all.pft;
static struct pfioc_trans_e	* pfte = pft_all.pfte;
static int dev, rule_log;
static const char *qname, *tagname;

extern void logmsg(int pri, const char *message, ...);

#ifdef VFTPPROXY_IOCTL_FORK
#define CHROOT_DIR "/var/empty"
int ioctl_pipeout = -1;
int ioctl_pipein = -1;
static int ioctl_real(int fd, unsigned long cmd, void * data) {
    return ioctl(fd, cmd, data);
}
#define ioctl(fd, cmd, data) ioctl_proxy(fd, cmd, data, sizeof(*data))
int ioctl_proxy(int fd, unsigned long cmd, void * data, size_t datasz) {
    (void) fd;
    int ret;
    ssize_t nread;
    if ((nread = write(ioctl_pipeout, &cmd, sizeof(cmd))) != sizeof(cmd)) {
        if (nread >= 0) errno = EINVAL;
        return -1;
    }
    if ((nread = write(ioctl_pipeout, data, datasz)) != (ssize_t)datasz) {
        if (nread >= 0) errno = EINVAL;
        return -1;
    }
    nread = read(ioctl_pipein, &ret, sizeof(int));
    if (nread != sizeof(int) || ret != 0) {
        if (nread >= 0) errno = EINVAL;
        return -1;
    }
    if ((nread = read(ioctl_pipein, data, datasz)) != datasz) {
        if (nread >= 0) errno = EINVAL;
        return -1;
    }
    return 0;
}
#endif

#ifdef VFTPPROXY_USE_PF_DEVICE
int
add_routeto_filter(u_int32_t id, u_int8_t dir, struct sockaddr *src,
    struct sockaddr *dst, u_int16_t d_port, const char * newintf)
{
	if (!src || !dst || !d_port) {
		errno = EINVAL;
		return (-1);
	}

	if (prepare_rule(id, PF_RULESET_FILTER, src, dst, d_port) == -1)
		return (-1);

	pfr.rule.direction = dir;
    pfr.rule.rt = PF_ROUTETO;
    pfr.rule.keep_state = 0;

    strlcpy(pfp.addr.addr.v.ifname, newintf, IFNAMSIZ);
    pfp.addr.addr.type = PF_ADDR_DYNIFTL;

	if (ioctl(dev, DIOCADDADDR, &pfp) == -1)
		return (-1);

	if (ioctl(dev, DIOCADDRULE, &pfr) == -1)
		return (-1);

	return (0);
}


int
add_filter(u_int32_t id, u_int8_t dir, struct sockaddr *src,
    struct sockaddr *dst, u_int16_t d_port)
{
	if (!src || !dst || !d_port) {
		errno = EINVAL;
		return (-1);
	}

	if (prepare_rule(id, PF_RULESET_FILTER, src, dst, d_port) == -1)
		return (-1);

	pfr.rule.direction = dir;

	if (ioctl(dev, DIOCADDRULE, &pfr) == -1)
		return (-1);

	return (0);
}

int
add_nat(u_int32_t id, struct sockaddr *src, struct sockaddr *dst,
    u_int16_t d_port, struct sockaddr *nat, u_int16_t nat_range_low,
    u_int16_t nat_range_high)
{
	if (!src || !dst || !d_port || !nat || !nat_range_low ||
	    (src->sa_family != nat->sa_family)) {
		errno = EINVAL;
		return (-1);
	}

	if (prepare_rule(id, PF_RULESET_NAT, src, dst, d_port) == -1)
		return (-1);

	if (nat->sa_family == AF_INET) {
		memcpy(&pfp.addr.addr.v.a.addr.v4,
		    &satosin(nat)->sin_addr.s_addr, 4);
		memset(&pfp.addr.addr.v.a.mask.addr8, 255, 4);
	} else {
		memcpy(&pfp.addr.addr.v.a.addr.v6,
		    &satosin6(nat)->sin6_addr.s6_addr, 16);
		memset(&pfp.addr.addr.v.a.mask.addr8, 255, 16);
	}
	if (ioctl(dev, DIOCADDADDR, &pfp) == -1)
		return (-1);

	pfr.rule.rpool.proxy_port[0] = nat_range_low;
	pfr.rule.rpool.proxy_port[1] = nat_range_high;
	if (ioctl(dev, DIOCADDRULE, &pfr) == -1)
		return (-1);

	return (0);
}

int
add_rdr(u_int32_t id, struct sockaddr *src, struct sockaddr *dst,
    u_int16_t d_port, struct sockaddr *rdr, u_int16_t rdr_port)
{
	if (!src || !dst || !d_port || !rdr || !rdr_port ||
	    (src->sa_family != rdr->sa_family)) {
		errno = EINVAL;
		return (-1);
	}

	if (prepare_rule(id, PF_RULESET_RDR, src, dst, d_port) == -1)
		return (-1);

	if (rdr->sa_family == AF_INET) {
		memcpy(&pfp.addr.addr.v.a.addr.v4,
		    &satosin(rdr)->sin_addr.s_addr, 4);
		memset(&pfp.addr.addr.v.a.mask.addr8, 255, 4);
	} else {
		memcpy(&pfp.addr.addr.v.a.addr.v6,
		    &satosin6(rdr)->sin6_addr.s6_addr, 16);
		memset(&pfp.addr.addr.v.a.mask.addr8, 255, 16);
	}
	if (ioctl(dev, DIOCADDADDR, &pfp) == -1)
		return (-1);

	pfr.rule.rpool.proxy_port[0] = rdr_port;
	if (ioctl(dev, DIOCADDRULE, &pfr) == -1)
		return (-1);

	return (0);
}

int
do_commit(void)
{
	if (ioctl(dev, DIOCXCOMMIT, &pft_all) == -1)
		return (-1);
    pft_all.pft.array = pfte;
	return (0);
}

int
do_rollback(void)
{
	if (ioctl(dev, DIOCXROLLBACK, &pft_all) == -1)
		return (-1);
    pft_all.pft.array = pfte;
	return (0);
}

#ifdef VFTPPROXY_IOCTL_FORK
/* process running as root handling ioctl pf requests
 * from proxy network process running as nobody
 * (on osx 10.11, rights on dev/pf are not enough,
 * we need to be root. */
void ioctl_process(int fdin, int fdout) {
    unsigned long id;
    struct pfioc_natlook pnl;
	struct pf_status status;
    void *data;
    size_t datasz;
    ssize_t nread;
    fd_set                  readfds, writefds, errfds;
    struct sigaction        sa;
    sigset_t                select_sigset, block_sigset;
    int                     select_ret, select_errno;
    //int ret, fd_max = -1;
    //struct timespec         select_timeout;

   /* setup the thread exit signal */
    sigemptyset(&select_sigset);
    sigemptyset(&block_sigset);

    /* ignore SIGPIPE */
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, NULL) < 0) {
        err(1, "error sigaction(SIGPIPE)");
    }

    while (1) {
        logmsg(LOG_DEBUG, "ioctl_process: loop");
        /* fill the read, write, err fdsets, and manage new registered signals  */
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_ZERO(&errfds);
        FD_SET(fdin, &readfds);
        FD_SET(fdin, &errfds);

        select_ret = pselect(fdin + 1, &readfds, &writefds, &errfds,
                             NULL /*&select_timeout*/, &select_sigset);
        select_errno = errno;
       /* -------------------------------------------- */

        if (select_ret == 0) {
            // timeout: continue ;
            continue ;
        }
        if (select_ret < 0 && select_errno == EINTR) {
            // "interrupted by signal: %s", strsignal(last_signal));
            continue ;
        }
        if (select_ret < 0) {
            logmsg(LOG_WARNING, "ioctl_process: select error");
            break ;
        }
        if (FD_ISSET(fdin, &errfds)) {
            logmsg(LOG_WARNING, "ioctl_process: select_fd error");
            break ;
        }
        if (FD_ISSET(fdin, &readfds)) {
            if ((nread = read(fdin, &id, sizeof(id))) < 0) {
                logmsg(LOG_WARNING, "ioctl_process: read error: %s", strerror(errno));
                break ;
            } else if (nread == 0) {
                logmsg(LOG_WARNING, "ioctl_process: pipe closed");
                break ;
            } else if (nread != sizeof(id)) {
                logmsg(LOG_WARNING, "ioctl_process: bad cmd size(%zd)", nread);
                continue ;
            }
            data = NULL;
            switch(id) {
                case DIOCGETSTATUS:
                    logmsg(LOG_DEBUG, "DIOCGETSTATUS");
                    if (read(fdin, &status, sizeof(status)) != sizeof(status)) {
                        logmsg(LOG_WARNING, "ERR: bad DIOCGETSTATUS(%lu)", id);
                     } else {
                         data = &status;
                         datasz = sizeof(status);
                     }
                     break ;
                case DIOCADDRULE:
                    logmsg(LOG_DEBUG, "DIOCADDRULE");
                    if (read(fdin, &pfr, sizeof(pfr)) != sizeof(pfr)) {
                        logmsg(LOG_WARNING, "ERR: bad DIOCADDRULE(%lu)", id);
                     } else {
                         data = &pfr;
                         datasz = sizeof(pfr);
                     }
                     break ;
                case DIOCADDADDR:
                case DIOCBEGINADDRS:
                    logmsg(LOG_DEBUG, "DIOCADDADDR(s)");
                    if (read(fdin, &pfp, sizeof(pfp)) != sizeof(pfp)) {
                        logmsg(LOG_WARNING, "ERR: bad DIOCADDR(%lu)", id);
                     } else {
                         data = &pfp;
                         datasz = sizeof(pfp);
                     }
                     break ;
                case DIOCXCOMMIT:
                case DIOCXROLLBACK:
                case DIOCXBEGIN:
                    logmsg(LOG_DEBUG, "DIOCXCOMMIT(s)");
                    if (read(fdin, &pft_all, sizeof(pft_all)) != sizeof(pft_all)) {
                        logmsg(LOG_WARNING, "ERR: bad DIOCXBEGIN(%lu)", id);
                     } else {
                         data = &pft_all;
                         datasz = sizeof(pft_all);
                         pft_all.pft.array = pfte;
                     }
                     break ;
                case DIOCNATLOOK:
                    logmsg(LOG_DEBUG, "DIOCNATLOOK");
                    if (read(fdin, &pnl, sizeof(pnl)) != sizeof(pnl)) {
                        logmsg(LOG_WARNING, "ERR: bad DIOCNATLOOK(%lu)", id);
                     } else {
                        data = &pnl;
                        datasz = sizeof(pnl);
                     }
                     break ;
                default:
                    logmsg(LOG_WARNING, "WARNING: unknown pf ctl command(%lu))", id);
                    break ;
            }
            if (data != NULL) {
                int res = ioctl_real(dev, id, data);
                if (write(fdout, &res, sizeof(int)) != sizeof(int)) {
                    logmsg(LOG_WARNING, "ioctl_process: cannot send ioctl retval(%lu)", id);
                }
                if (res == -1) {
                    logmsg(LOG_WARNING, "ioctl_process: error: ioctl(%lu): %s", id, strerror(errno));
                } else if (write(fdout, data, datasz) != datasz) {
                    logmsg(LOG_WARNING, "ioctl_process: cannot send ioctl out data(%lu)", id);
                }
            }
        }
    }
    logmsg(LOG_WARNING, "ioctl_process: shutting down");

    exit(0);
}
static void handle_signal(int sig) {
    (void) sig;
}
#endif

void
init_filter(const char *opt_qname, const char *opt_tagname, int opt_verbose)
{
	struct pf_status status;
#ifdef VFTPPROXY_IOCTL_FORK
    pid_t pid;
    int pipefd[2];
    int pipefd_ret[2];
#endif
	qname = opt_qname;
	tagname = opt_tagname;

	if (opt_verbose == 1)
		rule_log = PF_LOG;
	else if (opt_verbose == 2)
		rule_log = PF_LOG_ALL;

	dev = open("/dev/pf", O_RDWR);
	if (dev == -1)
		err(1, "open /dev/pf");
#ifdef VFTPPROXY_IOCTL_FORK
    if (pipe(pipefd) != 0 || pipe(pipefd_ret) != 0)
        err(1, "ioctl pipe failed");
    if ((pid = fork()) == -1)
        err(1, "ioctl fork failed");
    if (pid == 0) {
        close(pipefd[1]);
        close(pipefd_ret[0]);
        tzset();
	    if (chroot(CHROOT_DIR) != 0 || chdir("/") != 0) {
            err(1, "ioctl_process chroot");
        }
        ioctl_process(pipefd[0], pipefd_ret[1]);
    } else {
        struct sigaction        sa;
        /* SIGCHLD */
        sa.sa_flags = SA_RESTART;
        sa.sa_handler = handle_signal;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGCHLD, &sa, NULL) < 0) {
            err(1, "error sigaction(SIGCHLD)");
        }
        ioctl_pipeout = pipefd[1];
        ioctl_pipein = pipefd_ret[0];
        close(pipefd[0]);
        close(pipefd_ret[1]);
    }
#endif

	if (ioctl(dev, DIOCGETSTATUS, &status) == -1)
		err(1, "DIOCGETSTATUS");
	if (!status.running)
		errx(1, "pf is disabled");
}

int
prepare_commit(u_int32_t id)
{
	char an[PF_ANCHOR_NAME_SIZE];
	int i;

	memset(pft, 0, sizeof *pft);
	pft->size = TRANS_SIZE;
	pft->esize = sizeof pfte[0];
	pft->array = pfte;

	snprintf(an, PF_ANCHOR_NAME_SIZE, "%s/%d.%d", FTP_PROXY_ANCHOR,
	    getpid(), id);
	for (i = 0; i < TRANS_SIZE; i++) {
		memset(&pfte[i], 0, sizeof pfte[0]);
		strlcpy(pfte[i].anchor, an, PF_ANCHOR_NAME_SIZE);
		switch (i) {
		case TRANS_FILTER:
			pfte[i].rs_num = PF_RULESET_FILTER;
			break;
		case TRANS_NAT:
			pfte[i].rs_num = PF_RULESET_NAT;
			break;
		case TRANS_RDR:
			pfte[i].rs_num = PF_RULESET_RDR;
			break;
		default:
			errno = EINVAL;
			return (-1);
		}
	}

	if (ioctl(dev, DIOCXBEGIN, &pft_all) == -1)
		return (-1);
    pft_all.pft.array = pfte;
	return (0);
}

int
prepare_rule(u_int32_t id, int rs_num, struct sockaddr *src,
    struct sockaddr *dst, u_int16_t d_port)
{
	char an[PF_ANCHOR_NAME_SIZE];

	if ((src->sa_family != AF_INET && src->sa_family != AF_INET6) ||
	    (src->sa_family != dst->sa_family)) {
	    	errno = EPROTONOSUPPORT;
		return (-1);
	}

	memset(&pfp, 0, sizeof pfp);
	memset(&pfr, 0, sizeof pfr);
	snprintf(an, PF_ANCHOR_NAME_SIZE, "%s/%d.%d", FTP_PROXY_ANCHOR,
	    getpid(), id);
	strlcpy(pfp.anchor, an, PF_ANCHOR_NAME_SIZE);
	strlcpy(pfr.anchor, an, PF_ANCHOR_NAME_SIZE);

	switch (rs_num) {
	case PF_RULESET_FILTER:
		pfr.ticket = pfte[TRANS_FILTER].ticket;
		break;
	case PF_RULESET_NAT:
		pfr.ticket = pfte[TRANS_NAT].ticket;
		break;
	case PF_RULESET_RDR:
		pfr.ticket = pfte[TRANS_RDR].ticket;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}
	if (ioctl(dev, DIOCBEGINADDRS, &pfp) == -1)
		return (-1);
	pfr.pool_ticket = pfp.ticket;

	/* Generic for all rule types. */
	pfr.rule.af = src->sa_family;
	pfr.rule.proto = IPPROTO_TCP;
	pfr.rule.src.addr.type = PF_ADDR_ADDRMASK;
	pfr.rule.dst.addr.type = PF_ADDR_ADDRMASK;
	if (src->sa_family == AF_INET) {
		memcpy(&pfr.rule.src.addr.v.a.addr.v4,
		    &satosin(src)->sin_addr.s_addr, 4);
		memset(&pfr.rule.src.addr.v.a.mask.addr8, 255, 4);
		memcpy(&pfr.rule.dst.addr.v.a.addr.v4,
		    &satosin(dst)->sin_addr.s_addr, 4);
		memset(&pfr.rule.dst.addr.v.a.mask.addr8, 255, 4);
	} else {
		memcpy(&pfr.rule.src.addr.v.a.addr.v6,
		    &satosin6(src)->sin6_addr.s6_addr, 16);
		memset(&pfr.rule.src.addr.v.a.mask.addr8, 255, 16);
		memcpy(&pfr.rule.dst.addr.v.a.addr.v6,
		    &satosin6(dst)->sin6_addr.s6_addr, 16);
		memset(&pfr.rule.dst.addr.v.a.mask.addr8, 255, 16);
	}
    #ifdef __APPLE__
    pfr.rule.dst.xport.range.op = PF_OP_EQ;
	pfr.rule.dst.xport.range.port[0] = htons(d_port);
    #else
	pfr.rule.dst.port_op = PF_OP_EQ;      //FreeBSD
	pfr.rule.dst.port[0] = htons(d_port); //FreeBSD
    #endif

    pfr.rule.log = rule_log;

	switch (rs_num) {
	case PF_RULESET_FILTER:
		/*
		 * pass [quick] [log] inet[6] proto tcp \
		 *     from $src to $dst port = $d_port flags S/SA keep state
		 *     (max 1) [queue qname] [tag tagname]
		 */
		pfr.rule.action = PF_PASS;
		pfr.rule.quick = 1;
		//pfr.rule.log = rule_log;
		pfr.rule.keep_state = 1;
		pfr.rule.flags = TH_SYN;
		pfr.rule.flagset = (TH_SYN|TH_ACK);
		pfr.rule.max_states = 1;
		if (qname != NULL)
			strlcpy(pfr.rule.qname, qname, sizeof pfr.rule.qname);
		if (tagname != NULL) {
			pfr.rule.quick = 0;
			strlcpy(pfr.rule.tagname, tagname,
                                sizeof pfr.rule.tagname);
		}
		break;
	case PF_RULESET_NAT:
		/*
		 * nat inet[6] proto tcp from $src to $dst port $d_port -> $nat
		 */
		pfr.rule.action = PF_NAT;
		break;
	case PF_RULESET_RDR:
		/*
		 * rdr inet[6] proto tcp from $src to $dst port $d_port -> $rdr
		 */
		pfr.rule.action = PF_RDR;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}

	return (0);
}

int
server_lookup4(struct sockaddr_in *client, struct sockaddr_in *proxy,
    struct sockaddr_in *server)
{
	struct pfioc_natlook pnl;

	memset(&pnl, 0, sizeof pnl);
	pnl.direction = PF_OUT;
	pnl.af = AF_INET;
	pnl.proto = IPPROTO_TCP;
	memcpy(&pnl.saddr.v4, &client->sin_addr.s_addr, sizeof pnl.saddr.v4);
	memcpy(&pnl.daddr.v4, &proxy->sin_addr.s_addr, sizeof pnl.daddr.v4);
    #ifdef __APPLE__
    pnl.sxport.port = client->sin_port;
    pnl.dxport.port = proxy->sin_port;
    #else
    pnl.sport = client->sin_port;
	pnl.dport = proxy->sin_port;
    #endif

	if (ioctl(dev, DIOCNATLOOK, &pnl) == -1)
		return (-1);

	memset(server, 0, sizeof(struct sockaddr_in));
	server->sin_len = sizeof(struct sockaddr_in);
	server->sin_family = AF_INET;
	memcpy(&server->sin_addr.s_addr, &pnl.rdaddr.v4,
	    sizeof server->sin_addr.s_addr);
    #ifdef __APPLE__
    server->sin_port = pnl.rdxport.port;
    #else
    server->sin_port = pnl.rdport;
    #endif

	return (0);
}

int
server_lookup6(struct sockaddr_in6 *client, struct sockaddr_in6 *proxy,
    struct sockaddr_in6 *server)
{
	struct pfioc_natlook pnl;

	memset(&pnl, 0, sizeof pnl);
	pnl.direction = PF_OUT;
	pnl.af = AF_INET6;
	pnl.proto = IPPROTO_TCP;
	memcpy(&pnl.saddr.v6, &client->sin6_addr.s6_addr, sizeof pnl.saddr.v6);
	memcpy(&pnl.daddr.v6, &proxy->sin6_addr.s6_addr, sizeof pnl.daddr.v6);
    #ifdef __APPLE__
    pnl.sxport.port = client->sin6_port;
	pnl.dxport.port = proxy->sin6_port;
    #else
    pnl.sport = client->sin6_port;
	pnl.dport = proxy->sin6_port;
    #endif

	if (ioctl(dev, DIOCNATLOOK, &pnl) == -1)
		return (-1);

	memset(server, 0, sizeof(struct sockaddr_in6));
	server->sin6_len = sizeof(struct sockaddr_in6);
	server->sin6_family = AF_INET6;
	memcpy(&server->sin6_addr.s6_addr, &pnl.rdaddr.v6,
	    sizeof server->sin6_addr);
    #ifdef __APPLE__
    server->sin6_port = pnl.rdxport.port;
    #else
    server->sin6_port = pnl.rdport;
    #endif

	return (0);
}
#endif /* ! ifdef VFTPPROXY_USE_PF_DEVICE */

int
server_lookup(struct sockaddr *client, struct sockaddr *proxy,
    struct sockaddr *server)
{
	if (client->sa_family == AF_INET)
		return (server_lookup4(satosin(client), satosin(proxy),
		    satosin(server)));

	if (client->sa_family == AF_INET6)
		return (server_lookup6(satosin6(client), satosin6(proxy),
		    satosin6(server)));

	errno = EPROTONOSUPPORT;
	return (-1);
}


/*********************************
 * DEAD CODE, to be removed
 * *******************************/
#ifndef VFTPPROXY_USE_PF_DEVICE
int add_nat(u_int32_t a, struct sockaddr * b, struct sockaddr * c, u_int16_t d,
    struct sockaddr * e, u_int16_t f, u_int16_t g) {
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    (void)e;
    (void)f;
    (void)g;
    return 0;
}
int add_rdr(u_int32_t id, struct sockaddr *src, struct sockaddr *dst,
            u_int16_t d_port, struct sockaddr *rdr, u_int16_t rdr_port) {
    char rule_str[1024];
    char src_str[INET6_ADDRSTRLEN];
    char dst_str[INET6_ADDRSTRLEN];
    char rdr_str[INET6_ADDRSTRLEN];

    if (!src || !dst || !d_port || !rdr || !rdr_port ||
	    (src->sa_family != rdr->sa_family)) {
		errno = EINVAL;
		return (-1);
	}

    if (inet_ntop(src->sa_family, &(((struct sockaddr_in *)src)->sin_addr), src_str, sizeof(src_str)) == NULL)
       return (-1);
    if (inet_ntop(dst->sa_family, &(((struct sockaddr_in *)dst)->sin_addr), dst_str, sizeof(dst_str)) == NULL)
        return (-1);
    if (inet_ntop(rdr->sa_family, &(((struct sockaddr_in *)rdr)->sin_addr), rdr_str, sizeof(rdr_str)) == NULL)
        return (-1);

    /* rdr from $server to $proxy port $proxy_port -> $client port $port */
    snprintf(rule_str, sizeof(rule_str),
             "/usr/bin/printf -- 'rdr log(user) proto tcp from %s to %s port %d -> %s port %d\n'"
             " | /sbin/pfctl -f - -a ftp-proxy/%u", dst_str, src_str, rdr_port, src_str, d_port, id);
    fprintf(stderr, "ftp-proxy(uid=%d,euid=%d): adding rule '%s'\n", getuid(), geteuid(), rule_str);

    if (system(rule_str) != 0) {
        fprintf(stderr, "ftp-proxy: ERROR adding rule '%s': %s\n", rule_str, strerror(errno));
        return (-1);
    }

	return (0);
}
int do_commit(void) {
    return 0;
}
int do_rollback(void) {
    return 0;
}
void init_filter(const char * a, const char * b, int c) {
    (void)a;
    (void)b;
    (void)c;
}
int prepare_commit(u_int32_t a) {
    (void)a;
    return 0;
}
int
server_lookup4(struct sockaddr_in *client, struct sockaddr_in *proxy,
    struct sockaddr_in *server)
{
    in_addr_t servaddr = inet_addr("209.51.188.20"); // FIXME

	memset(server, 0, sizeof(struct sockaddr_in));
	server->sin_len = sizeof(struct sockaddr_in);
	server->sin_family = AF_INET;
	memcpy(&server->sin_addr.s_addr, &servaddr,
	    sizeof server->sin_addr.s_addr);
	server->sin_port = ntohs(21); //pnl.rdport;

	return (0);
}
int
server_lookup6(struct sockaddr_in6 *client, struct sockaddr_in6 *proxy,
    struct sockaddr_in6 *server)
{
    struct in6_addr servaddr;

    if (inet_pton(AF_INET6, "2001:470:142:3::b", &servaddr) != 0) // FIXME
        return (-1);

	memset(server, 0, sizeof(struct sockaddr_in6));
	server->sin6_len = sizeof(struct sockaddr_in6);
	server->sin6_family = AF_INET6;
	memcpy(&server->sin6_addr.s6_addr, &servaddr,
	    sizeof server->sin6_addr);
	server->sin6_port = ntohs(21);

	return (0);
}
int
add_filter(u_int32_t id, u_int8_t dir, struct sockaddr *src,
    struct sockaddr *dst, u_int16_t d_port)
{
    char rule_str[1024];
    char src_str[INET6_ADDRSTRLEN];
    char dst_str[INET6_ADDRSTRLEN];

    if (!src || !dst || !d_port) {
		errno = EINVAL;
		return (-1);
	}

    if (dir == PF_IN)
        return (0);

    if (inet_ntop(src->sa_family, &(((struct sockaddr_in *)src)->sin_addr), src_str, sizeof(src_str)) == NULL)
       return (-1);
    if (inet_ntop(dst->sa_family, &(((struct sockaddr_in *)dst)->sin_addr), dst_str, sizeof(dst_str)) == NULL)
        return (-1);

    snprintf(rule_str, sizeof(rule_str),
             "/usr/bin/printf -- 'pass out log(user) proto tcp from %s to %s port %d keep state\n'"
             " | /sbin/pfctl -f - -a ftp-proxy/%u", src_str, dst_str, d_port, id);
    fprintf(stderr, "ftp-proxy(uid=%d,euid=%d): adding rule '%s'\n", getuid(), geteuid(), rule_str);

    if (system(rule_str) != 0) {
        fprintf(stderr, "ftp-proxy: ERROR adding rule '%s': %s\n", rule_str, strerror(errno));
        return (-1);
    }

	return (0);
}
#endif /* ! ifndef VFTPPROXY_USE_PF_DEVICE */

