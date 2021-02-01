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
/*	$OpenBSD: filter.h,v 1.4 2007/08/01 09:31:41 henning Exp $ */
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

/* FIXME VSA BEGIN net/pfvar.h */
#include <sys/param.h>
#include <sys/queue.h>
//#include <sys/counter.h>
#include <sys/malloc.h>
//#include <sys/refcount.h>
//#include <sys/tree.h>
//#include <vm/uma.h>

//#include <net/radix.h>
#include <netinet/in.h>

//#include <netpfil/pf/pf.h>
//#include <netpfil/pf/pf_altq.h>
//#include <netpfil/pf/pf_mtag.h>

#define VFTPPROXY_USE_PF_DEVICE 1

#define	FTP_PROXY_ANCHOR "ftp-proxy"

int add_filter(u_int32_t, u_int8_t, struct sockaddr *, struct sockaddr *,
    u_int16_t);
int add_routeto_filter(u_int32_t id, u_int8_t dir, struct sockaddr *src,
    struct sockaddr *dst, u_int16_t d_port, const char * newintf);
int add_nat(u_int32_t, struct sockaddr *, struct sockaddr *, u_int16_t,
    struct sockaddr *, u_int16_t, u_int16_t);
int add_rdr(u_int32_t, struct sockaddr *, struct sockaddr *, u_int16_t,
    struct sockaddr *, u_int16_t);
int do_commit(void);
int do_rollback(void);
void init_filter(const char *, const char *, int);
int prepare_commit(u_int32_t);
int server_lookup(struct sockaddr *, struct sockaddr *, struct sockaddr *);

