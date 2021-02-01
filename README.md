
## vftp-proxy
---------------

* [Overview](#overview)
* [System Requirements](#system-requirements)
* [Compilation](#compilation)
* [Usage](#usage)
* [Contact](#contact)
* [License](#license)

## Overview
**vftp-proxy** is a fork from freebsd ftp-proxy, to enable ftp-proxy on osx 10.11,
whose builtin ftp-proxy do not work as expected when used on the same host 
making ftp requests (when pf is enabled on this host).

## System requirements
- A somewhat capable compiler (gcc/clang), make (GNU,BSD), sh (sh/bash/ksh)
  and coreutils (awk,grep,sed,date,touch,head,printf,which,find,test,...)
- libevent (http://libevent.org), with pkg-config files.
- OSX 10.11.6

## Compilation

### Cloning **vftp-proxy** repository
**vftp-proxy** is using SUBMODROOTDIR Makefile's feature (RECOMMANDED, see [submodules](#using-git-submodules)):  
    $ git clone https://github.com/vsallaberry/vftp-proxy.git  
    $ git submodule update --init # or just 'make'  

Otherwise:  
    $ git clone --recursive https://vsallaberry/vftp-proxy.git  

### net/pfvar.h kernel header
On OSX net/pfvar.h and libkern/tree.h are not public, they can be 
retrieved from apple opensource server. (https://opensource.apple.com/source/xnu).  
A custom makefile rule will download the right version for you:  
    $ make update_pfvar  
    $ mv $files ext/include

### Building
Just type:  
    $ make # (or 'make -j3' for SMP)  

If the Makefile cannot be parsed by 'make', try:  
    $ ./make-fallback  

### General information
An overview of Makefile rules can be displayed with:  
    $ make help  

Most of utilities used in Makefile are defined in variables and can be changed
with something like 'make SED=gsed TAR=gnutar' (or ./make-fallback SED=...)  

To See how make understood the Makefile, you can type:  
    $ make info # ( or ./make-fallback info)  

When making without version.h created (not the case for this repo), some old
bsd make can stop. Just type again '$ make' and it will be fine.  

### Using git submodules
When your project uses git submodules, it is a good idea to group
submodules in a common folder, here, 'ext'. Indeed, instead of creating a complex tree
in case the project (A) uses module B (which uses module X) and module C (which uses module X),
X will not be duplicated as all submodules will be in ext folder.  

You need to set the variable SUBMODROOTDIR in your program's Makefile to indicate 'make'
where to find submodules (will be propagated to SUBDIRS).  

As SUBDIRS in Makefile are called with SUBMODROOTDIR propagation, currently you cannot use 
'make -C <subdir>' (or make -f <subdir>/Makefile) but instead you can use 'make <subdir>',
 'make {check,debug,test,install,...}-<subdir>', as <subdir>, check-<subdir>, ... are
defined as targets.  

When SUBMODROOTDIR is used, submodules of submodules will not be populated as they are
included in root project. The command `make subsubmodules` will update index of non-populated 
sub-submodules to the index used in the root project.

You can let SUBMODROOTDIR empty if you do not want to group submodules together.

## Usage
Here, we describe only the setup for running the proxy
on an OSX host with pf enabled. The setup on a gateway is not described here.
### Create user _ftpproxy
### Run server
  $ vftp-proxy -D5 -N -d  
  $ vftp-proxy -D5 -N -d -6  
### PF configuration
#**********************
# Translation
#**********************
# ftp-proxy
rdr-anchor "ftp-proxy"
rdr-anchor "ftp-proxy/*"
nat-anchor "ftp-proxy"
nat-anchor "ftp-proxy/*"
# RDR FTP from ME to INTERNET -> localhost:8021
ftpprox_net_port=8021
rdr $logall on { lo0 } inet proto tcp from $ext_ip to { ! $ext_net } port { 21 } tagged "ftp-proxied-me2ext" -> 127.0.0.1 port $ftpprox_net_port
rdr $logall on { lo0 } inet6 proto tcp from $ext_ip6 to { ! $ext_net6 } port { 21 } tagged "ftp-proxied-me2ext" -> ::1 port $ftpprox_net_port
#**********************
# Filtering
#**********************
# FTP THIS->NET REDIRECT TO PROXY
pass out $logall on {$ext_if} route-to lo0 proto tcp from {$ext_ip} to { !$ext_net } port { 21 } \
  tag "ftp-proxied-me2ext" user { vincent root guest macports } label "FTP ext queries from me" #flags any
pass in $logall on { lo0 } reply-to $ext_if proto tcp from $ext_ip \
  to lo0 port { $ftpprox_net_port } tagged "ftp-proxied-me2ext" #flags any


#
#
## Contact
[vsallaberry@gmail.com]  
<https://github.com/vsallaberry/vftp-proxy>

## License
GPLv3 or later. See LICENSE file.  
CopyRight: Copyright (C) 2021 Vincent Sallaberry  

**vftp-proxy** is forked from **FreeBSD ftp-proxy**
 * https://github.com/freebsd/freebsd
 * contrib/pf/ftp-proxy (eb6f5408ecc27df916af9f862c55e90defe742c3)
 * See FreeBSD ftp-proxy copyright notice below  
  
  Copyright (c) 2004, 2005 Camiel Dobbelaar, <cd@sentia.nl>  
 
  Permission to use, copy, modify, and distribute this software for any  
  purpose with or without fee is hereby granted, provided that the above  
  copyright notice and this permission notice appear in all copies.  
 
  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES  
  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF  
  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR  
  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES  
  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN  
  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF  
  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.  
 

