#!/usr/local/bin/python3.4
#
# Copyright (c) 2015, Johan Ymerson
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of sidsd nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


# Dependencies:
# Python 3.4
# Daemonize: https://pypi.python.org/pypi/daemonize

import socket, select, signal, os, sys, ipaddress, time, subprocess, syslog
from daemonize import Daemonize

## Configuration options

# IP:port combinations to listen to.
# I recommend to only listen on one port on localhost
# and use Packet Filter to redirect desired traffic there.
sensors =[ '127.0.0.1:666' ]

# A list of networks that never should be blacklisted.
# Put your trusted networks here.
# Entries must be in the form '1.2.3.0/24'.
# Single hosts can be specified with netmask /32.
whitelist = [ '192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12' ]

# How long (in seconds) should hosts remain in the graylist.
graylist_timeout = 3600*4

# How long (in seconds) should hosts remain in the blacklist.
blacklist_timeout = 3600*4

# Name of the Packet Filter table to add blacklisted hosts to.
pftable = 'abusive_hosts'

# Where to put the PID-file
pidfile = '/var/run/ids.pid'

## End of configuration options

sockets = []
blacklist = []
graylist = []

class BlockedHost:
    """ Class to manage a blocked (or graylisted) host
    The constructor takes one argument, the IP address of the host.
    Public class variables:
      ip: the IP address of the host
      timestamp: when the host entry was first added
      hits: number of times this host has hit a sensor
    """
    def __init__(self, ip):
        self.ip = ip
        self.timestamp = time.time()
        self.hits = 1

    def __eq__(self, other):
        return self.ip == other.ip

    def __str__(self):
        return str(self.ip)

    def __repr__(self):
        return str(self.ip)

def pf_add_to_table(host, pftable):
    """ Add a host to a Packet Filter table

    Arguments:
    host: host (a BlockedHost object or IP address)
    pftable: name of Packet Filter table
    """
    subprocess.call(['pfctl', '-t', pftable, '-T', 'add', str(host)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def pf_remove_from_table(host, pftable):
    """ Remove a host from a Packet Filter table

    Arguments:
    host: host (a BlockedHost object or IP address)
    pftable: name of Packet Filter table
    """
    subprocess.call(['pfctl', '-t', pftable, '-T', 'delete', str(host)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def is_in_network(ip, net):
    """ Check if an IP address is part of a network
    
    Arguments:
    ip: IP address
    net: Network wich mask bits (like '1.3.4.0/24')

    Returns True if IP address is in the network, else False
    """
    return ipaddress.ip_address(ip) in ipaddress.ip_network(net)

def is_whitelisted(ip):
    """ Check if an IP address is in the whitelist

    Arguments:
    ip: IP address

    Returns True if IP address is in the whitelist, else False.
    """
    for w in whitelist:
        if is_in_network(ip, w):
            return(True)
    
def terminate(signum, frame):
    """ Terminate the daemon

    This function tries to clean up all sockets and remove all
    blocked hosts from the Packet Filter table before the
    daemon exits.
    """
    global sockets, pidfile, h

    syslog.syslog(syslog.LOG_INFO, 'Exiting')

    for s in sockets:
        s.close()
    for h in blacklist:
            pf_remove_from_table(h, pftable)

    signal.signal(signum, signal.SIG_DFL)
    sys.exit()

def main():
    """ The main daemon code

    Wait for connections on the sensor sockets. When a connection is opened,
    check the IP against whitelist, and add to graylist or blacklist, depending
    on how many times the IP address has tried to connect.

    Periodically clean out old addresses from the gray- and blacklist.
    """
    global sensors, sockets, whitelist, blacklist, blacklist_timeout, pftable

    signal.signal(signal.SIGTERM, terminate)

    syslog.syslog(syslog.LOG_INFO, "Daemon started, listening on %i sensors"
                  % len(sockets))

    while True:
        r, w, e = select.select(sockets, [], [], 5)
        for s in r:
            # Accept the connect and get the remote IP
            try:
                c, remote = s.accept()
            except:
                continue
            c.close()
            ip = remote[0]

            # Check if IP is whitelisted
            if (is_whitelisted(ip)):
                syslog.syslog(syslog.LOG_INFO, "%s in whitelist, ignored" % ip)
                continue

            h = BlockedHost(ip)
            if not h in blacklist:
                if h in graylist:
                    graylist[graylist.index(h)].hits += 1
                    h = graylist[graylist.index(h)]
                else:
                    graylist.append(h)
                    syslog.syslog(syslog.LOG_INFO, "%s added to graylist" % ip)
                if h.hits >= 2:
                    graylist.remove(h)
                    blacklist.append(h)
                    pf_add_to_table(h, pftable)
                    syslog.syslog(syslog.LOG_INFO, "%s added to blacklist" % ip)

        # Remove old entries from graylist
        for h in graylist:
            if time.time() > h.timestamp + graylist_timeout:
                pf_remove_from_table(h, pftable)
                graylist.remove(h)
                syslog.syslog(syslog.LOG_INFO, "%s removed from graylist" % h)
        # Remove old entries from blacklist
        for h in blacklist:
            if time.time() > h.timestamp + blacklist_timeout:
                pf_remove_from_table(h, pftable)
                blacklist.remove(h)
                syslog.syslog(syslog.LOG_INFO, "%s removed from blacklist" % h)


# A list of filedescriptors that need to be kept open when daemonizing
keep_fds = []

# Make sure localnet is always on the whitelist
whitelist.append('127.0.0.0/8')

# Initialize logging
syslog.openlog(ident='ids', logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)

# Open sockets for the sensors
for s in sensors:
    ip, port = s.split(':', 1)
    port = int(port)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((ip, port))
        s.listen(1)
        sockets.append(s)
        keep_fds.append(s.fileno())
    except socket.error as exc:
        print('Failed to bind to %s:%i: %s' % (ip, port, exc), file=sys.stderr)
        sys.exit(-1)

print("Daemon started, listening on %i sensors" % len(sockets))

# Initialize logging and daemonize
daemon = Daemonize(app='ids', pid=pidfile, action=main, keep_fds=keep_fds)
daemon.start()
