
GSS-TUNNEL
==========

This is a utility to tunnel normal TCP connections and wrap them into
a GSSAPI negotiated Secure Channel, pretty much like the stunnel utility
is used to wrap TCP connections into a TLS channel.

BUILDING
========

$ autoreconf -f -i
$ ./configure
$ make

DEPENDENCIES
============
docbook-style-xsl
gettext
libpopt
libini_config
ligssapi


EXAMPLE/TEST
============
Create a configuration file like this:
#-- gsstunnel.example.conf --
[in]
  accept=localhost:9000
  connect=localhost:9001
  client=yes
  target name = test@f.q.d.n

[out]
  accept=localhost:9001
  connect=localhost:9002
#--

Run these each in their terminal:
./gsstunnel -c gsstunnel.example.conf
ncat -l 9002 --exec=/bin/bash
telnet 9000

