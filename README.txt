
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
libpopt
libini_config
ligssapi

