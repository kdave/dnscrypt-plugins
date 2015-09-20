DNSCrypt plugins
================

A set of plugins that extend functionality of [DNSCrypt proxy](https://dnscrypt.org).

* logger - log queries to a file
* blacklist - filter outgoing queries by a pattern or IP address
* validate - validate names according to [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.txt), section 2.3.1
* empty\_aaaa - (copied from DNSCrypt) directly return empty answer to AAAA queries

Dependencies: dnscrypt-proxy headers and enabled plugin support, LDNS.

More plugins:
* https://github.com/jedisct1/dnscrypt-plugin-geoip-block -- Block DNS queries according to the country they resolve to

### logger
Parameter: path to log file

Usage:
```shell
$ dnscrypt-proxy --plugin=libdcplugin_logger.so,/var/log/dnscrypt-query.log
```

Note: adjust file write permissions for the dnscrypt-proxy daemon

Example output:
```
2015-03-06 00:00:00 (1425596400) - www.lwn.net  [A]
```

date, time, UNIX timestamp, domain name, [DNS record type](https://en.wikipedia.org/wiki/List_of_DNS_record_types)

### blacklist
Parameters:
* *domains* - path to file with list of domain patterns
* *ips* - path to file with list of IP address patterns
* *logfile* - path to logfile

A query returns `NXDOMAIN`. The matching is done by a *wildcard*, currently only `*` works.

Usage:

```shell
$ dnscrypt-proxy --plugin libdcplugin_blacklist.so,--ips=/etc/dnscrypt.d/block-ips,--domains=/etc/dnscrypt.d/block-domains,--logfile=/var/log/dnscrpt-blocked.log

```
Note: adjust file permissions for the dnscrypt-proxy daemon

Example output:
```
2015-03-06 00:00:00 (1425596400) - blocked: test.example.com *.example.com
```
date, time, UNIX timestamp, domain name blocked, matching pattern

### validate
No parameters, no output.

Refuse to resolve disallowed names by returning `NXDOMAIN`. May be used to
prevent resolving `user@host.typo` . See [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.txt), section 2.3.1.

### empty\_aaaa
No parameters, no output.

Usage:
```shell
$ dnscrypt-proxy --plugin=libdcplugin_empty_aaaa.so
```

Build
-----

Install autotools, LDNS devel packages and dnscrypt-proxy plugin headers.

After a checkout from git, run
```shell
$ ./autogen.sh
$ ./configure
$ ./make
```

The plugin files are in `.libs`, you can use
```
$ make collect
```

that will copy just the `.so` files to `.built-so` directory. Copy the files to
`/usr/lib64/dnscrypt-proxy` where *dnscrypt-proxy* expects to find them.
