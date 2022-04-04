BarricadeMX - An SMTP Filtering Proxy
=====================================

[BarricadeMX](http://www.snertsoft.com/doc/smtpf/) sits in front of one or more MTAs on SMTP port 25.  It acts as a proxy, filtering and forwarding mail to the MTAs, which can be on the same machine or different machines.  By using an independent SMTP pre-filter in the form of a proxy we avoid portability differences and limitations of MTA extension methods (milters, plugins, rule sets, etc.) and tighly couple & integrate tests to improve performance & message throughput.  Requires LibSnert.

[![The Big Picture](doc/Img/BarricadeMX1.jpg)](http://www.snertsoft.com/doc/smtpf/)
