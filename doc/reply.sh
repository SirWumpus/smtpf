#!/bin/sh

awk -f reply.awk ../src/*.c >reply.$$
cat reply-header.html reply.$$ syslog-footer.html >reply.html.in
rm -f reply.$$
