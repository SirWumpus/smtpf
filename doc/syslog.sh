#!/bin/sh

awk -f syslog.awk ../src/*.c >syslog.$$
cat syslog-header.html syslog.$$ syslog-footer.html >syslog.html.in
rm -f syslog.$$


