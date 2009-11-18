#!/bin/sh

for f in *.c; do
	if ! grep -E 'LOG_TRACE.*000,|MSG\(000\)|NUM\(000\)' $f ; then
		continue;
	fi
	if test ! -f $f.orig ; then
		mv $f $f.orig
	fi
	echo $f
	awk -f number_msg.awk $f.orig >$f
done