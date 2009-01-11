#!/bin/bash

if test $# -ne 2 ; then
	echo "usage: sync.sh dir/ map"
	exit 1
fi

if test -e "$1serverlist";
then
        for server in `cat $1serverlist`;
        do
                echo "Updating $2.cf on $server..."
                scp $1$2.cf $server:$1$2.cf
                echo "Rebuilding $2.sq3 on $server..."
                ssh $server "cd $1; make"
        done
fi

exit 0
