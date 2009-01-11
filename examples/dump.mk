.POSIX :
.SUFFIXES :
.SUFFIXES : .cf .sq3

# Define the smtpf config directory with a trailing slash.
CURDIR=/etc/smtpf/

.sq3.cf :
	cp ${CURDIR}$*.cf ${CURDIR}$*.cf.bak
	kvmap -d "$*!sql!${CURDIR}$*.sq3" > ${CURDIR}$*.cf
	chmod 660 ${CURDIR}$*.cf
	if test -f ${CURDIR}sync.sh ; then ${CURDIR}sync.sh ${CURDIR} $* ; fi

all : cf

cf : access.cf route.cf

