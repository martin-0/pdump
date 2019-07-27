ARCHBITS = $(shell getconf LONG_BIT)
CFLAGS=-g -Wall 
DEMO=demo
USER=nobody

ifeq ($(ARCHBITS),64)
	CFLAGS32:= ${CFLAGS} -m32
	DEMO32:= ${DEMO}32
endif

OUTDIR=../work

ALL:	${DEMO} perm


${DEMO}:	${DEMO}.c
	gcc ${CFLAGS} -o ${OUTDIR}/${DEMO} ${DEMO}.c
	gcc ${CFLAGS} -static -o ${OUTDIR}/${DEMO}S ${DEMO}.c

ifeq ($(ARCHBITS),64)
	gcc ${CFLAGS32} -o ${OUTDIR}/${DEMO32} ${DEMO}.c
	gcc ${CFLAGS32} -static -o ${OUTDIR}/${DEMO32}S ${DEMO}.c
endif

perm:
	sudo /bin/chown ${USER} ${OUTDIR}/${DEMO}*
	sudo /bin/chmod 4711 ${OUTDIR}/${DEMO}*

clean:
	rm -f ${OUTDIR}/${DEMO}* 
