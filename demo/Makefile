CFLAGS32=-g -O0 -pie -m32
CFLAGS64=-g -O0 -pie

OUTDIR=../work

DEMO=demo
DEMO32=demo32

PWNUSR=pwn

ALL:	${DEMO} ${DEMO32}

${DEMO}:	${DEMO}.c
	gcc ${CFLAGS64} -o ${OUTDIR}/${DEMO} ${DEMO}.c
	sudo /bin/chown ${PWNUSR} ${OUTDIR}/${DEMO}
	sudo /bin/chmod 4711 ${OUTDIR}/${DEMO}

${DEMO32}:	${DEMO}.c
	gcc ${CFLAGS32} -o ${OUTDIR}/${DEMO32} ${DEMO}.c
	sudo /bin/chown ${PWNUSR} ${OUTDIR}/${DEMO32}
	sudo /bin/chmod 4711 ${OUTDIR}/${DEMO32}


clean:
	rm -f ${OUTDIR}/${DEMO} ${OUTDIR}/${DEMO32}
