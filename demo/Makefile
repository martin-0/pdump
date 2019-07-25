CFLAGS32=-g -O0 -pie -m32
CFLAGS64=-g -O0 -pie

OUTDIR=../work

DEMO=demo
DEMO32=demo32

PWNUSR=pwn

ALL:	${DEMO} ${DEMO32} perm

${DEMO}:	${DEMO}.c
	gcc ${CFLAGS64} -o ${OUTDIR}/${DEMO} ${DEMO}.c
	gcc ${CFLAGS64} -static -o ${OUTDIR}/${DEMO}S ${DEMO}.c
	

${DEMO32}:	${DEMO}.c
	gcc ${CFLAGS32} -o ${OUTDIR}/${DEMO32} ${DEMO}.c
	gcc ${CFLAGS32} -static -o ${OUTDIR}/${DEMO32}S ${DEMO}.c

perm:
	sudo /bin/chown ${PWNUSR} ${OUTDIR}/${DEMO}*
	sudo /bin/chmod 4711 ${OUTDIR}/${DEMO}*

clean:
	rm -f ${OUTDIR}/${DEMO} ${OUTDIR}/${DEMO32} ${OUTDIR}/${DEMO32}S ${OUTDIR}/${DEMO}S
