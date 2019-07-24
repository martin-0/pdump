CFLAGS32=-g -O0 -no-pie -m32
CFLAGS64=-g -O0 -no-pie 

OUTDIR=work

PDUMP=pdump
PDUMP32=pdump32

.PHONY:	prep demo

ALL: 	prep ${PDUMP} ${PDUMP32} demo

prep:
	mkdir work

demo:
	${MAKE} -C demo

${PDUMP}:	${PDUMP}.c ${PDUMP}.h
	gcc ${CFLAGS64} -o ${OUTDIR}/${PDUMP} ${PDUMP}.c

${PDUMP32}:	${PDUMP}.c ${PDUMP}.h
	gcc ${CFLAGS32} -o ${OUTDIR}/${PDUMP32} ${PDUMP32}.c

clean:
	rm -f ${OUTDIR}/${PDUMP} ${OUTDIR}/${PDUMP32}
	${MAKE} -C demo clean
