CFLAGS=-g 

OUTDIR=work
PDUMP=pdump

.PHONY:	prep demo

ALL: 	${PDUMP} demo

prep:
	mkdir -p work

demo:	prep
	${MAKE} -C demo

${PDUMP}:	${PDUMP}.c ${PDUMP}.h
	gcc ${CFLAGS64} -o ${OUTDIR}/${PDUMP} ${PDUMP}.c

clean:
	rm -f ${OUTDIR}/${PDUMP}
	${MAKE} -C demo clean
