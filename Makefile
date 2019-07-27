CFLAGS=-g -Wall -pedantic 

OUTDIR=work
PDUMP=pdump

.PHONY: demo prep

ALL: 	prep ${PDUMP} demo

prep:
	mkdir -p work

demo:
	${MAKE} -C demo

${PDUMP}:	${PDUMP}.c ${PDUMP}.h
	gcc ${CFLAGS} -o ${OUTDIR}/${PDUMP} ${PDUMP}.c

clean:
	rm -f ${OUTDIR}/${PDUMP}
	${MAKE} -C demo clean
