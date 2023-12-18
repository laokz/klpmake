all:
	gcc -g -o klpsrc klpsrc.c sympos.c argument.c -lclang -ldwarf
	gcc -o fixklp fixklp.c -lelf

clean:
	rm -f fixklp klpsrc
