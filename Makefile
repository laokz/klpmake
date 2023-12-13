all:
	gcc -g -o klpsrc -I/root/include klpsrc.c sympos.c argument.c -L/root/lib -lclang -ldwarf
	gcc -o fixklp fixklp.c -lelf
