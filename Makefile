all:		opt

opt:	opt.c
		gcc -I./lib -g -O2 -D_REENTRANT -w opt.c -o opt  -L/usr/local/lib -lpcap -lpthread

clean:
		rm opt
