certcheck: certcheck.c
	gcc -o certcheck certcheck.c -lssl -lcrypto
clean:
	rm certcheck.o