
CFLAGS = -I /usr/local/include/pteid -g
PAM_INCLUDE_FILES = $(foreach f, pam_modules.h pam_client.h _pam_macros.h, /usr/include/security/$(f))

all: pam_safebox.so

pam_safebox.so: pam_safebox.o CCkpubFile.o
	ld -o $@ -shared $^ -L /usr/local/lib -lpam -lm

CCkpubFile.o: CCkpubFile.c CCkpubFile.h
	$(CC) -o $@ -c -fPIC $*.c $(CFLAGS)

pam_safebox.o: pam_safebox.c CCkpubFile.h
	@for f in $(PAM_INCLUDE_FILES); do \
		if test ! -f $$f; then \
			echo "install libpam0g-dev with apt-get or with a similar tool"; \
			exit 1; \
		fi; \
	done; \
	echo $(CC) -o $@ -c -fPIC -fno-stack-protector $*.c $(CFLAGS); \
	$(CC) -o $@ -c -fPIC -fno-stack-protector $*.c $(CFLAGS)

install:
	strip pam_safebox.so
	cp pam_safebox.so /lib/security
	test -d /etc/CC || mkdir /etc/CC
	
clean:
	rm *.o addCCuser pam_safebox.so
