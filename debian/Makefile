# Modified Makefile to allow for building of the standalone module

TITLE=pam_pwdfile

CC = gcc
LD = gcc
CFLAGS += -fPIC -c -g -Wall -Wformat-security -fvisibility=hidden
LDFLAGS += -Wl,-x --shared
LDLIBS = -lcrypt -lpam
LIBOBJ = $(TITLE).o md5_good.o md5_broken.o md5_crypt_good.o md5_crypt_broken.o bigcrypt.o
LIBSHARED = $(TITLE).so

all: $(LIBSHARED)

md5_good.o: md5.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -DHIGHFIRST -D'MD5Name(x)=Good##x' \
		$(TARGET_ARCH) $< -o $@

md5_broken.o: md5.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -D'MD5Name(x)=Broken##x' \
		$(TARGET_ARCH) $< -o $@

md5_crypt_good.o: md5_crypt.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -D'MD5Name(x)=Good##x' \
		$(TARGET_ARCH) $< -o $@

md5_crypt_broken.o: md5_crypt.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -D'MD5Name(x)=Broken##x' \
		$(TARGET_ARCH) $< -o $@

$(LIBSHARED): $(LIBOBJ)
	$(LD) $(LDFLAGS) -o $@ $(LIBOBJ) $(LDLIBS)

clean:
	rm -f $(LIBOBJS) $(LIBSHARED) core *~

extraclean: clean
	rm -f *.a *.o *.so *.bak

