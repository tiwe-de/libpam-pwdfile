PAM_LIB_DIR ?= /lib/security
INSTALL ?= install
CFLAGS ?= -O2 -g -Wall -Wformat-security

CPPFLAGS += -DUSE_CRYPT_R
CFLAGS += -fPIC -fvisibility=hidden
LDFLAGS += -Wl,-x -shared

TITLE = pam_pwdfile
LIBSHARED = $(TITLE).so
LDLIBS = -lcrypt -lpam
LIBOBJ = $(TITLE).o md5_broken.o md5_crypt_broken.o bigcrypt.o
CPPFLAGS_MD5_BROKEN = -DHIGHFIRST -D'MD5Name(x)=Broken\#\#x'


all: $(LIBSHARED)

$(LIBSHARED): $(LIBOBJ)
	$(CC) $(LDFLAGS) $(LIBOBJ) $(LDLIBS) -o $@


md5_broken.o: md5.c
	$(CC) -c $(CPPFLAGS) $(CPPFLAGS_MD5_BROKEN) $(CFLAGS) $< -o $@

md5_crypt_broken.o: md5_crypt.c
	$(CC) -c $(CPPFLAGS) $(CPPFLAGS_MD5_BROKEN) $(CFLAGS) $< -o $@


install: $(LIBSHARED)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(PAM_LIB_DIR)
	$(INSTALL) -m 0755 $(LIBSHARED) $(DESTDIR)$(PAM_LIB_DIR)

clean:
	$(RM) *.o *.so

changelog-from-git: changelog
	{ git log --decorate $(shell head -1 changelog | cut -d\  -f2).. | vipe; echo; cat changelog; } | sponge changelog
