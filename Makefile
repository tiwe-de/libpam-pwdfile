# $Id: Makefile,v 1.4 2002-05-11 14:42:35 cpbotha Exp $
#
# This Makefile controls a build process of $(TITLE) module for
# Linux-PAM. You should not modify this Makefile (unless you know
# what you are doing!).
#

include ../../Make.Rules

TITLE=pam_pwdfile
CFLAGS += -D_BSD_SOURCE

md5_good.o: md5.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -DHIGHFIRST -D'MD5Name(x)=Good##x' \
		$(TARGET_ARCH) -c $< -o $@

md5_broken.o: md5.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -D'MD5Name(x)=Broken##x' \
		$(TARGET_ARCH) -c $< -o $@

md5_crypt_good.o: md5_crypt.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -D'MD5Name(x)=Good##x' \
		$(TARGET_ARCH) -c $< -o $@

md5_crypt_broken.o: md5_crypt.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -D'MD5Name(x)=Broken##x' \
		$(TARGET_ARCH) -c $< -o $@

##### The following mostly from Simple.Rules
#####  * modifications to first 5 definitions

LIBFILES = $(TITLE) bigcrypt
LIBSRC = $(addsuffix .c,$(LIBFILES)) md5.c md5_crypt.c
LIBOBJ = $(addsuffix .o,$(LIBFILES))
LIBOBJD = $(addprefix dynamic/,$(LIBOBJ)) md5_good.o md5_broken.o md5_crypt_good.o md5_crypt_broken.o
LIBOBJS = $(addprefix static/,$(LIBOBJ)) md5_good.o md5_broken.o md5_crypt_good.o md5_crypt_broken.o

ifdef DYNAMIC
LIBSHARED = $(TITLE).so
endif

ifdef STATIC
LIBSTATIC = lib$(TITLE).o
endif

####################### don't edit below #######################

all: dirs $(LIBSHARED) $(LIBSTATIC) register

dynamic/%.o : %.c
	$(CC) $(CFLAGS) $(DYNAMIC) $(TARGET_ARCH) -c $< -o $@

static/%.o : %.c
	$(CC) $(CFLAGS) $(STATIC) $(TARGET_ARCH) -c $< -o $@

dirs:
ifdef DYNAMIC
	$(MKDIR) ./dynamic
endif
ifdef STATIC
	$(MKDIR) ./static
endif

register:
ifdef STATIC
	( cd .. ; ./register_static $(TITLE) $(TITLE)/$(LIBSTATIC) )
endif

ifdef DYNAMIC
$(LIBOBJD): $(LIBSRC)
endif

ifdef DYNAMIC
$(LIBSHARED):	$(LIBOBJD)
	$(LD_D) -o $@ $(LIBOBJD) $(MODULE_SIMPLE_EXTRALIBS) $(NEED_LINK_LIB_C)

endif

ifdef STATIC
$(LIBOBJS): $(LIBSRC)
endif

ifdef STATIC
$(LIBSTATIC): $(LIBOBJS)
	$(LD) -r -o $@ $(LIBOBJS) $(MODULE_SIMPLE_EXTRALIBS)
endif

install: all
	$(MKDIR) $(FAKEROOT)$(SECUREDIR)
ifdef DYNAMIC
	$(INSTALL) -m $(SHLIBMODE) $(LIBSHARED) $(FAKEROOT)$(SECUREDIR)
endif
	$(MODULE_SIMPLE_INSTALL)

remove:
	rm -f $(FAKEROOT)$(SECUREDIR)/$(TITLE).so
	$(MODULE_SIMPLE_REMOVE)

clean:
	rm -f $(LIBOBJD) $(LIBOBJS) core *~
	$(MODULE_SIMPLE_CLEAN)
	rm -f *.a *.o *.so *.bak
	rm -rf dynamic static
	$(MODULE_SIMPLE_EXTRACLEAN)

.c.o:	
	$(CC) $(CFLAGS) -c $<


