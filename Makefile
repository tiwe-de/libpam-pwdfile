# $Id: Makefile,v 1.3 2001-07-14 20:50:21 cpbotha Exp $
#
# This Makefile controls a build process of $(TITLE) module for
# Linux-PAM. You should not modify this Makefile (unless you know
# what you are doing!).
#

include ../../Make.Rules

TITLE=pam_pwdfile
CFLAGS += -D_BSD_SOURCE

MODULE_SIMPLE_EXTRALIBS = -lcrypt

include ../Simple.Rules
