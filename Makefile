# $Id: Makefile,v 1.2 2001-04-17 21:16:12 cpbotha Exp $
#
# This Makefile controls a build process of $(TITLE) module for
# Linux-PAM. You should not modify this Makefile (unless you know
# what you are doing!).
#

include ../../Make.Rules

TITLE=pam_pwdfile

MODULE_SIMPLE_EXTRALIBS = -lcrypt

include ../Simple.Rules
