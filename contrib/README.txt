$Id: README.txt,v 1.3 2003-07-07 15:09:41 cpbotha Exp $

* Makefile.standalone-0.95 and pam-pwdfile.spec were contributed by Jason F.
  McBrayer <jason@xeran.com>.  You can use these for building RPMs of
  pam_pwdfile; you should also be able to use the Makefile to build
  pam_pwdfile on other platforms _without_ the Linux-PAM hierarchy.

* warwick_duncan-cyrus_without_system_accounts.txt is a short explanation by
  Warwick Duncan on how to get Cyrus IMAPD + pam_pwdfile to work WITHOUT
  having to create system accounts for IMAPD users.
  
* Makefile.standalone was contributed by Gerald Richter and should be more
  up to date than Makefile.standalone-0.95.  The primary difference is that
  Gerald's Makefile also takes into account the new md5 code.

