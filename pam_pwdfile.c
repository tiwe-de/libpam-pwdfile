/* pam_pwdfile.c copyright 1999-2003 by Charl P. Botha <cpbotha@ieee.org>
 *
 * pam authentication module that can be pointed at any username/crypted
 * text file so that pam using application can use an alternate set of
 * passwords than specified in system password database
 * 
 * Copyright (c) Charl P. Botha, 1999-2003. All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 * 
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef USE_CRYPT_R
#define _GNU_SOURCE
#include <crypt.h>
#else
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#endif

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <unistd.h>
#include <syslog.h>

#include <security/pam_appl.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include "md5.h"
#include "bigcrypt.h"

static int lock_fd(int fd) {
    int delay;
    
    for (delay = 5; delay <= 40; delay *= 2) {
	if (flock(fd, LOCK_SH | LOCK_NB) == -1) {
	    /* failed */
	    if (errno != EWOULDBLOCK) goto failed;
	    sleep(delay);
	}else{
	    return 0;
	}
    }
    if (flock(fd, LOCK_SH | LOCK_NB) != -1) return 0;
    failed:
    return -1;
}

/* expected hook for auth service */
__attribute__((visibility("default")))
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
				   int argc, const char **argv) {
    int i;
    const char *name;
    char const * password;
    char const * pwdfilename = NULL;
    char const * stored_crypted_password = NULL;
    char const * crypted_password;
    FILE *pwdfile;
    int use_flock = 0;
    int use_delay = 1;
    int legacy_crypt = 0;
    int debug = 0;
    char * linebuf = NULL;
    size_t linebuflen;
#ifdef USE_CRYPT_R
    struct crypt_data crypt_buf;
#endif
    
    /* we require the pwdfile switch and argument to be present, else we don't work */
    for (i = 0; i < argc; ++i) {
	if (!strcmp(argv[i], "pwdfile") && i + 1 < argc)
	    pwdfilename = argv[++i];
	else if (!strncmp(argv[i], "pwdfile=", strlen("pwdfile=")))
	    pwdfilename = argv[i] + strlen("pwdfile=");
	else if (!strcmp(argv[i], "flock"))
	    use_flock = 1;
	else if (!strcmp(argv[i], "noflock"))
	    use_flock = 0;
	else if (!strcmp(argv[i], "nodelay"))
	    use_delay = 0;
	else if (!strcmp(argv[i], "debug"))
	    debug = 1;
	else if (!strcmp(argv[i], "legacy_crypt"))
	    legacy_crypt = 1;
    }
    
#ifdef HAVE_PAM_FAIL_DELAY
    if (use_delay) {
	if (debug) pam_syslog(pamh, LOG_DEBUG, "setting fail delay");
	(void) pam_fail_delay(pamh, 2000000);   /* 2 sec */
    }
#endif
    
    if (!pwdfilename) {
	pam_syslog(pamh, LOG_ERR, "password file name not specified");
	return PAM_AUTHINFO_UNAVAIL;
    }
    
    if (pam_get_user(pamh, &name, NULL) != PAM_SUCCESS) {
	pam_syslog(pamh, LOG_ERR, "couldn't get username from PAM stack");
	return PAM_AUTH_ERR;
    }
    if (debug) pam_syslog(pamh, LOG_DEBUG, "username is %s", name);
    
    if (!(pwdfile = fopen(pwdfilename, "r"))) {
	pam_syslog(pamh, LOG_ALERT, "couldn't open password file %s", pwdfilename);
	return PAM_AUTHINFO_UNAVAIL;
    }
    
    if (use_flock && lock_fd(fileno(pwdfile)) == -1) {
	pam_syslog(pamh, LOG_ALERT, "couldn't lock password file %s", pwdfilename);
	fclose(pwdfile);
	return PAM_AUTHINFO_UNAVAIL;
    }
    
    /* get the crypted password corresponding to this user out of pwdfile */
    while (getline(&linebuf, &linebuflen, pwdfile) > 0) {
	/* strsep changes its argument, make a copy */
	char * nexttok = linebuf;
	
	/* first field: username */
	char * curtok = strsep(&nexttok, ":");
	
	/* skip non-matching usernames */
	if (strcmp(curtok, name))
	    continue;
	
	/* second field: password (until next colon or newline) */
	if ((curtok = strsep(&nexttok, ":\n"))) {
	    stored_crypted_password = curtok;
	    break;
	}
    }
    fclose(pwdfile);
    /* we keep linebuf (allocated by getline), stored_crypted_password is pointing into it */

    if (!stored_crypted_password)
	if (debug) pam_syslog(pamh, LOG_ERR, "user not found in password database");
    
    if (stored_crypted_password && !strlen(stored_crypted_password)) {
	if (debug) pam_syslog(pamh, LOG_DEBUG, "user has empty password field");
	free(linebuf);
	return flags & PAM_DISALLOW_NULL_AUTHTOK ? PAM_AUTH_ERR : PAM_SUCCESS;
    }
    
    if (pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL) != PAM_SUCCESS) {
	pam_syslog(pamh, LOG_ERR, "couldn't get password from PAM stack");
	free(linebuf);
	return PAM_AUTH_ERR;
    }
    
    if (!stored_crypted_password) {
	free(linebuf);
	return PAM_USER_UNKNOWN;
    }
    
    if (debug) pam_syslog(pamh, LOG_DEBUG, "got crypted password == '%s'", stored_crypted_password);
    
#ifdef USE_CRYPT_R
    crypt_buf.initialized = 0;
    if (!(crypted_password = crypt_r(password, stored_crypted_password, &crypt_buf)))
#else
    if (!(crypted_password = crypt(password, stored_crypted_password)))
#endif
    {
	pam_syslog(pamh, LOG_ERR, "crypt() failed");
	free(linebuf);
	return PAM_AUTH_ERR;
    }
    
    if (legacy_crypt && strcmp(crypted_password, stored_crypted_password)) {
	if (!strncmp(stored_crypted_password, "$1$", 3))
	    crypted_password = Brokencrypt_md5(password, stored_crypted_password);
	else
	    crypted_password = bigcrypt(password, stored_crypted_password);
    }

    if (strcmp(crypted_password, stored_crypted_password)) {
	pam_syslog(pamh, LOG_NOTICE, "wrong password for user %s", name);
	free(linebuf);
	return PAM_AUTH_ERR;
    }
    
    if (debug) pam_syslog(pamh, LOG_DEBUG, "passwords match");
    free(linebuf);
    return PAM_SUCCESS;
}

/* another expected hook */
__attribute__((visibility("default")))
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, 
			      int argc, const char **argv)
{
    return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_listfile_modstruct = {
    "pam_pwdfile",
	pam_sm_authenticate,
	pam_sm_setcred,
	NULL,
	NULL,
	NULL,
	NULL,
};
#endif
/* vim:set ts=8 sw=4: */
