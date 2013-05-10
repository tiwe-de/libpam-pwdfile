/* pam_pwdfile.c copyright 1999-2003 by Charl P. Botha <cpbotha@ieee.org>
 *
 * $Id: pam_pwdfile.c,v 1.18 2003-12-20 19:21:19 cpbotha Exp $
 * 
 * pam authentication module that can be pointed at any username/crypted
 * text file so that pam using application can use an alternate set of
 * passwords than specified in system password database
 * 
 * version 0.99
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

#include <features.h>
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

#define CRYPTED_DESPWD_LEN 13
#define CRYPTED_MD5PWD_LEN 34
#define CRYPTED_BCPWD_LEN 178

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

/* puts the crypted password corresponding to user "name" in password,
 * from a file with lines consisting of: name:crypted_password
 * if unsucessful, returns 0
 */
static int fgetpwnam(FILE *stream, const char *name, char *password) {
    char * linebuf = NULL;
    size_t linebuflen;
    int pwdfound = 0;
    
    /* iterate through lines in file, until end of file */
    while (getline(&linebuf, &linebuflen, stream) > 0) {
	/* strsep changes its argument, make a copy */
	char * nexttok = linebuf;
	
	/* first field: username */
	char * curtok = strsep(&nexttok, ":");
	
	/* skip non-matchin usernames */
	if (strcmp(curtok, name))
	    continue;
	
	/* second field: password (until next colon or newline) */
	curtok = strsep(&nexttok, ":\n");
	
	if (curtok) {
	    /* we use bigcrypt pwd len, as this is just a safe maximum */
	    strncpy(password, curtok, CRYPTED_BCPWD_LEN + 1);
	    pwdfound = 1;
	    break;
	}
    }
    free(linebuf); /* allocated by getline */
    return pwdfound;
}

/* expected hook for auth service */
__attribute__((visibility("default")))
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
				   int argc, const char **argv) {
    int retval, i;
    const char *name;
    char const * password;
    char const * pwdfilename = NULL;
    char salt[12], stored_crypted_password[CRYPTED_BCPWD_LEN+1];
    char *crypted_password;
    FILE *pwdfile;
    int use_flock = 0;
    int use_delay = 1;
    int temp_result = 0;
    int debug = 0;
    
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
    
    if (debug) pam_syslog(pamh, LOG_DEBUG, "password filename extracted");
    
    /* now try to open the password file */
    if ((pwdfile=fopen(pwdfilename,"r"))==NULL) {
	pam_syslog(pamh, LOG_ALERT, "couldn't open password file %s", pwdfilename);
	return PAM_AUTHINFO_UNAVAIL;
    }
    
    if (use_flock && lock_fd(fileno(pwdfile)) == -1) {
	pam_syslog(pamh, LOG_ALERT, "couldn't lock password file %s", pwdfilename);
	return PAM_AUTHINFO_UNAVAIL;
    }
    
    /* get user name */
    if ((retval = pam_get_user(pamh, &name, NULL)) != PAM_SUCCESS) {
	pam_syslog(pamh, LOG_ERR, "username not found");
	fclose(pwdfile);
	return retval;
    }
    
    if (debug) pam_syslog(pamh, LOG_DEBUG, "username is %s", name);
    
    if ((retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL)) != PAM_SUCCESS) {
	pam_syslog(pamh, LOG_ERR, "auth token not found");
	fclose(pwdfile);
	return retval;
    }
    
    /* now crypt password and compare to the user entry in the password file */
    /* first make sure password is long enough -- may I do this? */
    if (strlen(password)<2 || password==NULL) {
	pam_syslog(pamh, LOG_ERR, "password too short or NULL");
	fclose(pwdfile);
	return PAM_AUTH_ERR;
    }
    
    /* get the crypted password corresponding to this user */
    if (!fgetpwnam(pwdfile, name, stored_crypted_password)) {
	pam_syslog(pamh, LOG_ERR, "user not found in password database");
	fclose(pwdfile);
	return PAM_AUTHINFO_UNAVAIL;
    }
    
    if (debug) pam_syslog(pamh, LOG_DEBUG, "got crypted password == '%s'", stored_crypted_password);
    
    
    temp_result = 0;
    
    /* Extract the salt and set the passwd length, depending on MD5 or DES */
    if (strncmp(stored_crypted_password, "$1$", 3) == 0) {
	if (debug) pam_syslog(pamh, LOG_ERR, "password hash type is 'md5'");
	/* get out the salt into "salt" */
	strncpy(salt, stored_crypted_password, 11);
	salt[11] = '\0';
	stored_crypted_password[CRYPTED_MD5PWD_LEN] = '\0';
	/* try both md5 crypts */
	crypted_password = Goodcrypt_md5(password, salt);
	if (strcmp(crypted_password, stored_crypted_password) == 0)
	{
	    temp_result = 1;
	}
	else
	{
	    crypted_password = Brokencrypt_md5(password, salt);
	    if (strcmp(crypted_password, stored_crypted_password) == 0)
	    {
		temp_result = 1;
	    }
	}
    } else {
	/* get the salt out into "salt" */
	strncpy(salt, stored_crypted_password, 2);
	salt[2] = '\0';
	stored_crypted_password[CRYPTED_BCPWD_LEN] = '\0';

	if (strlen(stored_crypted_password) <= CRYPTED_DESPWD_LEN) {
	    if (debug) pam_syslog(pamh, LOG_DEBUG, "password hash type is 'crypt'");
	    crypted_password = crypt(password, salt);
	} else {
	    if (debug) pam_syslog(pamh, LOG_DEBUG, "password hash type is 'bigcrypt'");
	    crypted_password = bigcrypt(password, salt);
	}

	if (strcmp(crypted_password, stored_crypted_password) == 0)
	{
	    temp_result = 1;
	}
    }
    
    if (debug) pam_syslog(pamh, LOG_DEBUG, "user password crypted is '%s'", crypted_password);
    
    /* if things don't match up, complain */
    if (!temp_result) 
    {
	pam_syslog(pamh, LOG_NOTICE, "wrong password for user %s", name);
	fclose(pwdfile);
	return PAM_AUTH_ERR;
    }
    
    if (debug) pam_syslog(pamh, LOG_DEBUG, "passwords match");
    
    /* we've gotten here, i.e. authentication was sucessful! */
    fclose(pwdfile);
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
