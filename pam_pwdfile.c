/* pam_pwdfile.c copyright 1999 by Charl P. Botha <cpbotha@ieee.org>
 *
 * $Id: pam_pwdfile.c,v 1.1.1.1 1999-08-05 13:09:07 cpbotha Exp $
 * 
 * pam authentication module that can be pointed at any username/crypted
 * text file so that pam using application can use an alternate set of
 * passwords than specified in system password database
 *
 * Copyright (c) Charl P. Botha, 1999. All rights reserved
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

#ifndef LINUX 
#include <security/pam_appl.h>
#endif  /* LINUX */

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define _XOPEN_SOURCE
#include <unistd.h>

/* unistd.h does not declare this as it should */
extern char *crypt(const char *key, const char *salt);

#define PWDF_PARAM "pwdfile"
#define PWDFN_LEN 256
#define CRYPTEDPWD_LEN 13

#ifdef DEBUG
# define D(a) a;
#else
# define D(a) {}
#endif

/* prototypes */
int converse(pam_handle_t *, int, struct pam_message **, struct pam_response **);
int _set_auth_tok(pam_handle_t *, int, int, const char **);

/* logging function ripped from pam_listfile.c */
static void _pam_log(int err, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    openlog("pam_pwdfile", LOG_CONS|LOG_PID, LOG_AUTH);
    vsyslog(err, format, args);
    va_end(args);
    closelog();
}

/* this function ripped from pam_unix/support.c */
int converse(	pam_handle_t *pamh,
		int nargs, 
		struct pam_message **message,
		struct pam_response **response	)

{
	int retval;
	struct pam_conv *conv;

	retval = pam_get_item(	pamh, PAM_CONV,  (const void **) &conv ) ; 
	if ( retval == PAM_SUCCESS )
		{
	  		retval = conv->conv( 	nargs,  
	  					( const struct pam_message ** ) message, 
	  					response, 
	  					conv->appdata_ptr );
     		}
	return retval;
}

/* this function ripped from pam_unix/support.c */
int _set_auth_tok(	pam_handle_t *pamh, 
			int flags, int argc, 
			const char **argv	) {
	int	retval;
	char	*p;
	
	struct pam_message msg[1],*pmsg[1];
	struct pam_response *resp;

	/* set up conversation call */

	pmsg[0] = &msg[0];
	msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
	msg[0].msg = "Password: ";
	resp = NULL;

	if ( ( retval = converse( pamh, 1 , pmsg, &resp ) ) != PAM_SUCCESS ) 
		return retval;

	if ( resp ) 
		{
			if ( ( flags & PAM_DISALLOW_NULL_AUTHTOK ) && 
							resp[0].resp == NULL ) 
		       		{
					free( resp );
					return PAM_AUTH_ERR;
		  		}

			p = resp[ 0 ].resp;
			
			/* This could be a memory leak. If resp[0].resp 
			   is malloc()ed, then it has to be free()ed! 
			   	-- alex 
			*/
			
		  	resp[ 0 ].resp = NULL; 		  				  

	     	} 
	else 
		return PAM_CONV_ERR;

	free( resp );
	pam_set_item( pamh, PAM_AUTHTOK, p );
	return PAM_SUCCESS;
}


/* puts the crypted password corresponding to user "name" in password,
 * from a file with lines consisting of: name:crypted_password
 * if unsucessful, returns 0
 */
static int fgetpwnam(FILE *stream, const char *name, char *password) {
  char tempLine[256], *tpointer, *curname, *curpass, *fgr;
  int loopdone, pwdfound;
  
  /* go to beginning of file */
  rewind(stream);
  /* some control variables */
  loopdone = pwdfound = 0;
  /* iterate through lines in file, until end of file */
  do {
    /* get the current line */
    fgr = fgets(tempLine,256,stream);
    /* if it's valid, go on */
    if ( fgr != NULL) {
      /* first get the username out */
      tpointer = tempLine;
      curname = strsep(&tpointer,":");
      /* check to see if it's the right one */
      if (strcmp(curname,name)==0) {
	/* at least we know our loop is done */
	loopdone = 1;
	/* get the password and put it in its place */
	curpass = strsep(&tpointer,":");
	if (curpass != NULL) {
	  strncpy(password,curpass,CRYPTEDPWD_LEN+1);
	  pwdfound = 1;
	} /* if (curpass... */
      } /* if (strcmp(curname... */
    } /* if (tempLine... */
  } while (fgr != NULL);
  return pwdfound;
}

/* expected hook for auth service */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
				   int argc, const char **argv) {
  int retval, pcnt, pwdfilename_found, loopdone;
  const char *name;
  char *password;
  char pwdfilename[PWDFN_LEN];
  char salt[3], crypted_password[CRYPTEDPWD_LEN+1];
  FILE *pwdfile;

  /* we require the pwdfile switch and argument to be present, else we don't work */
  /* pcnt is the parameter counter variable for iterating through argv
   * loopdone is an extra loop control variable */
  pcnt = loopdone = pwdfilename_found = 0;
  do {
    /* see if the current parameter looks like "pwdfile" */
    if (strcmp(argv[pcnt],PWDF_PARAM)==0) {
      /* if argv is long enough, grab the subsequent parameter */
      if (pcnt+1 < argc) {
	/* make sure we can't overflow */
	strncpy(pwdfilename,argv[pcnt+1],PWDFN_LEN);
	/* indicate that we've found it */
	pwdfilename_found = 1;
      }
      /* whether we actually found the name or not, this loop is done,
       * as we have found the pwdfile switch itself */
      loopdone = 1;
    }
  } while (!loopdone && pcnt++ < argc);
  
  /* for some or other reason, the password file wasn't specified */
  if (!pwdfilename_found) {
    _pam_log(LOG_ERR,"password file name not specified");
    return PAM_AUTHINFO_UNAVAIL;
  }
  
  /* DEBUG */
  D(_pam_log(LOG_ERR, "password filename extracted"));
  
  /* now try to open the password file */
  if ((pwdfile=fopen(pwdfilename,"r"))==NULL) {
    _pam_log(LOG_ERR,"couldn't open password file %s",pwdfilename);
    return PAM_AUTHINFO_UNAVAIL;
  }
  
  /* get user name */
  if ((retval = pam_get_user(pamh,&name,"login: ")) != PAM_SUCCESS) {
    _pam_log(LOG_ERR, "username not found");
    fclose(pwdfile);
    return retval;
  }
  
  /* DEBUG */
  D(_pam_log(LOG_ERR,"username is %s", name));

  /* get password - code from pam_unix_auth.c */
  pam_get_item(pamh, PAM_AUTHTOK, (void *)&password);
  if (!password) {
    retval = _set_auth_tok(pamh, flags, argc, argv);
    if (retval!=PAM_SUCCESS) {
      fclose(pwdfile);
      return retval;
    }
  }
  pam_get_item(pamh, PAM_AUTHTOK, (void *)&password);

  if ((retval = pam_get_item(pamh, PAM_AUTHTOK, (void *)&password)) != PAM_SUCCESS) {
    _pam_log(LOG_ERR, "auth token not found");
    fclose(pwdfile);
    return retval;
  }
  
  /* DEBUG */
  D(_pam_log(LOG_ERR,"got password from user", password));
  
  /* now crypt password and compare to the user entry in the password file */
  /* first make sure password is long enough -- may I do this? */
  if (strlen(password)<2 || password==NULL) {
    _pam_log(LOG_ERR,"password too short or NULL");
    fclose(pwdfile);
    return PAM_AUTH_ERR;
  }
  
  /* get the crypted password corresponding to this user */
  if (!fgetpwnam(pwdfile, name, crypted_password)) {
    _pam_log(LOG_ERR,"password file corrupt");
    fclose(pwdfile);
    return PAM_AUTHINFO_UNAVAIL;
  }
  
  /* DEBUG */
  D(_pam_log(LOG_ERR,"got crypted password == %s", crypted_password));
  
  /* extract the salt */
  salt[0] = crypted_password[0]; salt[1] = crypted_password[1]; salt[2] = '\0';
  
  /* DEBUG */
  D(_pam_log(LOG_ERR,"user password crypted is %s", crypt(password,salt)));
  
  /* if things don't match up, complain */
  crypted_password[CRYPTEDPWD_LEN] = '\0';
  if (strcmp(crypt(password,salt),crypted_password)!=0) {
    _pam_log(LOG_ERR,"wrong password for user %s",name);
    fclose(pwdfile);
    return PAM_AUTH_ERR;
  }

  /* DEBUG */
  D(_pam_log(LOG_ERR,"passwords match"));
  
  /* we've gotten here, i.e. authentication was sucessful! */
  fclose(pwdfile);
  return PAM_SUCCESS;
}

/* another expected hook */
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
