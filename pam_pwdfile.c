/* pam_pwdfile.c copyright 1999 by Charl P. Botha <cpbotha@ieee.org>
 *
 * $Id: pam_pwdfile.c,v 1.12 2001-05-12 09:59:45 cpbotha Exp $
 * 
 * pam authentication module that can be pointed at any username/crypted
 * text file so that pam using application can use an alternate set of
 * passwords than specified in system password database
 * 
 * version 0.8
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

#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <unistd.h>

#include <security/pam_appl.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

/* unistd.h does not declare this as it should */
extern char *crypt(const char *key, const char *salt);

#define PWDF_PARAM "pwdfile"
#define FLOCK_PARAM "flock"
#define PWDFN_LEN 256
#define CRYPTED_DESPWD_LEN 13
#define CRYPTED_MD5PWD_LEN 34

#ifdef DEBUG
# define D(a) a;
#else
# define D(a) {}
#endif

/* prototypes */
int converse(pam_handle_t *, int, struct pam_message **, struct pam_response **);
int _set_auth_tok(pam_handle_t *, int, int, const char **);

/* logging function ripped from pam_listfile.c */
static void _pam_log(int err, const char *format, ...) {
   va_list args;
   
   va_start(args, format);
   openlog("pam_pwdfile", LOG_CONS|LOG_PID, LOG_AUTH);
   vsyslog(err, format, args);
   va_end(args);
   closelog();
}

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

/* this function ripped from pam_unix/support.c */
int converse(	pam_handle_t *pamh,
		int nargs, 
		struct pam_message **message,
		struct pam_response **response	) {
   int retval;
   struct pam_conv *conv;
   
   retval = pam_get_item(	pamh, PAM_CONV,  (const void **) &conv ) ; 
   if ( retval == PAM_SUCCESS ) {
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
	       /* we use md5 pwd len, as this is just a safe maximum */
	       strncpy(password,curpass,CRYPTED_MD5PWD_LEN+1);
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
   int retval, pcnt, pwdfilename_found;
   const char *name;
   char *password;
   char pwdfilename[PWDFN_LEN];
   char salt[12], crypted_password[CRYPTED_MD5PWD_LEN+1];
   FILE *pwdfile;
   int use_flock = 0;

   /* we require the pwdfile switch and argument to be present, else we don't work */
   /* pcnt is the parameter counter variable for iterating through argv */
   pcnt = pwdfilename_found = 0;
   do {
      /* see if the current parameter looks like "pwdfile" */
      if (strcmp(argv[pcnt],PWDF_PARAM)==0) {
	 /* if argv is long enough, grab the subsequent parameter */
	 if (pcnt+1 < argc) {
	    /* make sure we can't overflow */
	    strncpy(pwdfilename,argv[++pcnt],PWDFN_LEN);
	    /* indicate that we've found it */
	    pwdfilename_found = 1;
	 }
	 /* also check for "pwdfile=blah" */
      } else if (strncmp(argv[pcnt],PWDF_PARAM "=",sizeof(PWDF_PARAM "=")-1)==0) {
	 /* make sure we can't overflow */
	 strncpy(pwdfilename,argv[pcnt]+sizeof(PWDF_PARAM),PWDFN_LEN);
	 /* indicate that we've found it */
	 pwdfilename_found = 1;
      } else if (strcmp(argv[pcnt],FLOCK_PARAM)==0) {
	 /* we have a "flock" parameter */
	 use_flock = 1;
      } else if (strcmp(argv[pcnt],"no" FLOCK_PARAM)==0) {
	 /* or a "noflock" parameter */
	 use_flock = 0;
      }

   } while (++pcnt < argc);
   
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
   
   /* set a lock on the password file */
   if (use_flock && lock_fd(fileno(pwdfile)) == -1) {
      _pam_log(LOG_ERR,"couldn't lock password file %s",pwdfilename);
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
      _pam_log(LOG_ERR,"user not found in password database");
      fclose(pwdfile);
      return PAM_AUTHINFO_UNAVAIL;
   }
   
   /* DEBUG */
   D(_pam_log(LOG_ERR,"got crypted password == %s", crypted_password));
   
   /* Extract the salt and set the passwd length, depending on MD5 or DES */
   if (strncmp(crypted_password, "$1$", 3) == 0) {
      strncpy(salt, crypted_password, 11);
      salt[11] = '\0';
      crypted_password[CRYPTED_MD5PWD_LEN] = '\0';
   } else {
      strncpy(salt, crypted_password, 2);
      salt[2] = '\0';
      crypted_password[CRYPTED_DESPWD_LEN] = '\0';      
   }
   
   /* DEBUG */
   D(_pam_log(LOG_ERR,"user password crypted is %s", crypt(password,salt)));
   
   /* if things don't match up, complain */
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
