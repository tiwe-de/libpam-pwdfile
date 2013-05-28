/*
 * This function implements the "bigcrypt" algorithm specifically for
 * Linux-PAM.
 *  
 * This algorithm is algorithm 0 (default) shipped with the C2 secure
 * implementation of Digital UNIX.
 * 
 * Disclaimer: This work is not based on the source code to Digital
 * UNIX, nor am I connected to Digital Equipment Corp, in any way
 * other than as a customer. This code is based on published
 * interfaces and reasonable guesswork.
 * 
 * Description: The cleartext is divided into blocks of SEGMENT_SIZE=8
 * characters or less. Each block is encrypted using the standard UNIX
 * libc crypt function. The result of the encryption for one block
 * provides the salt for the suceeding block.
 * 
 * Restrictions: The buffer used to hold the encrypted result is
 * statically allocated. (see MAX_PASS_LEN below).  This is necessary,
 * as the returned pointer points to "static data that are overwritten
 * by each call", (XPG3: XSI System Interface + Headers pg 109), and
 * this is a drop in replacement for crypt();
 *
 * Andy Phillips <atp@mssl.ucl.ac.uk>
 */

#define _XOPEN_SOURCE 700
#include <unistd.h>
#include <string.h>

#include "bigcrypt.h"

/*
 * Max cleartext password length in segments of 8 characters this
 * function can deal with (16 segments of 8 chars= max 128 character
 * password).
 */

#define MAX_SEGMENTS       16
#define SEGMENT_SIZE       8
#define SALT_SIZE          2
#define ESEGMENT_SIZE      11

char *bigcrypt(char const * key, char const * salt) {
	static char outbuf[MAX_SEGMENTS * ESEGMENT_SIZE + SALT_SIZE + 1];	/* static storage area */

	unsigned char n_seg, seg;
	char * outptr;

	/* ensure NUL-termination */
	memset(outbuf, 0, sizeof(outbuf));

	if (strlen(salt) == (SALT_SIZE + ESEGMENT_SIZE)) /* conventional crypt */
		n_seg = 1;
	else if (key[0] == '\0')
		n_seg = 1;
	else
		n_seg = (strnlen(key, MAX_SEGMENTS * SEGMENT_SIZE) + SEGMENT_SIZE - 1) / SEGMENT_SIZE;

	/* first block is special and just traditional crypt() */
	outptr = outbuf;
	strncpy(outptr, crypt(key, salt), SALT_SIZE + ESEGMENT_SIZE);

	for (seg = 1, outptr += SALT_SIZE; seg < n_seg; ++seg) {
		/* subsequent blocks use the previous output block for salt input */
		salt = outptr;
		key += SEGMENT_SIZE;
		outptr += ESEGMENT_SIZE;
		/* and omit the salt on output */
		strncpy(outptr, crypt(key, salt) + SALT_SIZE, ESEGMENT_SIZE);
	}

	return outbuf;
}
