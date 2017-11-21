#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <SHA256.h>

#include "ISOidentity-interface.h"
#include "regex.h"


static _Bool parse_field(char *update, char *fd, char *match, size_t len)

{
	_Bool retn = false;

        regex_t regex;

	regmatch_t regmatch[2];


	if ( regcomp(&regex, fd, REG_EXTENDED) != 0 )
		ERR(goto done);

	if ( regexec(&regex, update, 2, regmatch, 0) != REG_OK )
		ERR(goto done);

	memset(match, '\0', len);
	memcpy(match, update + regmatch[1].rm_so, \
	       regmatch[1].rm_eo - regmatch[1].rm_so);

	retn = true;


 done:
	return retn;
}


void update_model(char *update)

{
	char bufr[1024];


	if ( !parse_field(update, "event\\{([^}]*)\\}", bufr, sizeof(bufr)) )
		ERR(goto done);
	fprintf(stdout, "update: %s\n", bufr);

	if ( !parse_field(update, "actor\\{([^}]*)\\}", bufr, sizeof(bufr)) )
		ERR(goto done);
	fprintf(stdout, "actor: %s\n", bufr);

	if ( !parse_field(update, "subject\\{([^}]*)\\}", bufr, sizeof(bufr)) )
		ERR(goto done);
	fprintf(stdout, "subject: %s\n\n", bufr);


done:
	return;
}
