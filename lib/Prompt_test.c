/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <HurdLib.h>
#include <String.h>

#include <NAAAIM.h>
#include "Prompt.h"


extern int main(int argc, char *argv[])

{
	_Bool pwdfail;

	String prompt = NULL,
	       verify = NULL,
	       phrase = NULL;

	Prompt pwd;


	INIT(HurdLib, String, phrase, ERR(goto done));
	INIT(HurdLib, String, verify, ERR(goto done));
	INIT(HurdLib, String, prompt, ERR(goto done));
	if ( !prompt->add(prompt, "Private key password: ") )
		ERR(goto done);
	if ( !verify->add(verify, "Verify - ") )
		ERR(goto done);

	INIT(NAAAIM, Prompt, pwd, ERR(goto done));

	if ( !pwd->get(pwd, prompt, verify, 10, phrase, &pwdfail) )
		ERR(goto done);

	if ( pwdfail )
		fputs("\nPassword entry failed.\n", stdout);
	else {
		fputs("\nPassphrase: ", stdout);
		phrase->print(phrase);
	}


 done:
	WHACK(prompt);
	WHACK(verify);
	WHACK(phrase);

	WHACK(pwd);

	return 0;
}
