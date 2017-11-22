#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <SHA256.h>

#include "ISOidentity-interface.h"
#include "regex.h"
#include "ExchangeEvent.h"


void update_model(char *update)

{
	Buffer bufr = NULL;

	String entry = NULL;

	ExchangeEvent event = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	INIT(HurdLib, String, entry, ERR(goto done));
	if ( !entry->add(entry, update) )
		ERR(goto done);
	entry->print(entry);
	fputc('\n', stdout);


	INIT(NAAAIM, ExchangeEvent, event, ERR(goto done));

	if ( !event->parse(event, entry) )
		ERR(goto done);
	if ( !event->measure(event) )
		ERR(goto done);
	event->dump(event);
	fputc('\n', stdout);


done:
	WHACK(bufr);
	WHACK(entry);
	WHACK(event);

	return;
}
