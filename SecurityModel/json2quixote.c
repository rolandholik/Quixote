/** \file
 *
 * This file implements a utility for converting a JSON encoded TSEM
 * security event description stream into the encoding that is used
 * for the Quixote trust orchestrators.
 *
 * The utility takes a single argument, -i, that specifies the file
 * that holds the JSON encoded security event description stream.  If
 * no argument is specified stdin is used.
 */


#include <stdio.h>
#include <getopt.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>

#include "TSEMevent.h"


int main(int argc, char *argv[])

{
	char *input_file = "/dev/stdin";

	int opt,
	    retn = 1;

	String event = NULL;

	TSEMevent parser = NULL;

	File trajectory = NULL;


	while ( (opt = getopt(argc, argv, "i:")) != EOF )
		switch ( opt ) {
			case 'i':
				input_file = optarg;
				break;
		}


	/* Read and process file. */
	INIT(NAAAIM, TSEMevent, parser, ERR(goto done));
	INIT(HurdLib, String, event, ERR(goto done));

	INIT(HurdLib, File, trajectory, ERR(goto done));
	if ( !trajectory->open_ro(trajectory, input_file) )
		ERR(goto done);

	while ( trajectory->read_String(trajectory, event) ) {
		if ( !parser->set_event(parser, event) )
			ERR(goto done);
		if ( !parser->extract_event(parser) )
			ERR(goto done);

		event->reset(event);
		if ( !parser->encode_event(parser, event) )
			ERR(goto done);
		event->print(event);

		event->reset(event);
		parser->reset(parser);
	}

	retn = 0;


 done:
	WHACK(event);
	WHACK(parser);
	WHACK(trajectory);

	return retn;
}
