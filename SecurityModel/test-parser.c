#define  EVENT "{\"export\": {\"type\": \"event\"}, \"event\": {\"pid\": \"1095\", \"process\": \"runc\", \"filename\": \"/opt/Quixote/bin/runc\", \"type\": \"mmap_file\", \"task_id\": \"9bfaba4da8210d41b2bc5faf6c2c2fce348b9018035bf8d08a8aea721bc302dc\"}, \"COE\": {\"uid\": \"0\", \"euid\": \"0\", \"suid\": \"0\", \"gid\": \"0\", \"egid\": \"0\", \"sgid\": \"0\", \"fsuid\": \"0\", \"fsgid\": \"0\", \"cap\": \"0x1ffffffffff\"}, \"mmap_file\": {\"type\": \"0\", \"reqprot\": \"1\", \"prot\": \"1\", \"flags\": \"1048578\"}, \"file\": {\"flags\": \"32800\", \"uid\": \"2\", \"gid\": \"2\", \"mode\": \"0100755\", \"name_length\": \"21\", \"name\": \"4829ead93d026770746f9cdebc76cc4d2a27f45db2d3ac436aa6fce4e2640415\", \"s_magic\": \"ef536200250\", \"s_id\": \"xvda\", \"s_uuid\": \"feadbeaffeadbeaffeadbeaffeadbeaf\", \"digest\": \"7c1a43eb99fa739056d6554001d450ca1c9c184ca7e2d8a785bd1e5fd53bad8c\"}}"


#include <stdio.h>
#include <getopt.h>

#include <HurdLib.h>
#include <String.h>

#include <NAAAIM.h>

#include "TSEMevent.h"


int main(int argc, char *argv[])

{
	char *descn = EVENT;

	int opt,
	    retn = 1;

	String event = NULL,
	       value = NULL;

	TSEMevent parser = NULL;

	while ( (opt = getopt(argc, argv, "e:")) != EOF )
		switch ( opt ) {
			case 'e':
				descn = optarg;
				break;
		}


	INIT(HurdLib, String, value, ERR(goto done));
	INIT(HurdLib, String, event, ERR(goto done));
	if ( !event->add(event, descn) )
		ERR(goto done);


	INIT(NAAAIM, TSEMevent, parser, ERR(goto done));
	if ( !parser->set_event(parser, event) )
		ERR(goto done);

	switch ( parser->extract_export(parser) ) {
		case TSEM_EVENT_AGGREGATE:
			if ( !parser->get_text(parser, "value", value) )
				ERR(goto done);
			fputs("aggregate: ", stdout);
			value->print(value);
			break;

		case TSEM_EVENT_EVENT:
			if ( !parser->encode_event(parser, value) )
				ERR(goto done);
			value->print(value);
			break;
			
		case TSEM_EVENT_LOG:
		case TSEM_EVENT_UNKNOWN:
			break;
	}

	retn = 0;


 done:
	WHACK(event);
	WHACK(value);
	WHACK(parser);

	return retn;
}
