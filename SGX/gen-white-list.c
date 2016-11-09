#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include "NAAAIM.h"


extern int main(int argc, char *argv[])

{
	_Bool retn = false;

	uint8_t *sp;

	size_t lp;

	Buffer bufr = NULL;

	File file = NULL;


	if (argc != 2) {
		fprintf(stderr, "%s: Specify white list name.\n", argv[0]);
		goto done;
	}

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, File, file, ERR(goto done));

	file->open_ro(file, argv[1]);
	if ( !file->slurp(file, bufr) )
		ERR(goto done);

	fputs("static uint8_t LE_white_list[] = {\n\t", stdout);

	sp = (uint8_t *) bufr->get(bufr);
	for (lp= 1; lp <= bufr->size(bufr); ++lp) {
		fprintf(stdout, "0x%02x", sp[lp-1]);
		if ( (lp % 8) == 0 ) {
			if ( lp == bufr->size(bufr) )
				fputs("  \\\n", stdout);
			else
				fputs(", \\\n\t", stdout);
		}
		else
			fputs(", ", stdout);
	}
	fputs("};\n", stdout);

	retn = true;


 done:
	WHACK(bufr);
	WHACK(file);

	return retn;
}
