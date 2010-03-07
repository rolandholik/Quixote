#include <stdio.h>

#include "DBduct.h"


extern int main(int argc, char *argv[])

{
	auto int retn = 1;

	auto unsigned int result;

	auto DBduct db = NULL;


	/* Initialize the connection object and then open a connection. */
	if ( (db = NAAAIM_DBduct_Init()) == NULL ) {
		fputs("Cannot initialize database duct.\n", stderr);
		goto done;
	}

	if ( !db->init_connection(db, "dbname=keys") ) {
		fputs("Cannot open connection.\n", stderr);
		goto done;
	}

	if ( (result = db->query(db, "select * from npi limit 0")) == -1 ) {
		fputs("Failed query.\n", stderr);
		goto done;
	}
	
	fprintf(stdout, "Query resulted in %d %s.\n", result, \
		result == 1 ? "row" : "rows");
	if ( result > 0 )
		db->print(db);

	retn = 0;

 done:
	if ( db != NULL )
		db->whack(db);

	return retn;
}
