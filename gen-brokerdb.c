#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <Buffer.h>

#include "NAAAIM.h"
#include "OrgID.h"
#include "DBduct.h"


static void do_organization(const DBduct const keydb, \
			    const DBduct const iddb, const OrgID const orgidx)

{
	return;
}


static void do_provider(const DBduct const keydb, const DBduct const iddb, \
			const OrgID const orgid)

{
	auto _Bool retn = false;

	auto char *p,
		  query[256],
		  orgkey[65],
		  inbufr[512],
		  npi[11],
		  name[100],
		  class[10],
		  address[50],
		  city[50],
		  state[3],
		  zip[10],
		  phone[11],
		  taxonomy[20];

	auto unsigned int lp,
		          cnt = 0;

	auto Buffer bfp;
	
	snprintf(query, sizeof(query), "%s", "BEGIN");
	if ( !iddb->exec(iddb, query) ) {
		fputs("Failed transaction start\n", stderr);
		goto done;
	}

	while ( fgets(inbufr, sizeof(inbufr), stdin) != NULL ) {
		if ( (p = strchr(inbufr, '\n')) == NULL )
			*p = '\0';

		if ( (p = strtok(inbufr, "^")) == NULL )
			goto done;
		strcpy(npi, p);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		strcpy(name, p);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		strcpy(class, p);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		strcpy(address, p);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		strcpy(city, p);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		strcpy(state, p);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		strcpy(zip, p);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		strcpy(phone, p);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		strcpy(taxonomy, p);

		
		++cnt;
		snprintf(query, sizeof(query), "select orgkey from npi " \
			 "where number = %s\n", npi);

		if ( keydb->query(keydb, query) != 1 )
			goto done;
		orgid->create(orgid, keydb->get_element(keydb, 0, 0), npi);

		lp = 0;
		bfp = orgid->get_Buffer(orgid);
		memset(orgkey, '\0', sizeof(orgkey));
		p = orgkey;
		while ( lp < bfp->size(bfp) ) {
			sprintf(p + lp*2, "%02x", *(bfp->get(bfp)+lp));
			++lp;
		}
		orgid->reset(orgid);

		snprintf(query, sizeof(query), "insert into idmap values " \
			 "('%s', 1, nextval('idsequence'))", orgkey);
		if ( !iddb->exec(iddb, query) ) {
			fputs("Failed idmap insertion\n", stderr);
			goto done;
		}

		if ( (p = strchr(taxonomy, '\n')) != NULL )
			*p = '\0';
		snprintf(query, sizeof(query), "insert into idvalues values " \
			 "(currval('idsequence'), '%s', E'%s', '%s', '%s', "  \
			 "'%s', '%s', '%s', '%s')", name, class, address,     \
			 city, state,  zip, phone, taxonomy);
		if ( !iddb->exec(iddb, query) ) {
			fputs("Failed idvalue table insertion.\n", stderr);
			fprintf(stdout, "%d: insert = %s\n", cnt, query);
			goto done;
		}
	}

	snprintf(query, sizeof(query), "%s", "COMMIT");
	if ( !iddb->exec(iddb, query) ) {
		fputs("Failed transaction start\n", stderr);
		goto done;
	}

	retn = true;


 done:
	if ( retn == false ) {
		fputs("Error on parsing.\n", stderr);
		fprintf(stdout, "%d Buffer: %s\n", cnt, inbufr);
		exit(1);
	}

	return;
}


extern int main(int argc, char *argv[])

{
	auto _Bool provider	= false,
		   organization = false;

	auto int retn;

	auto OrgID orgid = NULL;

	auto DBduct keydb = NULL,
		    iddb  = NULL;


	while ( (retn = getopt(argc, argv, "op")) != EOF )
		switch ( retn ) {
			case 'o':
				organization = true;
				break;
			case 'p':
				provider = true;
				break;
		}
	if ( !provider && !organization ) {
		fputs("No build type specified.\n", stderr);
		goto done;
	}


	/* Initialize organizational identity object. */
	if ( (orgid = NAAAIM_OrgID_Init()) == NULL ) {
		fputs("Failed organization object init.\n", stderr);
		goto done;
	}

	/* Initialize and open database connections. */
	if ( (keydb = NAAAIM_DBduct_Init()) == NULL ) {
		fputs("Failed to initialize database object.\n", stderr);
		goto done;
	}
	if ( !keydb->init_connection(keydb, "dbname=keys") ) {
		fputs("Failed to open keys database connection.\n", stderr);
		goto done;
	}

	if ( (iddb = NAAAIM_DBduct_Init()) == NULL ) {
		fputs("Failed to initialize database object.\n", stderr);
		goto done;
	}
	if ( !iddb->init_connection(iddb, "dbname=idbroker") ) {
		fputs("Failed to open idbroker database connection.\n", \
		      stderr);
		goto done;
	}


	if ( provider )
		do_provider(keydb, iddb, orgid);
	else
		do_organization(keydb, iddb, orgid);


 done:
	if ( orgid != NULL )
		orgid->whack(orgid);
	if ( keydb != NULL )
		keydb->whack(keydb);
	if ( iddb != NULL )
		iddb->whack(iddb);

	return retn;
}
