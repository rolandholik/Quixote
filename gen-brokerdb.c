#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "OrgID.h"
#include "DBduct.h"


static void do_organization(const DBduct const keydb, \
			    const DBduct const iddb, const OrgID const orgid)

{
	auto _Bool retn = false;

	auto char *p,
		  query[256],
		  orgkey[65],
		  inbufr[512];


	auto unsigned int lp,
		          cnt = 0;

	auto Buffer bfp,
		    npi,
		    name,
		    address,
		    city,
		    state,
		    zip,
		    phone,
		    taxonomy;


	/* Initialize field objects. */
	npi	 = HurdLib_Buffer_Init();
	name	 = HurdLib_Buffer_Init();
	address	 = HurdLib_Buffer_Init();
	city	 = HurdLib_Buffer_Init();
	state	 = HurdLib_Buffer_Init();
	zip	 = HurdLib_Buffer_Init();
	phone	 = HurdLib_Buffer_Init();
	taxonomy = HurdLib_Buffer_Init();

	if ( (npi == NULL) || (name == NULL) || (address == NULL) ||	\
	     (city == NULL) || (state == NULL) || (zip == NULL) || 	\
	     (phone == NULL) || (taxonomy == NULL) ) {
		fputs("Field object initialization failed.\n", stderr);
		goto done;
	}


	/* Start transaction to avoid auto-commit overhead. */
	snprintf(query, sizeof(query), "%s", "BEGIN");
	if ( !iddb->exec(iddb, query) ) {
		fputs("Failed transaction start\n", stderr);
		goto done;
	}

	while ( fgets(inbufr, sizeof(inbufr), stdin) != NULL ) {
		if ( (p = strchr(inbufr, '\n')) != NULL )
			*p = '\0';

		if ( (p = strtok(inbufr, "^")) == NULL )
			goto done;
		npi->add(npi, (unsigned char *) p, strlen(p)+1);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		name->add(name, (unsigned char *) p, strlen(p)+1);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		address->add(address, (unsigned char *) p, strlen(p)+1);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		city->add(city, (unsigned char *) p, strlen(p)+1);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		state->add(state, (unsigned char *) p, strlen(p)+1);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		zip->add(zip, (unsigned char *) p, strlen(p)+1);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		phone->add(phone, (unsigned char *) p, strlen(p)+1);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		taxonomy->add(taxonomy, (unsigned char *) p, strlen(p)+1);

		
		++cnt;
		snprintf(query, sizeof(query), "select orgkey from npi " \
			 "where number = %s\n", npi->get(npi));

		if ( keydb->query(keydb, query) != 1 )
			goto done;
		orgid->create(orgid, keydb->get_element(keydb, 0, 0), \
			      (char *) npi->get(npi));

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
			 "('%s', 2, nextval('idsequence'))", orgkey);
		if ( !iddb->exec(iddb, query) ) {
			fputs("Failed idmap insertion\n", stderr);
			goto done;
		}

		snprintf(query, sizeof(query), "insert into organization "    \
			 "values (currval('idsequence'), E'%s', E'%s', '%s', "\
			 "'%s', '%s', '%s', '%s')", name->get(name), 	      \
			 address->get(address), city->get(city),	      \
			 state->get(state), zip->get(zip), phone->get(phone), \
			 taxonomy->get(taxonomy));
		if ( !iddb->exec(iddb, query) ) {
			fputs("Failed organization table insertion.\n", \
			      stderr);
			fprintf(stdout, "buffer: %s\n", inbufr);
			fprintf(stdout, "%d: insert = %s\n", cnt, query);
			snprintf(query, sizeof(query), "%s", "COMMIT");
			iddb->exec(iddb, query);
			goto done;
		}
		if ( (cnt % 10000) == 0 )
			fprintf(stdout, "Add count: %d\n", cnt);

		npi->reset(npi);
		name->reset(name);
		address->reset(address);
		city->reset(city);
		state->reset(state);
		zip->reset(zip);
		phone->reset(phone);
		taxonomy->reset(taxonomy);
	}

	snprintf(query, sizeof(query), "%s", "COMMIT");
	if ( !iddb->exec(iddb, query) ) {
		fputs("Failed transcation commit.\n", stderr);
		goto done;
	}

	retn = true;


 done:
	if ( retn == false ) {
		fputs("Error on parsing.\n", stderr);
		fprintf(stdout, "%d Buffer: %s\n", cnt, inbufr);
		exit(1);
	}

	if ( npi != NULL )
		npi->whack(npi);
	if ( name != NULL )
		name->whack(name);
	if ( address != NULL )
		address->whack(address);
	if ( city != NULL )
		city->whack(city);
	if ( state != NULL )
		state->whack(state);
	if ( zip != NULL )
		zip->whack(zip);
	if ( phone != NULL )
		phone->whack(phone);
	if (taxonomy != NULL )
		taxonomy->whack(taxonomy);

	return;
}


static void do_provider(const DBduct const keydb, const DBduct const iddb, \
			const OrgID const orgid)

{
	auto _Bool retn = false;

	auto char *p,
		  query[256],
		  orgkey[65],
		  inbufr[512];


	auto unsigned int lp,
		          cnt = 0;

	auto Buffer bfp,
		    npi,
		    name,
		    class,
		    address,
		    city,
		    state,
		    zip,
		    phone,
		    taxonomy;


	/* Initialize field objects. */
	npi	 = HurdLib_Buffer_Init();
	name	 = HurdLib_Buffer_Init();
	class	 = HurdLib_Buffer_Init();
	address	 = HurdLib_Buffer_Init();
	city	 = HurdLib_Buffer_Init();
	state	 = HurdLib_Buffer_Init();
	zip	 = HurdLib_Buffer_Init();
	phone	 = HurdLib_Buffer_Init();
	taxonomy = HurdLib_Buffer_Init();

	if ( (npi == NULL) || (name == NULL) || (class == NULL) ||    	 \
	     (address == NULL) || (city == NULL) || (state == NULL) ||	 \
	     (zip == NULL) || (phone == NULL) || (taxonomy == NULL) ) {
		fputs("Field object initialization failed.\n", stderr);
		goto done;
	}



	/* Start transaction to avoid auto-commit overhead. */
	snprintf(query, sizeof(query), "%s", "BEGIN");
	if ( !iddb->exec(iddb, query) ) {
		fputs("Failed transaction start\n", stderr);
		goto done;
	}

	while ( fgets(inbufr, sizeof(inbufr), stdin) != NULL ) {
		if ( (p = strchr(inbufr, '\n')) != NULL )
			*p = '\0';

		if ( (p = strtok(inbufr, "^")) == NULL )
			goto done;
		npi->add(npi, (unsigned char *) p, strlen(p)+1);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		name->add(name, (unsigned char *) p, strlen(p)+1);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		class->add(class, (unsigned char *) p, strlen(p)+1);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		address->add(address, (unsigned char *) p, strlen(p)+1);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		city->add(city, (unsigned char *) p, strlen(p)+1);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		state->add(state, (unsigned char *) p, strlen(p)+1);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		zip->add(zip, (unsigned char *) p, strlen(p)+1);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		phone->add(phone, (unsigned char *) p, strlen(p)+1);

		if ( (p = strtok(NULL, "^")) == NULL )
			goto done;
		taxonomy->add(taxonomy, (unsigned char *) p, strlen(p)+1);

		
		++cnt;
		snprintf(query, sizeof(query), "select orgkey from npi " \
			 "where number = %s\n", npi->get(npi));

		if ( keydb->query(keydb, query) != 1 )
			goto done;
		orgid->create(orgid, keydb->get_element(keydb, 0, 0), \
			      (char *) npi->get(npi));

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

		snprintf(query, sizeof(query), "insert into provider values " \
			 "(currval('idsequence'), '%s', E'%s', E'%s', '%s', " \
			 "'%s', '%s', '%s', '%s')", name->get(name), 	      \
			 class->get(class), address->get(address),	      \
			 city->get(city), state->get(state), zip->get(zip),   \
			 phone->get(phone), taxonomy->get(taxonomy));
		if ( !iddb->exec(iddb, query) ) {
			fputs("Failed provider table insertion.\n", stderr);
			fprintf(stdout, "buffer: %s\n", inbufr);
			fprintf(stdout, "%d: insert = %s\n", cnt, query);
			snprintf(query, sizeof(query), "%s", "COMMIT");
			iddb->exec(iddb, query);
			goto done;
		}
		if ( (cnt % 10000) == 0 )
			fprintf(stdout, "Add count: %d\n", cnt);

		npi->reset(npi);
		name->reset(name);
		class->reset(class);
		address->reset(address);
		city->reset(city);
		state->reset(state);
		zip->reset(zip);
		phone->reset(phone);
		taxonomy->reset(taxonomy);
	}

	snprintf(query, sizeof(query), "%s", "COMMIT");
	if ( !iddb->exec(iddb, query) ) {
		fputs("Failed transcation commit.\n", stderr);
		goto done;
	}

	retn = true;


 done:
	if ( retn == false ) {
		fputs("Error on parsing.\n", stderr);
		fprintf(stdout, "%d Buffer: %s\n", cnt, inbufr);
		exit(1);
	}

	if ( npi != NULL )
		npi->whack(npi);
	if ( name != NULL )
		name->whack(name);
	if ( class != NULL )
		class->whack(class);
	if ( address != NULL )
		address->whack(address);
	if ( city != NULL )
		city->whack(city);
	if ( state != NULL )
		state->whack(state);
	if ( zip != NULL )
		zip->whack(zip);
	if ( phone != NULL )
		phone->whack(phone);
	if (taxonomy != NULL )
		taxonomy->whack(taxonomy);

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
