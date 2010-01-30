#define ORGID   "1234567890"
#define ORGANON "b5da47c67077b6104c0c2d01397e70c764449970a1518c660b511d86b7410ac2"

#include <stdio.h>
#include <stdbool.h>

#include "NAAAIM.h"
#include "Buffer.h"
#include "OrgID.h"


extern int main(int argc, char *argv[])

{
	auto OrgID orgid;


	if ( (orgid = NAAAIM_OrgID_Init()) == NULL ) {
		fputs("Failed OrgID object creation\n", stderr);
		return 1;
	}

	orgid->create(orgid, ORGANON, ORGID);
	orgid->print(orgid);

	orgid->whack(orgid);
	return 0;
}
