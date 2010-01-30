#define ORGID   "1234567890"
#define ORGANON "b5da47c67077b6104c0c2d01397e70c764449970a1518c660b511d86b7410ac2"
#define PTID	"000-00-0000"
#define PTIDKEY	"8310342c6fe343d9b54cf8363a78850aa58edc9b982899c946b081faad52aa5d"

#include <stdio.h>
#include <stdbool.h>

#include "NAAAIM.h"
#include "Buffer.h"
#include "OrgID.h"
#include "PatientID.h"


extern int main(int argc, char *argv[])

{
	auto OrgID orgid = NULL;

	auto PatientID ptid = NULL;


	if ( (orgid = NAAAIM_OrgID_Init()) == NULL ) {
		fputs("Failed OrgID object creation\n", stderr);
		goto done;
	}

	orgid->create(orgid, ORGANON, ORGID);
	fputs("OrgID:     ", stdout);
	orgid->print(orgid);


	if ( (ptid = NAAAIM_PatientID_Init()) == NULL ) {
		fputs("Failed PatientID object creation.\n", stderr);
		goto done;
	}

	ptid->create(ptid, orgid, PTIDKEY, PTID);
	fputs("PatientID: ", stdout);
	ptid->print(ptid);


 done:
	if ( orgid != NULL )
		orgid->whack(orgid);
	if ( ptid != NULL )
		ptid->whack(ptid);

	return 0;
}
