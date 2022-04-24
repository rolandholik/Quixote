#include <stdint.h>
#include <errno.h>
#include <os.h>
#include <kernel.h>
#include <sched.h>
#include <string.h>
#include <console.h>
#include <netfront.h>
#include <pcifront.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#include <xenbus.h>
#include <events.h>
#include <shutdown.h>
#include <mini-os/lib.h>

#include <HurdLib.h>
#include <Buffer.h>

#include <NAAAIM.h>
#include <XENduct.h>

#include "sancho.h"


int main(int argc, char *argv[])

{
	_Bool retn = false;

	Buffer bufr = NULL;

	XENduct duct = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	INIT(NAAAIM, XENduct, duct, ERR(goto done));
	if ( !duct->init_device(duct, "backend/SanchoXen") )
		ERR(goto done);


	/* Invoke the interpreter on each connection. */
	while ( true ) {
		if ( !duct->accept_connection(duct) )
			ERR(goto done);
		sancho_interpreter(duct);
		duct->reset(duct);
	}


 done:
	WHACK(bufr);
	WHACK(duct);

	return retn;
}
