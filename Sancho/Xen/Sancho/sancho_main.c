#include <stdint.h>
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
#include <xenbus.h>
#include <events.h>
#include <shutdown.h>
#include <mini-os/lib.h>


int main(int argc, char *argv[])

{
	printk("This is SanchoXen\n");

	while ( 1 )
		continue;

	return 0;
}
