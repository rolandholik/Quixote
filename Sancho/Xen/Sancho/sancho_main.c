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


/* Path to connection state variable. */
static const char *Connect_path = "backend/SanchoXen";

/* Shared page. */
static uint8_t *Shared_page;

static uint8_t *Shared_data;

static _Bool Have_event = false;

static _Bool Connected = false;


void sancho_event(evtchn_port_t vp, struct pt_regs *regs, void *page)

{
	uint32_t *size = page;


	if ( *size != 0 )
		Have_event = true;

	return;
}


static _Bool wait_for_connect(xenbus_event_queue *events)

{
	_Bool retn = false;

	char *error,
	     **connect,
	     *refstr = NULL;

	unsigned int lp,
		     remote_id;

	uint32_t *size;

	grant_ref_t grant;

	struct gntmap map;

	evtchn_port_t evp_remote,
		      evp_local = 0;


	/* Wait for grant reference value to start connection .*/
        connect = xenbus_wait_for_watch_return(events);
	printk("%s: Connect string: %s\n", __func__, *connect);

	if ( sscanf(*connect, "backend/SanchoXen/%u/grant-ref", \
		    &remote_id) != 1 ) {
		printk("%s: Cannot interpret connection string\n", __func__);
		goto done;
	}

	printk("%s: Remote id=%u\n", __func__, remote_id);


	if ( (error = xenbus_read(XBT_NIL, *connect, &refstr)) != NULL ) {
		printk("%s: Xenbus read domain failed: %s\n", __func__, error);
		free(error);
		goto done;
	}

	printk("%s: Grant reference: %s\n", __func__, refstr);
	grant = (unsigned int) strtol(refstr, NULL, 0);
	if ( errno == ERANGE) {
		fputs("Invalid grant reference.\n", stderr);
		goto done;
	}
	if ( (Shared_page = gntmap_map_grant_refs(&map, 1, &remote_id, 0, \
					   &grant,			  \
					   PROT_READ | PROT_WRITE)) == NULL ) {
		printk("%s: Failed grant mapping.\n", __func__);
		goto done;
	}

	printk("%s: Mapped buffer.\n", __func__);
	for (lp= 0; lp < 16; ++lp)
		printk("%02x", Shared_page[lp]);
	printk("\n");

	memset(Shared_page, '\0', 4096);
	Shared_data = Shared_page + sizeof(uint32_t);


	/* Obtain event channel. */
	printk("%s: Waiting for event.\n", __func__);
        connect = xenbus_wait_for_watch_return(events);
	printk("%s: Connect string: %s\n", __func__, *connect);

	if ( sscanf(*connect, "backend/SanchoXen/%u/event-channel", \
		    &remote_id) != 1 ) {
		printk("%s: Cannot interpret event channel\n", __func__);
		goto done;
	}

	printk("%s: Reading xenstore event: %s\n", __func__, *connect);
	if ( (error = xenbus_read(XBT_NIL, *connect, &refstr)) != NULL ) {
		printk("%s: Xenbus read event failed: %s\n", __func__, error);
		free(error);
		goto done;
	}

	printk("%s: Event channel: %s\n", __func__, refstr);
	evp_remote = (unsigned int) strtol(refstr, NULL, 0);
	if ( errno == ERANGE) {
		printk("%s: Invalid event channel.\n", __func__);
		goto done;
	}


	printk("%s: Binding remote: %u\n", __func__, evp_remote);
	if ( evtchn_bind_interdomain(remote_id, evp_remote, sancho_event, \
				     Shared_page, &evp_local) != 0 ) {
		printk("%s: Cannot bind event channel.\n", __func__);
		goto done;
	}

	printk("%s: Unmasking local port: %u\n", __func__, evp_local);
	unmask_evtchn(evp_local);

	printk("%s: Sending remote notification.\n", __func__);
	notify_remote_via_evtchn(evp_local);

	Connected = true;
	while ( Connected ) {
		if ( Have_event ) {
			size = (uint32_t *) Shared_page;
			printk("%s: Have event: %u\n", __func__, *size);

			if ( *size == 0xffffffff ) {
				printk("%s: Have disconnect.\n", __func__);
				Connected = false;
				continue;
			}

			printk("%s: Have write: %u\n", __func__, *size);
			*size *= 2;
			notify_remote_via_evtchn(evp_local);
			Have_event = false;
		}

		msleep(500);
	}

	printk("%s: Exiting handler.\n", __func__);
	retn = true;


 done:
	free(refstr);

	gntmap_munmap(&map, (long unsigned int) Shared_page, 1);

	if ( evp_local > 0 ) {
		mask_evtchn(evp_local);
		unbind_evtchn(evp_local);
	}

	return retn;
}


int main(int argc, char *argv[])

{
	_Bool retn = false;

	char *error,
	     *root,
	     **connect;

	xenbus_event_queue events = NULL;


	/* Initialize xenstore. */
	if ( (error = xenbus_read(XBT_NIL, "domid", &root)) != NULL ) {
		printk("%s: Xenbus read domain failed: %s\n", __func__, error);
		free(error);
		goto done;
	}
	printk("%s: Sancho root: %s\n", __func__, root);
	free(root);


	if ( (error = xenbus_watch_path_token(XBT_NIL, Connect_path,	 \
					      Connect_path, &events)) != \
	     NULL ) {
		printk("%s: Watch path token: %s\n", __func__, error);
		free(error);
		goto done;
	}

	connect = xenbus_wait_for_watch_return(&events);
	printk("%s: Return from first watch: %s\n", __func__, *connect);



	/* Wait for a valid connection. */
	printk("SanchoXen: Initialized.\n");

	while ( true ) {
		printk("Waiting for connection.\n");
		if ( !wait_for_connect(&events) )
			goto done;
	}


 done:
	return retn;
}
