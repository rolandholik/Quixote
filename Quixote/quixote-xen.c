/** \file
 * This file implements a prototype utility for interrogaing a Xen
 * stubdomain based Sancho implementation.
 */

/**************************************************************************
 * Copyright (c) 2020, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <xenstore.h>
#include <xengnttab.h>
#include <xenevtchn.h>

#include <NAAAIM.h>


/*
 * Program entry point.
 */

extern int main(int argc, char *argv[])

{
	int opt,
	    retn = 1;

	unsigned int length,
		     sancho_id;

	char xspath[80],
	     xsvalue[80],
	     *domid = NULL;

	uint8_t *gntp = NULL;

	uint32_t *size,
	         gnt_refs,
		 marker = 0xfeadbeef;

	struct xs_handle *handle = NULL;

	struct xengntdev_handle *grant_handle = NULL;

	xenevtchn_port_or_error_t evp = -1;

	xenevtchn_handle *evh = NULL;


	while ( (opt = getopt(argc, argv, "s:")) != EOF )
		switch ( opt ) {
			case 's':
				domid = optarg;
				break;
		}


	/* Convert domain id to numeric value. */
	if ( domid == NULL ) {
		fputs("No Sancho domain specified.\n", stderr);
		goto done;
	}

	sancho_id = (unsigned int) strtol(domid, NULL, 0);
	if ( errno == ERANGE) {
		fputs("Invalid domain id specified.\n", stderr);
		domid = NULL;
		goto done;
	}
	domid = NULL;


	if ( (handle = xs_open(0)) == NULL ) {
		fputs("Error getting xenstore handle.\n", stderr);
		goto done;
	}

	if ( (domid = xs_read(handle, XBT_NULL, "domid", &length)) == NULL ) {
		fputs("Cannot read domain id.\n", stderr);
		goto done;
	}

	fprintf(stdout, "Domain id: %s\n", domid);


	/* Setup grant page access. */
	if ( (grant_handle = xengntshr_open(NULL, 0)) == NULL ) {
		fputs("Cannot obtain grant page handle.\n", stderr);
		goto done;
	}

	if ( (gntp = xengntshr_share_pages(grant_handle, sancho_id, 1, \
					   &gnt_refs, true)) == NULL ) {
		fputs("Cannot grant memory page.\n", stderr);
		goto done;
	}

	memset(gntp, '\0', 4096);
	memcpy(gntp, &marker, sizeof(marker));
	fprintf(stdout, "Shared page=%p, reference=%u\n", gntp, gnt_refs);


	/* Setup event channel. */
	if ( (evh = xenevtchn_open(NULL, 0)) == NULL ) {
		fputs("Cannot open event channel.\n", stderr);
		goto done;
	}

	if ( (evp = xenevtchn_bind_unbound_port(evh, sancho_id)) == -1 ) {
		fputs("Cannot setup event channel.\n", stderr);
		goto done;
	}

	fprintf(stdout, "Have event channel: %u\n", evp);
	fflush(stdout);


	/* Update SanchoXen xenstore with grant reference. */
	if ( snprintf(xspath, sizeof(xspath),				 \
		      "/local/domain/%u/backend/SanchoXen/%s/grant-ref", \
		      sancho_id, domid) >= sizeof(xspath) ) {
		fputs("Error building xenstore buffer.\n", stderr);
		goto done;
	}

	if ( snprintf(xsvalue, sizeof(xsvalue), "%0x", gnt_refs) >= \
	     sizeof(xsvalue) ) {
		fputs("Error building grant reference buffer.\n", stderr);
		goto done;
	}

	if ( !xs_write(handle, XBT_NULL, xspath, xsvalue, strlen(xsvalue)) ) {
		fputs("Error writing connection message.\n", stderr);
		goto done;
	}


	/* Update SanchoXen xenstore with event channel. */
	if ( snprintf(xspath, sizeof(xspath),				     \
		      "/local/domain/%u/backend/SanchoXen/%s/event-channel", \
		      sancho_id, domid) >= sizeof(xspath) ) {
		fputs("Error building xenstore buffer.\n", stderr);
		goto done;
	}

	if ( snprintf(xsvalue, sizeof(xsvalue), "%u", evp) >= \
	     sizeof(xsvalue) ) {
		fputs("Error building event channel value.\n", stderr);
		goto done;
	}

	if ( !xs_write(handle, XBT_NULL, xspath, xsvalue, strlen(xsvalue)) ) {
		fputs("Error writing connection message.\n", stderr);
		goto done;
	}


	/* Wait for connection response. */
	fputs("Unmasking event.\n", stdout);
	if ( xenevtchn_unmask(evh, evp) == -1 ) {
		fputs("Error unmasking event channel.\n", stderr);
		goto done;
	}

	fputs("Waiting for connection.\n", stdout);
	if ( xenevtchn_pending(evh) == -1 ) {
		fputs("Erroring getting event.\n", stderr);
		goto done;
	}


	/* Send test write. */
	size = (uint32_t *) gntp;

	fputs("Sending write of 100 bytes.\n", stdout);
	*size = 100;
	xenevtchn_notify(evh, evp);

	if ( xenevtchn_pending(evh) == -1 ) {
		fputs("Error getting write responde.\n", stderr);
		goto done;
	}
	fprintf(stdout, "Reply size: %u\n", *size);

	/* Send shutdown. */
	fputs("Sending shutdown.\n", stdout);
	*size = 0xffffffff;
	xenevtchn_notify(evh, evp);

	retn = 0;


 done:
	free(domid);
	xs_close(handle);

	if ( grant_handle != NULL ) {
		retn = xengntshr_unshare(grant_handle, gntp, 1);
		xengntshr_close(grant_handle);
	}

	if ( evp != -1 )
		xenevtchn_unbind(evh, evp);
	if ( evh != NULL )
		xenevtchn_close(evh);


	return retn;
}
