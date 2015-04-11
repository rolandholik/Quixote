/** \file
 * This file implements the system hotplug manager.  The purpose of
 * this manager is to monitor for KOBJECT addition and deletion events
 * and respond with appropriate actions such as device node creation
 * and removal.
 *
 * Its primary role is to manage the creation and deletion of the USB
 * endpoint devices created when hardware authentication keys are
 * inserted and removed.
 */

/**************************************************************************
 * (C)Copyright 2015, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <linux/netlink.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include <NAAAIM.h>


/* Variables referenced statically by this program. */

/** The file descriptor bound to the netlink socket. */
static int NetlinkFD = 0;


/**
 * Internal function.
 *
 * This function carries out the setup and initialization of the
 * the netlink socket.  The file descriptor which the socket is bound
 * to is placed in the statically scoped NetlinkFD variable for
 * reference generically throughout the context of this program.
 *
 * This function expects no input variables.
 *
 * \return	A boolean value is used to indicate the status of
 *		the netlink socket creation.  A false value indicates
 *		setup failed with a true value indicating that the
 *		netlink system is ready for access.
 */

static _Bool setup_netlink(void)

{
	_Bool retn = false;

	struct sockaddr_nl netlink;


	/* Setup the socket for kernel netlink events. */
	NetlinkFD = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	if ( NetlinkFD == -1 )
		ERR(goto done);

	/* Bind the socket file descriptor to the netlink socket. */
	memset(&netlink, '\0', sizeof(netlink));
	netlink.nl_family = AF_NETLINK;
	netlink.nl_pid	  = getpid();
	netlink.nl_groups = -1;

	if ( bind(NetlinkFD, (const struct sockaddr * ) &netlink, \
		  sizeof(netlink)) == -1 )
	     ERR(goto done);

	retn = true;


 done:
	return retn;
}


/**
 * Internal function.
 *
 * This function waits for a kernel netlink socket event.  When a
 * message becomes available the event message is loaded into
 * the caller supplied Buffer object for processing.
 *
 * \param evnet	The object which the event payload is to be loaded into.
 *
 * \return	A boolean value is used to indicate the status of
 *		message reception.  A false value indicates an error
 *		occurred while a true value indicates the supplied
 *		Buffer object has a valid payload.n
 */

static _Bool get_event(CO(Buffer, event))

{
	_Bool retn   = false,
	      no_msg = true;

	unsigned char bufr[1024];

	ssize_t amt;


	if ( (event == NULL) || event->poisoned(event) )
		ERR(goto done);

	while ( no_msg ) {
		amt = recv(NetlinkFD, bufr, sizeof(bufr), MSG_WAITALL);
		if ( (amt == -1) && (errno == EINTR) )
			continue;
		if ( amt > 0 )
			no_msg = false;
	}

	if ( !event->add(event, bufr, amt) )
		ERR(goto done);

	retn = true;


 done:
	return retn;
}


/**
 * Internal private function.
 *
 * This function is responsible for printing the list of entries
 * associated with an event.  This is largely a utility function for
 * debugging device event processing.
 *
 * \param list	The object containing the list of event items.
 *
 * \return	No return value is specified.
 */

static String _print_list(CO(Buffer, list))

{
	unsigned char *member;

	size_t size;

	String entry;


	size = list->size(list) / sizeof(String);
	member = list->get(list);

	while ( size > 0 ) {
		memcpy(&entry, member, sizeof(entry));
		entry->print(entry);
		member += sizeof(entry);
		--size;
	}

	return NULL;
}


/**
 * Internal private function.
 *
 * This function is responsible for freeing the entries in the event
 * item list.
 *
 * \param list	The object containing the list of event items to be freed.
 *
 * \return	No return value is specified.
 */

static String _free_list(CO(Buffer, list))

{
	unsigned char *member;

	size_t size;

	String entry;


	size = list->size(list) / sizeof(String);
	member = list->get(list);

	while ( size > 0 ) {
		memcpy(&entry, member, sizeof(entry));
		entry->whack(entry);
		member += sizeof(entry);
		--size;
	}

	return NULL;
}


/**
 * Internal private function.
 *
 * This function is responsible for locating an entry in the list of
 * items associated with an event which matches the specified
 * arguement.
 *
 * \param list	The object containing the list of event items.
 *
 * \param match	A pointer to a null-terminated string containing
 *		the entry which is to be matched.
 *
 * \return	If the search is unsuccessful a NULL pointer is
 *		returned.  If the match was successful the String
 *		object which was matched is returned.
 */

static String _search_list(CO(Buffer, list), CO(char *, match))

{
	unsigned char *member;

	size_t size;

	String entry;


	size = list->size(list) / sizeof(String);
	member = list->get(list);

	while ( size > 0 ) {
		memcpy(&entry, member, sizeof(entry));
		if ( strncmp(match, entry->get(entry), strlen(match)) == 0 )
			return entry;
		member += sizeof(entry);
		--size;
	}

	return NULL;
}


/**
 * Private function.
 *
 * This function is responsible for processing a device addition or
 * removal event.
 *
 * \param list	The object containing the list of items describing
 *		the event.
 *
 * \param add	The type of event to be processed.  A true value
 *		indicates the device is to be added while a false
 *		value indicates the device is to be removed.
 *
 * \return	If addition of the device failed a false value is
 *		returned.  A true value indicates the device was
 *		successfully created.
 */

static _Bool process_device(CO(Buffer, list), const _Bool add)

{
	_Bool retn = false;

	char *p;

	dev_t major,
	      minor;

	String entry,
	       path = NULL;


	/* Create the device path. */
	if ( (entry = _search_list(list, "DEVNAME=")) == NULL )
		ERR(goto done);
	if ( (path = HurdLib_String_Init_cstr("/dev/")) == NULL )
		ERR(goto done);
	if ( !path->add(path, entry->get(entry)) )
		ERR(goto done);


	/* Process a removal. */
	if ( !add ) {
		unlink(path->get(path));
		fprintf(stderr, "Removed: %s\n", path->get(path));
		retn = true;
		goto done;
	}

	/* Process a device addition. */
	if ( (entry = _search_list(list, "MAJOR=")) == NULL )
		ERR(goto done);
	p = strchr(entry->get(entry), '=') + 1;
	major = strtol(p, NULL, 10);
	if ( errno == ERANGE )
		ERR(goto done);

	if ( (entry = _search_list(list, "MINOR=")) == NULL )
		ERR(goto done);
	p = strchr(entry->get(entry), '=') + 1;
	minor = strtol(p, NULL, 10);
	if ( errno == ERANGE )
		ERR(goto done);

	fprintf(stdout, "Created device=%s, major=%d, minor=%d\n", \
		entry->get(entry), (int) major, (int) minor);
	retn = true;

 done:
	return retn;
}
	

/**
 * Internal function.
 *
 * This function processes the buffer which was supplied by the
 * kernel object event.
 *
 * \param event	The object containing the vent payload.
 *
 * \return	A boolean value is used to indicate the status of
 *		event processing.  A false value indicates processing
 *		of the event failed while a true value indicates the
 *		event was successfully processed.
 */

static _Bool process_event(CO(Buffer, event))

{
	_Bool retn = false;

	char *bp;

	size_t size = 0;

	Buffer list = NULL;

	String entry;


	if ( (event == NULL) || event->poisoned(event) )
		ERR(goto done);

	/* Create list of entries in the event. */
	INIT(HurdLib, Buffer, list, goto done);
	bp = (char *) event->get(event);

	while ( size < event->size(event) ) {
		INIT(HurdLib, String, entry, goto done);
		if ( !entry->add(entry, bp) )
			ERR(goto done);
		if ( !list->add(list, (void *) &entry, sizeof(entry)) )
			ERR(goto done);
		
		size += (strlen(bp) + 1);
		bp   += (strlen(bp) + 1);
	}

	if ( (entry = _search_list(list, "DEVTYPE=usb_device")) != NULL ) {
		if ( _search_list(list, "PRODUCT=1050/116/336") == NULL ) {
			retn = true;
			goto done;
		}
		if ( _search_list(list, "ACTION=add") != NULL ) {
			fputs("Calling device add\n", stderr);
			retn = process_device(list, true);
		}
		if ( _search_list(list, "ACTION=remove") != NULL ) {
			fputs("Calling device remove.\n", stdout);
			retn = process_device(list, false);
		}
	}
	fprintf(stdout, "%s: return = %d\n", __func__, retn);


 done:
	_free_list(list);
	WHACK(list);

	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int retn = 1;

	Buffer event = NULL;


	/* Initialize socket interface for netlink messages. */
	if ( !setup_netlink() )
		goto done;

	/* Loop over events. */
	INIT(HurdLib, Buffer, event, goto done);

	while ( 1 ) {
		if ( !get_event(event) )
			ERR(goto done);
		if ( !process_event(event) )
			ERR(goto done);
		event->reset(event);
	}

	retn = 0;


 done:
	WHACK(event)

	return retn;
}
