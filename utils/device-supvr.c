/** \file
 * This file implements the system hotplug manager and device supervisor.
 * The purpose of this utility is to monitor for KOBJECT addition and
 * deletion events and respond with appropriate actions such as device
 * node creation and removal.
 *
 * Its primary role is to manage the creation and deletion of the USB
 * endpoint devices created when hardware authentication keys are
 * inserted and removed.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Local defines. */

/* Owner of the device nodes. */
#define OWNER 32767


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <linux/netlink.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>


/* Variables referenced statically by this program. */

/** Run in debug mode. */
static _Bool Debug = false;

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

	struct stat statbuf;

	String entry,
	       busdir = NULL,
	       path   = NULL;


	/* Create the device path. */
	if ( (entry = _search_list(list, "DEVNAME=")) == NULL )
		ERR(goto done);
	p = strchr(entry->get(entry), '=') + 1;

	if ( (path = HurdLib_String_Init_cstr("/dev/")) == NULL )
		ERR(goto done);
	if ( !path->add(path, p) )
		ERR(goto done);


	/* Process a removal. */
	if ( !add ) {
		if ( Debug ) {
			fputs("Event:\n", stdout);
			_print_list(list);
			fprintf(stdout, "\nRemoving: %s\n", path->get(path));
			fflush(stdout);
		}

		unlink(path->get(path));
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

	if ( Debug ) {
		fputs("Event:\n", stdout);
		_print_list(list);
		fprintf(stdout, "Creating device=%s, major=%d, minor=%d\n", \
			path->get(path), (int) major, (int) minor);
		fflush(stdout);
	}


	/* Verify the bus directory is present. */
	if ( (busdir = HurdLib_String_Init_cstr("/dev/bus/usb/")) == NULL)
		ERR(goto done);
	if ( (entry = _search_list(list, "BUSNUM=")) == NULL )
		ERR(goto done);

	p = strchr(entry->get(entry), '=') + 1;
	if ( !busdir->add(busdir, p) )
		ERR(goto done);

	if ( stat(busdir->get(busdir), &statbuf) != 0 ) {
		if ( errno != ENOENT )
			ERR(goto done);
		if ( mkdir(busdir->get(busdir), S_IRUSR | S_IWUSR | S_IXUSR) \
		     != 0 )
			ERR(goto done);
		if ( chown(busdir->get(busdir), OWNER, OWNER) != 0 )
			ERR(goto done);
	}


	/* Create the device node. */
	if ( mknod(path->get(path), S_IFCHR | S_IRUSR | S_IWUSR, \
		   makedev(major, minor)) != 0 )
		ERR(goto done);
	if ( chown(path->get(path), OWNER, OWNER) != 0 )
		ERR(goto done);

	retn = true;


 done:
	WHACK(path);
	WHACK(busdir);

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
		if ( _search_list(list, "ACTION=add") != NULL )
			retn = process_device(list, true);
		if ( _search_list(list, "ACTION=remove") != NULL )
			retn = process_device(list, false);
	}
	else
		retn = true;


 done:
	_free_list(list);
	WHACK(list);

	return retn;
}


/**
 * Internal private function.
 *
 * This function is responsible for creating a device node for an
 * eligible device.  The strategy used by this function is to
 * read the uevent pseudo-file and convert the file into a Buffer
 * object which can then be processed by the process_device function.
 *
 * \param sysfile	A character pointer to the name of the
 *			directory in the /sys heirarchy which describes
 *			the device.
 *
 * \return	A boolean value is used to indicate the status of
 *		device creation.  A false value indicates there was
 *		a failure in creating the device while a true value
 *		indicates the device was successfully created.
 */

static _Bool _create_device(CO(char *, sysfile))

{
	_Bool retn = false;

	char *p;
	const char *add = "ACTION=add\n";

	Buffer event = NULL;

	String device = NULL;

	File uevent = NULL;


	INIT(HurdLib, String, device, goto done);
	device->add(device, sysfile);
	if ( !device->add(device, "/uevent") )
		ERR(goto done);

	INIT(HurdLib, File, uevent, goto done);
	INIT(HurdLib, Buffer, event, goto done);

	uevent->open_ro(uevent, device->get(device));
	event->add(event, (unsigned char *) add, strlen(add));
	if ( !uevent->slurp(uevent, event) )
		ERR(goto done);

	/*
	 * Convert all linefeeds into NULL's to match the buffer format
	 * which is supplied by a netlink message.
	 */
	p = (char *) (event->get(event) + event->size(event) - 1);
	*p = '\0';

	p = (char *) event->get(event);
	while ( (p = strchr(p, '\n')) != NULL )
		*p++ = '\0';

	if ( !process_event(event) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(event);
	WHACK(device);
	WHACK(uevent);

	return retn;
}


/**
 * Internal function.
 *
 * This function is responsible for searching for devices which have
 * been introduced or discovered before the daemon was started.  This
 * allows the daemon to manage a current list of devices after
 * startup.
 *
 * This function expects no input variables.
 *
 * \return	A boolean value is used to indicate the status of
 *		the device.  A false value indicates discovery and
 *		setup failed while a true value indicates the device
 *		nodes were updated.
 */

static _Bool update_devices(void)

{
	_Bool retn = false;

	const char *device_list[] = {
		"Yubikey NEO OTP+U2F+CCID",
		NULL
	};

	int rv;
	unsigned int lp,
		     lp1;

	glob_t devices;

	String device  = NULL,
	       product = NULL;

	File sysfile = NULL;


	/* Get a list of USB devices. */
	rv = glob("/sys/bus/usb/devices/[0-9]*", 0, NULL, &devices);
	if ( rv != 0 ) {
		if ( rv == GLOB_NOMATCH ) {
			retn = true;
			goto done;
		}
		ERR(goto done);
	}


	/* Iterate through the device list looking for ones of interest. */
	INIT(HurdLib, String, device, goto done);
	INIT(HurdLib, String, product, goto done);
	INIT(HurdLib, File, sysfile, goto done);

	for (lp= 0; lp < devices.gl_pathc; ++lp) {
		device->add(device, devices.gl_pathv[lp]);
		if ( !device->add(device, "/product") )
			ERR(goto done);

		sysfile->open_ro(sysfile, device->get(device));
		if ( sysfile->read_String(sysfile, product) ) {
			char *p;

			for (lp1= 0; device_list[lp1] != NULL; ++lp1) {
				if ( strcmp(product->get(product), \
					    device_list[lp1]) == 0 ) {
					p = devices.gl_pathv[lp];
					if ( !_create_device(p) )
						ERR(goto done);
				}
			}
		}

		sysfile->reset(sysfile);
		device->reset(device);
		product->reset(product);
	}

	retn = true;


 done:
	WHACK(device);
	WHACK(product);
	WHACK(sysfile);

	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int opt,
	    retn = 1;

	Buffer event = NULL;


	while ( (opt = getopt(argc, argv, "d")) != EOF )
		switch ( opt ) {
			case 'd':
				Debug = true;
				break;
		}


	/* Add device nodes for previously plugged devices. */
	if ( !update_devices() )
		ERR(goto done);

	/* Initialize socket interface for netlink messages. */
	if ( !setup_netlink() )
		ERR(goto done);

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
