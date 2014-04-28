/** \file
 *
 */

/**************************************************************************
 * (C)Copyright 2014, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */


/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <Origin.h>
#include <HurdLib.h>

#include "NAAAIM.h"
#include "Netconfig.h"

#define STATE(var) CO(Netconfig_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_Netconfig_OBJID)
#error Object identifier not defined.
#endif


/** Netconfig private state information. */
struct NAAAIM_Netconfig_State
{
	/** The root object. */
	Origin root;

	/** Library identifier. */
	uint32_t libid;

	/** Object identifier. */
	uint32_t objid;

	/** The error code which generated the object poisoning. */
	int error;

	/* Object status. */
	_Bool poisoned;

};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_Netconfig_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const Netconfig_State const S) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_Netconfig_OBJID;

	S->error    = 0;
	S->poisoned = false;

	return;
}


/**
 * Internal private method.
 *
 * This method is responsible for obtaining the IPV4 address which has
 * been assigned to a network interface.
 *
 * \param this	The object whose address is to be queried.
 *
 * \param iface	A null-terminated character buffer containing the
 *		name of the interface whose address is to be
 *		obtained.
 *
 * \param addr	The variable which will be used to store the network
 *		address.
 *
 * \param mask	The variable which will be used to store the network
 *		mask assigned to the interface.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the interface was successfully interrogated.  A false
 *		value indicates failure while a true value indicates
 *		the interface was successfully interrogated.
 */

static _Bool get_address(CO(Netconfig, this), CO(char *, name), \
			 struct in_addr *addr, struct in_addr *mask)

{
	STATE(S);

	_Bool retn = false;

	int fd = -1;

	struct ifreq request;

	struct sockaddr_in sock_addr;


	if ( (fd = socket(AF_INET, SOCK_DGRAM, AF_UNSPEC)) == -1 ) {
		fprintf(stderr, "%s[%s]: socket error = %s\n", __FILE__, \
			__func__, strerror(errno));
		goto done;
	}

	memset(&request, '\0', sizeof(struct ifreq));
	strncpy(request.ifr_name, name, IFNAMSIZ);

	memset(&sock_addr, '\0', sizeof(struct sockaddr));
	sock_addr.sin_family	  = AF_INET;
	sock_addr.sin_port	  = 0;

	if ( ioctl(fd, SIOCGIFADDR, &request) == -1 ) {
		fprintf(stderr, "%s[%s]: SIOCGIFADDR error = %s\n", \
			__FILE__, __func__, strerror(errno));
		goto done;
	}
	memcpy(&sock_addr, &request.ifr_addr, sizeof(struct sockaddr));
	addr->s_addr = sock_addr.sin_addr.s_addr;

	if ( ioctl(fd, SIOCGIFNETMASK, &request) == -1 ) {
		fprintf(stderr, "%s[%s]: SIOCGIFNETMASK error = %s\n", \
			__FILE__, __func__, strerror(errno));
		goto done;
	}
	memcpy(&sock_addr, &request.ifr_addr, sizeof(struct sockaddr));
	mask->s_addr = sock_addr.sin_addr.s_addr;

	retn = true;

 done:
	if ( !retn )
		S->error = errno;
	if ( fd != -1 )
		close(fd);

	return retn;
}


/**
 * Internal private method.
 *
 * This method is responsible for configuring a network interface.
 *
 * \param this	The object whose address is to be set.
 *
 * \param iface	A null-terminated character buffer containing the
 *		name of the interface to be configured.
 *
 * \param addr	The IPv4 address for the interface in ASCII dotted
 *		format.
 *
 * \param mask	The network interface address mask in ASCII dotted
 *		format.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the interface was successfully configured.  A false
 *		value indicates failure while a true value indicates
 *		the interface was successfully configured.
 */

static _Bool set_address(CO(Netconfig, this), CO(char *, name), \
			 CO(char *, addr), CO(char *, mask))

{
	STATE(S);

	_Bool retn = false;

	int fd = -1;

	struct ifreq request;

	struct sockaddr_in sock_addr;


	if ( (fd = socket(AF_INET, SOCK_DGRAM, AF_UNSPEC)) == -1 ) {
		fprintf(stderr, "%s[%s]: socket error = %s\n", __FILE__, \
			__func__, strerror(errno));
		goto done;
	}

	memset(&request, '\0', sizeof(struct ifreq));
	strncpy(request.ifr_name, name, IFNAMSIZ);

	memset(&sock_addr, '\0', sizeof(struct sockaddr));
	sock_addr.sin_family	  = AF_INET;
	sock_addr.sin_port	  = 0;

	sock_addr.sin_addr.s_addr = inet_addr(addr);
	memcpy(&request.ifr_addr, &sock_addr, sizeof(struct sockaddr));
	if ( ioctl(fd, SIOCSIFADDR, &request) == -1 ) {
		fprintf(stderr, "%s[%s]: SIOCSIFADDR error = %s\n", \
			__FILE__, __func__, strerror(errno));
		goto done;
	}

	sock_addr.sin_addr.s_addr = inet_addr(mask);
	memcpy(&request.ifr_netmask, &sock_addr, sizeof(struct sockaddr));
	if ( ioctl(fd, SIOCSIFNETMASK, &request) == -1 ) {
		fprintf(stderr, "%s[%s]: SIOCSIFNETMASK error = %s\n", \
			__FILE__, __func__, strerror(errno));
		goto done;
	}

	if ( ioctl(fd, SIOCGIFFLAGS, &request) == -1 ) {
		fprintf(stderr, "%s[%s]: SIOCGIFFLAGS error = %s\n", \
			__FILE__, __func__, strerror(errno));
		goto done;
	}

	request.ifr_flags |= (IFF_UP | IFF_RUNNING);
	if ( ioctl(fd, SIOCSIFFLAGS, &request) == -1 ) {
		fprintf(stderr, "%s[%s]: SIOCSIFFLAGS error = %s\n", \
			__FILE__, __func__, strerror(errno));
		goto done;
	}

	retn = true;


 done:
	if ( !retn )
		S->error = errno;
	if ( fd != -1 )
		close(fd);

	return retn;
}


/**
 * Internal private method.
 *
 * This method implements the ability to define a gateway for a
 * static route.
 *
 * \param this	The object whose route is to be set.
 *
 * \param addr	The IPv4 address for the destination network.
 *
 * \param gw	The IPv4 address for the gateway to the destination
 *		network.
 *
 * \parm mask	The IPV4 mask to be applied to the destination address.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the route was successfully configured.  A false
 *		value indicates failure while a true value indicates
 *		the route was successfully configured.
 */

static _Bool set_route(CO(Netconfig, this), CO(char *, destination), \
		       CO(char *, gateway), CO(char *, mask))

{
	STATE(S);

	_Bool retn = false;

	int fd = -1;

	struct rtentry route;

	struct sockaddr_in sock_addr;


	if ( (fd = socket(AF_INET, SOCK_DGRAM, AF_UNSPEC)) == -1 ) {
		fprintf(stderr, "%s[%s]: socket error = %s\n", __FILE__, \
			__func__, strerror(errno));
		goto done;
	}

	memset(&sock_addr, '\0', sizeof(struct sockaddr));
	sock_addr.sin_family	  = AF_INET;
	sock_addr.sin_port	  = 0;

	memset(&route, '\0', sizeof(struct rtentry));

	sock_addr.sin_addr.s_addr = inet_addr(destination);
	memcpy(&route.rt_dst, &sock_addr, sizeof(struct sockaddr));

	sock_addr.sin_addr.s_addr = inet_addr(gateway);
	memcpy(&route.rt_gateway, &sock_addr, sizeof(struct sockaddr));

	sock_addr.sin_addr.s_addr = inet_addr(mask);
	memcpy(&route.rt_genmask, &sock_addr, sizeof(struct sockaddr));

	route.rt_flags = RTF_UP | RTF_GATEWAY;

	if ( ioctl(fd, SIOCADDRT, &route) == -1 ) {
		fprintf(stderr, "%s[%s]: SIOCADDRT error = %s\n", \
			__FILE__, __func__, strerror(errno));
		goto done;
	}

	retn = true;


 done:
	if ( !retn )
		S->error = errno;
	if ( fd != -1 )
		close(fd);

	return retn;
}


/**
 * External public method.
 *
 * This method implements an accesor for retrieving the error code
 * from the object.
 *
 * \param this	A pointer to the object whose error is to be
 *		retrieved.
 */

static int get_error(CO(Netconfig, this))

{
	STATE(S);

	return S->error;
}


/**
 * External public method.
 *
 * This method implements a destructor for a Netconfig object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const Netconfig const this)

{
	STATE(S);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a Netconfig object.
 *
 * \return	A pointer to the initialized Netconfig.  A null value
 *		indicates an error was encountered in object generation.
 */

extern Netconfig NAAAIM_Netconfig_Init(void)

{
	Origin root;

	Netconfig this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_Netconfig);
	retn.state_size   = sizeof(struct NAAAIM_Netconfig_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_Netconfig_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->set_address = set_address;
	this->get_address = get_address;
	this->set_route	  = set_route;

	this->get_error	  = get_error;
	this->whack	  = whack;

	return this;
}
