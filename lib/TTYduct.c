/** \file
 * This file provides the implementation of an object that provides
 * packet based communications over a tty device.
 */

/**************************************************************************
 * Copyright (c) 2020, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "TTYduct.h"

/* State extraction macro. */
#define STATE(var) CO(TTYduct_State, var) = this->state

/* Maximum receive buffer size - 256K. */
#define MAX_RECEIVE_SIZE 262144


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_TTYduct_OBJID)
#error Object identifier not defined.
#endif


/** LocalDuct private state information. */
struct NAAAIM_TTYduct_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* End of transmission flag. */
	_Bool eof;

	/* Error code. */
	int error;

	/* Device file descriptor. */
	int fd;

	/* Receive buffer. */
	unsigned char bufr[1024];
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the QUIXOTE_LocalDuct_State
 * structure which holds state information for each instantiated object.
 * The object is started out in poisoned state to catch any attempt
 * to use the object without initializing it.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(TTYduct_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_TTYduct_OBJID;


	S->poisoned = false;

	return;
}


/**
 * External public method.
 *
 * This method initializes a local device for communications.
 *
 * \param this	The communications object for which the device is to be
 *		opened.
 *
 * \param path	The path to the device to be used for this object.
 *
 * \return	If the tty device is successfully opened and initialized
 *		a boolean true value is returned.  If open or
 *		initialization fails a false value is returned and the
 *		object is poisoned.
 */

static _Bool init_device(CO(TTYduct, this), CO(char *, path))

{
	STATE(S);

	_Bool retn = false;

	uint8_t inchar,
		cr = '\n';

#if 0
	int rc;
#endif

	struct termios options;


	if ( S->poisoned )
		ERR(goto done);


	/* Open communicatios device. */
	if ( (S->fd = open(path, O_RDWR | O_NOCTTY | O_SYNC)) == -1 )
		ERR(goto done);


	/* Set communication parameters. */
	tcgetattr(S->fd, &options);
#if 0
	cfsetospeed(&options, B115200);
	cfsetispeed(&options, B115200);

	options.c_cflag |= (CLOCAL | CREAD);
	options.c_cflag |= ~CSIZE;
	options.c_cflag &= ~PARENB;
	options.c_cflag &= ~CSTOPB;
	options.c_cflag &= ~CRTSCTS;

	options.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | \
			     IGNCR | ICRNL | IXON);
	options.c_iflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);

	options.c_oflag &= ~OPOST;

	options.c_cc[VMIN]  = 1;
	options.c_cc[VTIME] = 0;
#else
#if 0
	cfsetspeed(&options, B57600);
#else
	/*cfsetspeed(&options, B19200);*/
	cfsetspeed(&options, B115200);
#endif
	cfmakeraw(&options);
	options.c_lflag &= ~(ECHOE | ECHOK);

	options.c_cc[VTIME] = 1;
	options.c_cflag |= CRTSCTS;
	options.c_iflag |= IXON;
#endif

	tcsetattr(S->fd, TCSANOW, &options);
	fputs("Synchronizing: ", stdout);
	fflush(stdout);
	sleep(2);
#if 0
	tcflush(S->fd, TCIFLUSH);
#else
	tcflush(S->fd, TCIOFLUSH);
#endif

	inchar = '\0';
	write(S->fd, &cr, sizeof(cr));
	while ( inchar != '@' ) {
		read(S->fd, &inchar, 1);
		sleep(1);
	}
	fputs("OK\n", stdout);
	fflush(stdout);

	tcflush(S->fd, TCIOFLUSH);

#if 0
	while ( inchar != '@' ) {
		rc = write(S->fd, &cr, sizeof(cr));
		if ( rc == sizeof(cr) ) {
			rc = read(S->fd, &inchar, 1);
			if ( rc != 1 )
				sleep(1);
		}
#if 0
		fputc('.', stdout);
#else
		fprintf(stdout, "%c", inchar);
#endif
	}
#endif

#if 0
	tcflush(S->fd, TCIFLUSH);
	tcdrain(S->fd);
#endif

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements accepting a connection on an initialized server
 * port.
 *
 * \param this	The communications object which is to accept a connection.
 *
 * \return	This call blocks until a connection occurs.  The file
 *		descriptor of the connected socket is returned.
 */

static _Bool accept_connection(CO(TTYduct, this))

{
	return true;
}


/**
 * External public method.
 *
 * This method implements sending the contents of a specified Buffer object
 * over the connection represented by the callingn object.
 *
 * \param this	The LocalDuct object over which the Buffer is to be sent.
 *
 * \return	A boolean value is used to indicate whether or the
 *		write was successful.  A true value indicates the
 *		transmission was successful.
 */

static _Bool send_Buffer(CO(TTYduct, this), CO(Buffer, bf))

{
	STATE(S);

	_Bool retn = false;

	unsigned char *p;

#if 0
	struct iovec vector[2];
#endif
	uint32_t size = htonl(bf->size(bf));

	Buffer bufr = NULL;


	if ( S->poisoned )
		ERR(goto done);
	if ( S->fd == -1 )
		ERR(goto done);
	if ( (bf == NULL) || bf->poisoned(bf))
		ERR(goto done);


	/* Setup vectors for packet size and payload. */
#if 0
	vector[0].iov_len  = sizeof(uint32_t);
	vector[0].iov_base = &size;

	vector[1].iov_len  = bf->size(bf);
	vector[1].iov_base = bf->get(bf);
#endif

	/*
	 * Transmit the message vector.
	 *
	 * The code that is commented out was needed in order to
	 * provide reliable communications at 115.2 KBAUD.  At the
	 * current setting of 57.6 KBAUD the MCU appears capable
	 * of handling the data stream.
	 *
	 * The code open coded implementation is currently being
	 * maintained until there is verification that this
	 * implementation is not needed.
	 */
#if 1
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, (unsigned char *) &size, sizeof(size)) )
		ERR(goto done);
	if ( !bufr->add_Buffer(bufr, bf) )
		ERR(goto done);

	p    = bufr->get(bufr);
	size = bufr->size(bufr);
	while ( size-- ) {
		write(S->fd, p++, 1);
#if 0
		usleep(300);
#if 1
#else
		usleep(300);
#endif
#endif
	}
#else
	sent = writev(S->fd, vector, 2);
	if ( sent != (vector[0].iov_len + vector[1].iov_len) )
		ERR(S->error = errno; goto done);
#endif

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(bufr);

	return retn;
}


/**
 * Private function.
 *
 * The following method is a helper function for the ->receive_Buffer
 * method.  It provides an efficient method of ingressing a buffer of
 * specified length using select on the non-blocking input device.
 *
 * \param S	A pointer to the state informationn for the
 *		object that is ingressing the data.
 *
 * \param cnt	The number of bytes to load into the buffer.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the buffer was successfully populated.  A false
 *		value indicates an error was encountered while a
 *		true value indicates that the specified number of
 *		bytes were read.
 */

static _Bool _read_buffer(const TTYduct_State S, size_t cnt)

{
	_Bool retn = false;

	unsigned char *p = S->bufr;

#if 0
	int rc,
	    available;
#else
	int rc;
#endif

	size_t received = 0;

#if 0
	struct pollfd poll_data[1];
#endif


	/* Validate input. */
	if ( cnt == 0 )
		ERR(goto done);


	/* Setup poll to return information on available data. */
#if 0
	poll_data[0].fd = S->fd;
	poll_data[0].events = POLLIN;
#endif


	/* Loop until I/O is completed. */
	memset(S->bufr, '\0', sizeof(S->bufr));

	while ( received < cnt ) {
#if 0
		printf("Polling: received=%lu, cnt=%lu\n", received, cnt);
		rc = poll(poll_data, 1, -1);
		if ( rc < 0 )
			ERR(goto done);

		if ( (poll_data[0].revents & POLLIN) == 0 )
			ERR(goto done);

		if ( ioctl(S->fd, FIONREAD, &available) != 0 )
			ERR(goto done);

		if ( (rc = read(S->fd, p, available)) < 0 )
			ERR(goto done);
#else
		if ( (rc = read(S->fd, p, 1)) < 0 )
			ERR(goto done);
		if ( rc == 0 )
			continue;
#endif

		p	 += rc;
		received += rc;
	}

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements loading the specified number of bytes into
 * the provided Buffer object.
 *
 * \param this	The LocalDuct object from which data is to be read.
 *
 * \return	A boolean value is used to indicate whether or the
 *		read was successful.  A true value indicates the receive
 *		was successful.
 */

static _Bool receive_Buffer(CO(TTYduct, this), CO(Buffer, bf))

{
	STATE(S);

	_Bool retn = false;

	uint32_t rsize;

	size_t lp,
	       blocks,
	       residual;


	if ( S->poisoned )
		ERR(goto done);
	if ( (bf == NULL) || bf->poisoned(bf) )
		ERR(goto done);


	/*
	 * Get the size of the buffer to be received and convert the
	 * network byte order value to a host integer. If more then
	 * the object specified amount is specified set the errno
	 * variable to be a negative value so it can be distinguished
	 * from a standard error number.
	 */
	if ( !_read_buffer(S, sizeof(rsize)) )
		ERR(goto done);
	memcpy(&rsize, S->bufr, sizeof(rsize));

	rsize = ntohl(rsize);
	if ( rsize == 0 ) {
		retn   = true;
		S->eof = true;
		goto done;
	}
	if ( rsize > MAX_RECEIVE_SIZE ) {
		this->terminal(this);
		ERR(S->error = -1; goto done);
	}


	/* Loop over the number of integral receipt blocks. */
	blocks	 = rsize / sizeof(S->bufr);
	residual = rsize % sizeof(S->bufr);

	for (lp= 0; lp < blocks; ++lp) {
		if ( !_read_buffer(S, sizeof(S->bufr)) )
			ERR(S->error = errno; goto done);
		if ( !bf->add(bf, S->bufr, sizeof(S->bufr)) )
			ERR(S->error = -2; goto done);
	}


	/* Read the residual data. */
	if ( residual ) {
		if ( !_read_buffer(S, residual) )
			ERR(S->error = errno; goto done);
		if ( !bf->add(bf, S->bufr, residual) )
			ERR(S->error = -2; goto done);
	}

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


static _Bool terminal(CO(TTYduct, this))

{
	STATE(S);

	_Bool retn = false;

#if 1
	int recvd,
	    lp = 20;
#else
	int recvd;
#endif

	char inbufr[1];


	if ( S->poisoned )
		ERR(goto done);

	while ( 1 ) {
#if 1
		if ( (recvd = read(S->fd, inbufr, sizeof(inbufr))) == \
		     sizeof(inbufr) ) {
			fprintf(stdout, "Received %d: %c/%x\n", recvd, \
				inbufr[0], inbufr[0]);
			fflush(stdout);
			--lp;
		}
#else
		if ( (recvd = read(S->fd, inbufr, sizeof(inbufr))) == \
		     sizeof(inbufr) ) {
			fprintf(stdout, "%c", inbufr[0]);
			fflush(stdout);
		}
#endif
	}

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements a destructor for a LocalDuct object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(TTYduct, this))

{
	STATE(S);


	/* Destroy resources. */
	S->root->whack(S->root, this, S);

	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a LocalDuct object.
 *
 * \return	A pointer to the initialized LocalDuct.  A null value
 *		indicates an error was encountered in object generation.
 */

extern TTYduct NAAAIM_TTYduct_Init(void)

{
	Origin root;

	TTYduct this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_TTYduct);
	retn.state_size   = sizeof(struct NAAAIM_TTYduct_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_TTYduct_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->init_device	= init_device;
	this->accept_connection	= accept_connection;

	this->send_Buffer	= send_Buffer;
	this->receive_Buffer	= receive_Buffer;

	this->terminal		= terminal;

	this->whack		= whack;

	return this;
}
