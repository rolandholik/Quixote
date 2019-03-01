/** \file
 * This file implements an object for accessing a Postgresl database.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>

#include <libpq-fe.h>

#include "NAAAIM.h"
#include "DBduct.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_DBduct_OBJID)
#error Object identifier not defined.
#endif


/** DBduct private state information. */
struct NAAAIM_DBduct_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Boolean to indicate the need to clear a result object. */
	_Bool have_result;

	/* Object describing the connection. */
	PGconn *connection;

	/* Command result pointer. */
	PGresult *result;

	/* Row and column counts returned by the query method. */
	int rows;
	int columns;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_DBduct_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const DBduct_State const S) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_DBduct_OBJID;

	S->poisoned    = true;
	S->have_result = false;
	S->connection  = NULL;
	S->result      = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements opening of a connection to a database server.
 * If the connection fails the object is poisoned.
 *
 * \param this		A pointer to the object describing the database
 *			connection.
 *
 * \param options	A null terminated buffer containing the
 *			options whic describe the database connection.
 *
 * \return		A boolean value is used to indicate success or
 *			failure of the connection attempt.  A false
 *			value is used to indicate a failure.
 */

static _Bool init_connection(const DBduct const this, \
			     const char * const options)

{
	auto const DBduct_State const S = this->state;

	auto _Bool retn = false;


	if ( (S->connection = PQconnectdb(options)) == NULL )
		goto done;
	if ( PQstatus(S->connection) != CONNECTION_OK )
		goto done;

	retn	    = true;
	S->poisoned = false;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements the execution of one or more SQL commands
 * which do not return results.  Multiple commands are separated with
 * a semicolon.
 *
 * \param this		The database connection on which the command
 *			is to be executed.
 *
 * \param cmd		A pointer to a null-terminated character array
 *			containing the command to be executed.
 *
 * \return		A boolean value is used to indicate whether or
 *			not execution of the command succeeded.  A
 *			true value is used to indicate success.
 */

static _Bool exec(const DBduct const this, const char * const cmd)

{
	auto const DBduct_State const S = this->state;

	auto _Bool retn = false;


	if ( S->poisoned )
		goto done;

	if ( S->have_result )
		PQclear(S->result);

	if ( (S->result = PQexec(S->connection, cmd)) == NULL )
		goto done;
	if ( PQresultStatus(S->result) != PGRES_COMMAND_OK )
		goto done;

	retn	       = true;
	S->have_result = true;


 done:
	if ( retn == false )
		S->have_result = false;

	return retn;
}


/**
 * External public method.
 *
 * This method implements the execution of SQL commands which return
 * results such as a SELECT etc.  Multiple command, separated by
 * semicolons, can be specified.
 *
 * \param this		The database connection on which the command
 *			is to be executed.
 *
 * \param cmd		A pointer to a null-terminated character array
 *			containing the query command to be executed.
 *
 * \return		The number of rows produced by the query is
 *			returned to the caller.
 */

static int query(const DBduct const this, const char * const cmd)

{
	auto const DBduct_State const S = this->state;

	auto int retn = -1;


	if ( S->poisoned )
		goto done;

	if ( S->have_result )
		PQclear(S->result);

	if ( (S->result = PQexec(S->connection, cmd)) == NULL )
		goto done;
	if ( PQresultStatus(S->result) != PGRES_TUPLES_OK )
		goto done;

	/* Set the row and column counts and the return status. */
	S->rows    = PQntuples(S->result);
	S->columns = PQnfields(S->result);

	retn	       = S->rows;
	S->have_result = true;


 done:
	if ( retn == -1 )
		S->have_result = false;

	return retn;
}


/**
 * External public method.
 *
 * This method implements returning one element out of the return
 * matrix.
 *
 * \param this		The database object from an element is to be
 *			returned.
 *
 * \param row		The number of the row in the reply which is
 *			to be returned.
 *
 * \param column	The number of the column in the reply which is
 *			be returned.
 *
 * \return		A character pointer to the return value is returned.
 *			A null value is returned if an error is detected.
 */

static char * get_element(const DBduct const this, int const row, \
			  int const column)

{
	auto const DBduct_State const S = this->state;


	/* Sanity checks. */
	if ( S->poisoned )
		return NULL;
	if ( row > S->rows )
		return NULL;
	if ( column > S->columns )
		return NULL;

	return PQgetvalue(S->result, row, column);
}


/**
 * External public method.
 *
 * This method implements printing out the results of a query.  This
 * method is primarily for diagnostic purposes and simply prints out
 * the matrix of return results.
 *
 * \param this		The database object which contains the results
 *			of a query.
 */

static void print(const DBduct const this)

{
	auto const DBduct_State const S = this->state;

	auto char *value;

	auto int row,
		 column;


	if ( S->poisoned ) {
		fputs("* POISONED *\n", stderr);
		return;
	}

	if ( !S->have_result ) {
		fputs("* NO RESULTS *\n", stderr);
		return;
	}

	for (row= 0; row < S->rows; ++row) {
		for (column= 0; column < S->columns; ++column) {
			if ( PQgetisnull(S->result, row, column) ) {
				fputs("NULL", stdout);
				continue;
			}
			if ( PQfformat(S->result, column) == 1 ) {
				fputs("BINARY", stdout);
				continue;
			}
			value = PQgetvalue(S->result, row, column);
			fprintf(stdout, "%s\t", value);
		}
		fputc('\n', stdout);
	}

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a DBduct object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const DBduct const this)

{
	auto const DBduct_State const S = this->state;


	if ( S->have_result )
		PQclear(S->result);

	if ( S->connection != NULL )
		PQfinish(S->connection);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a DBduct object.
 *
 * \return	A pointer to the initialized DBduct.  A null value
 *		indicates an error was encountered in object generation.
 */

extern DBduct NAAAIM_DBduct_Init(void)

{
	auto Origin root;

	auto DBduct this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_DBduct);
	retn.state_size   = sizeof(struct NAAAIM_DBduct_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_DBduct_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->init_connection = init_connection;
	this->exec	      = exec;
	this->query	      = query;
	this->get_element     = get_element;
	this->print	      = print;

	this->whack = whack;

	return this;
}
