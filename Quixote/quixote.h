/** \file
 *
 * This file implements common definitions for Quixote management
 * utilities.
 */

/**************************************************************************
 * Copyright (c) 2020, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

/* TSEM read buffer size. */
#define TSEM_READ_BUFFER 1536

/* Filesystem locations. */
#define TSEM_CONTROL_FILE		"/sys/kernel/security/tsem/control"
#define TSEM_UPDATE_FILE		"/sys/kernel/security/tsem/external_tma/%llu"

#define QUIXOTE_PROCESS_MGMT_DIR	"/var/lib/Quixote/mgmt/processes"
#define QUIXOTE_CARTRIDGE_MGMT_DIR	"/var/lib/Quixote/mgmt/cartridges"
#define QUIXOTE_MAGAZINE		"/var/lib/Quixote/Magazine"
