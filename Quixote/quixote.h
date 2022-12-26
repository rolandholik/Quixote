/** \file
 *
 * This file implements common definitions for Quixote management
 * utilities.
 */

/**************************************************************************
 * Copyright (c) 2020, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

/* Filesystem locations. */
#define TSEM_CONTROL_FILE		"/sys/kernel/security/tsem/control"

#define QUIXOTE_PROCESS_MGMT_DIR	"/var/lib/Quixote/mgmt/processes"
#define QUIXOTE_CARTRIDGE_MGMT_DIR	"/var/lib/Quixote/mgmt/cartridges"
#define QUIXOTE_MAGAZINE		"/var/lib/Quixote/Magazine"

#define SYSFS_UPDATES			"/sys/fs/tsem/ExternalTMA/%llu"
#define SYSFS_EXTERNAL			"/sys/kernel/security/tsem/external"
