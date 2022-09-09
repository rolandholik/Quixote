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

#define SYSFS_UPDATES			"/sys/fs/tsem/update-%llu"
#define SYSFS_EXTERNAL			"/sys/kernel/security/tsem/external"

/* Kernel driver definitions. */
#define CLONE_EVENTS 0x00000040

#define CAP_TRUST 38

#define SYS_CONFIG_DOMAIN  436
#define IMA_TE_ENFORCE	   0x8
#define IMA_EVENT_EXTERNAL 0x10

#define SYS_CONFIG_ACTOR  437
#define DISCIPLINE_ACTOR  1
#define RELEASE_ACTOR	  2
