/**
 * This file contains the application specific linker commands for
 * the SanchoMCU implementation based on Nordic NRF52840-DK board.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

SEARCH_DIR(.)
GROUP(-lgcc -lc -lnosys)

MEMORY
{
	FLASH(rx) : ORIGIN = 0x0,	 LENGTH = 0x100000
	RAM(rwx)  : ORIGIN = 0x20000000, LENGTH = 0x40000
}

INCLUDE "sancho-common.ld"
