/** \file
 *
 * This file implements a loadable module framework that implements
 * only the modeling of the file_open and mmap_file security event
 * handlers as an example of how integrity measurement can be
 * implement with a loadable TSEM model.
 */

/**************************************************************************
 * Copyright (c) 2024, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/mman.h>

#include "tsem.h"
#include "nsmgr.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("The Quixote Project");
MODULE_DESCRIPTION("Sample TSEM integrity model.");

static bool event_handlers[TSEM_EVENT_CNT] = {
	[TSEM_FILE_OPEN] = true,
	[TSEM_MMAP_FILE] = true
};

static int cell_init(struct tsem_event *ep)
{
	int retn;

	retn = tsem_event_generate(ep);
	if (retn < 0)
		return retn;

	if (!((ep->COE.uid == 0) || (ep->COE.suid == 0) ||
	      (ep->COE.euid == 0)) ) {
		return 0;
	}

	retn = 0;
	switch (ep->event) {
	case TSEM_FILE_OPEN:
		if (ep->CELL.file.out.inode.mode & S_IXUGO)
			retn = 1;
		break;
	case TSEM_MMAP_FILE:
		if (ep->CELL.mmap_file.prot & PROT_EXEC)
			retn = 1;
		break;
	default:
		break;
	}

	return retn;
}

static int map_event(struct tsem_event *ep)
{
	u8 *p;

	switch (ep->event) {
	case TSEM_FILE_OPEN:
		p = ep->CELL.file.out.digest;
		break;
	case TSEM_MMAP_FILE:
		p = ep->CELL.mmap_file.file.out.digest;
		break;
	default:
		return 0;
		break;
	}

	memcpy(ep->mapping, p, sizeof(ep->mapping));
	return 0;
}

const struct tsem_context_ops integrity_ops = {
	.name = KBUILD_MODNAME,
	.events = event_handlers,
	.cell_init = cell_init,
	.map = map_event
};

static int __init integrity_init(void)
{
	return tsem_nsmgr_register(&integrity_ops, THIS_MODULE);
}
module_init(integrity_init);

static void __exit integrity_exit(void)
{
	tsem_nsmgr_release(&integrity_ops);
}
module_exit(integrity_exit);
