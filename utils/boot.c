/** \file
 * This file implements the system initialization manager.  It is the
 * first executable to be loaded and is responsible for managing the
 * boot of the platform manager or the application image.
 */

/**************************************************************************
 * (C)Copyright 2014, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */
/* TPM daemon location. */
#define TCSD_PATH "/usr/local/musl/sbin/tcsd"

/* Location of manifest file. */
#define MANIFEST "/boot/manifest"


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <sys/mount.h>
#include <sys/reboot.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include "SoftwareStatus.h"


/* Variable static to this file. */
static _Bool Debug = false;


/**
 * Private function.
 *
 * This function is responsible for terminating the boot process.  It
 * requests a reboot of the system.
 *
 * No arguements are expected by this function.
 *
 * This function does not return.
 */

static void do_reboot(void)

{
	if ( Debug ) {
		fputs("Reboot requested.\n", stderr);
		return;
	}

#if 0
	fputs("Rebooting.\n", stderr);
	reboot(RB_AUTOBOOT);
#endif
}


/**
 * Private function.
 *
 * This function is responsible for managing the start and stop of the
 * TPM daemon.  The daemon needs to be started in order for the
 * laod-image binary to unseal the encryption keys for the root
 * filesystem image.
 *
 * \param start	A boolean variable which specifies whether or not the
 *		the function should start or stop the TPM daemon.  A
 *		true value indicates the daemon should be started
 *		while a false value requests shutdown of the daemon.
 *
 * \return	A boolean variable is returned to indicate whether or
 *		not the stop/stop process succeeded.  A true
 *		value indicates the function has successfully executed
 *		the desired action.
 */

static _Bool tpm_daemon(const _Bool start)

{
	static pid_t tpm_pid = 0;


	/* Shutdown daemon. */
	fputs("Shutting down daemon.\n", stderr);
	if ( !start ) {
		if ( kill(tpm_pid, SIGTERM) == -1 )
			return false;
		return true;
	}
		
	/* Startup daemon. */
	fputs("Starting daemon.\n", stderr);
	tpm_pid = fork();
	if ( tpm_pid == -1 )
		return false;
	/* Child. */
	if ( tpm_pid == 0 ) {
		execl(TCSD_PATH, TCSD_PATH, "-f", NULL);
		return false;
	}

	/* Parent - verify DAEMON is running. */
	fputs("Checking for daemon presence.\n", stderr);
	sleep(5);
	if ( kill(tpm_pid, 0) == -1 )
		return false;

	return true;
}
	
	
/**
 * Private function.
 *
 * This function is responsible for managing the mounting and unmounting
 * of filesystems needed in the system load process.
 *
 * \param mode	A boolean variable which specifies whether or not the
 *		the function should mount or unmount the filesystems.  A
 *		true value indicates the filesystems should be mounted
 *		while a false value requests unmounting of the
 *		filesystems.
 *
 * \return	A boolean variable is returned to indicate whether or
 *		not the mount/unmount process succeeded.  A true
 *		value indicates the function has successfully executed
 *		the desired action.
 */

static _Bool do_mounts(const _Bool mode)

{
	_Bool sysfs = false,
	      proc  = false,
	      retn = false;


	if ( mode ) {
		if ( mount("sysfs", "/sys", "sysfs", 0, NULL) == 0 )
			sysfs = true;
		if ( mount("proc", "/proc", "proc", 0, NULL) == 0 )
			proc = true;
		retn = true;
	}
	else {
		umount("/proc");
		umount("/sys");
		retn = true;
	}


	if ( !retn ) {
		if ( sysfs )
			umount("/sys");
		if ( proc )
			umount("/proc");
	}

	return retn;
}

	
/**
 * Private function.
 *
 * This function searches the /proc/cmdline pseudo-file to locate the
 * root= variable.  If successful a Buffer object is returned with
 * the name of the root device.
 *
 * No arguements are expected to this function.
 *
 * \return	If the root device is located a Buffer object is returned
 *		with the name of the device.  A NULL value is returned
 *		if there is an error or the root= directive is not
 *		found.
 */

static Buffer find_root(void)

{
	char *rp,
	     *root_name = NULL;
	const char * const tag = "root=";

	unsigned int root_length = 0;

	Buffer cmdbufr = NULL;

	File cmdline = NULL;

	Buffer retn = NULL;


	if ( (cmdline = HurdLib_File_Init()) == NULL )
		goto done;
	if ( (cmdbufr = HurdLib_Buffer_Init()) == NULL )
		goto done;
	if ( (retn = HurdLib_Buffer_Init()) == NULL )
		goto done;

	cmdline->open_ro(cmdline, "/proc/cmdline");
	cmdline->read_Buffer(cmdline, cmdbufr, 0);
	if ( !cmdbufr->add(cmdbufr, (unsigned char *) "\0", 1) )
		goto done;


	rp = (char *) cmdbufr->get(cmdbufr);
	while ( *rp != '\0' ) {
		if ( strncmp(rp, tag, strlen(tag)) == 0 ) {
			root_name = rp + strlen(tag);
			break;
		}
		++rp;
	}
	if ( root_name != NULL ) {
		rp = root_name;
		while ( (*rp != '\0') && (*rp != '\n') && (*rp != ' ') )
			++rp;
		root_length = rp - root_name;
	}

	retn->add(retn, (unsigned char *) root_name, root_length);
	if ( !retn->add(retn, (unsigned char *) "\0", 1) )
		WHACK(retn);

 done:
	WHACK(cmdline);
	WHACK(cmdbufr);
	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for loading the root and configuration
 * filesystems from their encrypted images on the boot device.
 *
 * \param device	No arguements are expected.
 *
 * \return              A boolean value is used to indicate if the
 *			filesystem image was successfuly loaded.  A
 *			false value indicates failure while a true
 *			value indicates the root filesystem is loaded.
 */

static _Bool load_root(void)

{
	_Bool retn = false;

	char *rootdev,
	     *fs;

	unsigned long mountflags;

	Buffer root = NULL;


	if ( (root = find_root()) == NULL )
		return false;

	if ( Debug ) {
		fputs("Using bind mount\n", stderr);
		rootdev = "/";
		mountflags = MS_BIND;
		fs = NULL;
	}
	else {
		rootdev = (char *) root->get(root);
		mountflags = 0;
		fs = "ext3";
	}

	if ( mount(rootdev, "/mnt", fs, mountflags, NULL) == -1 ) {
		fprintf(stderr, "Mount failed: %s\n", strerror(errno));
		goto done;
	}
	if ( system("/sbin/load-image -r /mnt/boot/root " \
		    "-t -k /mnt/boot/root.seal -o /dev/hpd0") != 0 )
		goto done;

	if ( system("/sbin/load-image -u 1 -r /mnt/boot/config " \
		    "-t -k /mnt/boot/config.seal -o /dev/hpd1") != 0 ) {
		fputs("Configuration load failed.\n", stderr);
		goto done;
	}

	if ( umount("/mnt") != 0 ) {
		fprintf(stderr, "umount failed: %s\n", strerror(errno));
		goto done;
	}

	retn = true;

 done:
	WHACK(root);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for initializing the Integrity Management
 * Architecture (IMA) by reading the filesystem manifest list and
 * reading each file in the manifest in order to have the kernel
 * initialize an IMA entry for the file.
 *
 * No arguements are specified.
 *			
 * \return	No return value is specified.
 */

static void initialize_ima(void)

{
	char *p,
	     bufr[PATH_MAX];

	Buffer b;

	FILE *manifest = NULL;

	File file = NULL;

	SoftwareStatus software = NULL;


	if ( (manifest = fopen(MANIFEST, "r")) == NULL )
		return;
	INIT(HurdLib, File, file, goto done);

	while ( fgets(bufr, sizeof(bufr), manifest) != NULL ) {
		if ( (p = strchr(bufr, '\n')) != NULL )
			*p = '\0';
		file->open_ro(file, bufr);
		file->reset(file);
	}

	INIT(NAAAIM, SoftwareStatus, software, goto done);
	if ( !software->open(software) )
		goto done;
	if ( !software->measure(software) )
		goto done;
	fputs("Software status:\n", stdout);
	b = software->get_template_hash(software);
	b->print(b);


 done:
	memset(bufr, sizeof(bufr), '\0');

	if ( manifest != NULL )
		fclose(manifest);

	WHACK(file);
	WHACK(software);
	
	return;
}
	

/**
 * Private function.
 *
 * This function is responsible for switching execution to the root of
 * the loaded filesystem.
 *
 * No arguements are specified.
 *			
 * \return              This function returns if switching to the new
 *			root fails.  Otherwise the initial process
 *			is started on the new root filesystem.
 */

static void switch_root(void)

{
	if ( mount("/dev/hpd0", "/mnt", "ext3", 0, NULL) == -1 )
		return;
	if ( chdir("/mnt") == -1 )
		return;

	if ( !Debug ) {
		if ( mount("/mnt", "/", NULL, MS_MOVE, NULL) == -1 )
			return;
	}
	if ( chroot(".") == -1 )
		return;

	do_mounts(true);
	mount("securityfs", "/sys/kernel/security", "securityfs", 0, NULL);

	initialize_ima();

	if ( mount("/dev/hpd1", "/etc/conf", "ext3", 0, NULL) == -1 ) {
		fprintf(stderr, "Configuration mount failed: %s\n", \
			strerror(errno));
		return;
	}

	execl("/sbin/init", "/sbin/init", NULL);
	return;
}
     
/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int opt;


	while ( (opt = getopt(argc, argv, "d")) != EOF )
		switch ( opt ) {
			case 'd':
				Debug = true;
				break;
		}


	fputs("Doing mount.\n", stderr);
	if ( !do_mounts(true) )
		goto done;

	fputs("Starting TPM daemon.\n", stderr);
	if ( !tpm_daemon(true) )
		goto done;

	fputs("Loading images.\n", stderr);
	if ( !load_root() )
		goto done;

	fputs("Releasing mounts.\n", stderr);
	if ( !do_mounts(false) )
		goto done;

	fputs("Shutting down TPM daemon.\n", stderr);
	if ( !tpm_daemon(false) )
		goto done;

	fputs("Changing root.\n", stderr);
	switch_root();
	
 done: 
	do_mounts(false);
	do_reboot();
	return 0;
}
