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
#define TCSD_PATH "/usr/local/sbin/tcsd"

/* Location of manifest file. */
#define PSEUDOMAP  "/sys/kernel/security/ima/iso-identity/pseudonym"
#define PSEUDONYMS "/boot/pseudonyms"

#define MAPFILE	 "/sys/kernel/security/ima/iso-identity/map"
#define CONTOURS "/boot/contours"

/* Locations of root password and seal files. */
#define ROOT_PWD    "/mnt/boot/root.pwd"
#define ROOT_SEAL   "/mnt/boot/root.seal"
#define CONFIG_SEAL "/mnt/boot/config.seal"

/* System call flag defines. */
#define SYS_set_behavior 326

#define IMA_SET_CONTOUR		0x1
#define IMA_SET_PSEUDONYM	0x2


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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>

#include <SoftwareStatus.h>

#include "Netconfig.h"


/* Variable static to this file. */
static _Bool Debug = false;


/**
 * Private function.
 *
 * This function is responsible for terminating the boot process.  It
 * requests a reboot of the system.
 *
 * \param boot	A boolean variable which specifies whether the system
 *		is to reboot or halt.  A true value requests that the
 *		system should halt while a true value indictes the
 *		system should reboot.
 *
 * This function does not return.
 */

static void do_reboot(const _Bool boot)

{
	if ( boot )
		reboot(RB_AUTOBOOT);
	else
		reboot(RB_HALT_SYSTEM);
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
	int lp,
	    status;

	static pid_t tpm_pid = 0;

	Netconfig netconfig = NULL;


	/* Shutdown daemon. */
	if ( !start ) {
		if ( kill(tpm_pid, SIGTERM) == -1 )
			return false;
		for (lp= 0; lp < 5; ++lp) {
			waitpid(tpm_pid, &status, WNOHANG);
			if ( WIFEXITED(status) ) {
				fprintf(stderr, "TPM daemon %d shutdown, " \
					"code=%d\n", tpm_pid,		   \
					WEXITSTATUS(status));
				return true;
			}
			sleep(1);
		}
		return false;
	}

	/* Startup daemon. */
	fputs("Configuring loopback.\n", stderr);
	INIT(NAAAIM, Netconfig, netconfig, return false);
	if ( !netconfig->set_address(netconfig, "lo", "127.0.0.1", \
				     "255.0.0.0") )
		return false;
	WHACK(netconfig);

	fputs("Starting daemon.\n", stderr);
	tpm_pid = fork();
	if ( tpm_pid == -1 )
		return false;
	/* Child. */
	if ( tpm_pid == 0 ) {
		execl(TCSD_PATH, TCSD_PATH, "-f", "-n", NULL);
		return false;
	}

	/* Parent - verify DAEMON is running. */
	fputs("Checking for daemon presence.\n", stderr);
	sleep(10);
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
	_Bool sysfs	 = false,
	      securityfs = false,
	      proc	 = false,
	      retn	 = false,
	      devpts	 = false;


	if ( mode ) {
		if ( mount("sysfs", "/sys", "sysfs", 0, NULL) == 0 )
			sysfs = true;
		if ( mount("securityfs", "/sys/kernel/security", \
			   "securityfs", 0, NULL) == 0 )
			securityfs = true;
		if ( mount("proc", "/proc", "proc", 0, NULL) == 0 )
			proc = true;
		if ( mount("devpts", "/dev/pts", "devpts", 0, NULL) == 0 )
			devpts = true;
		retn = true;
	}
	else {
		umount("/dev/pts");
		umount("/proc");
		umount("/sys/kernel/security");
		umount("/sys");
		retn = true;
	}


	if ( !retn ) {
		if ( securityfs )
			umount("/sys/kernel/security");
		if ( sysfs )
			umount("/sys");
		if ( proc )
			umount("/proc");
		if ( devpts )
			umount("/dev/pts");
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
 * This function is responsible for sealing the root and configuration
 * system passwords if a root password was located and verified on
 * the /boot system partition.
 *
 * \return              A boolean value is used to indicate if an
 *			error occurred during sealing of the passwords.
 *			A true value indicates the password was sealed
 *			and is available.
 */

static _Bool seal_pwd(void)

{
	_Bool retn	  = false,
	      have_pwd	  = false,
	      have_sealed = false;

	struct stat seal_stat;

	const char * const seal_root_cmd = "tpm_sealdata -z -i " ROOT_PWD    \
		" -o " ROOT_SEAL " -p 0 -p 1 -p 2 -p 3 -p 4 -p 5 -p 6 -p 7 " \
		"-p 17 -p 18 2>&1 >/dev/null";
	const char * const seal_config_cmd = "tpm_sealdata -z -i " ROOT_PWD  \
		" -o " CONFIG_SEAL " -p 0 -p 1 -p 2 -p 3 -p 4 -p 5 -p 6 "    \
		"-p 7 -p 17 -p 18 2>&1 >/dev/null";


	/*
	 * Check for the presence of root and password files.  If
	 * a password file is not present we simply return and proceed.
	 * If a seal file is present the existing sealed file is unlinked
	 * and a new seal file is generated using the current password.
	 *
	 * Note that in order to provide a secure system the root and
	 * configuration images need to be encrypted outside of this
	 * platform.  The following will cause the existing images to
	 * be lost if an alternate password file is placed into
	 * position.
	 */
	if ( stat(ROOT_SEAL, &seal_stat) == 0 )
		have_sealed = true;

	if ( stat(ROOT_PWD, &seal_stat) == 0 )
		have_pwd = true;

	if ( !have_pwd ) {
		retn = true;
		goto done;
	}

	if ( have_sealed ) {
		if ( unlink(ROOT_SEAL) != 0 )
			goto done;
		if ( unlink(CONFIG_SEAL) != 0 )
			goto done;
	}


	/* Drop to a non-privileged user and seal the provided password. */
	if ( setreuid(1, -1) == -1 )
		goto done;

	if ( system(seal_root_cmd) != 0 ) {
		fputs("Failed to seal root password.\n", stderr);
		setreuid(geteuid(), -1);
		goto done;
	}

	if ( system(seal_config_cmd) != 0 ) {
		fputs("Failed to seal config password.\n", stderr);
		setreuid(geteuid(), -1);
		goto done;
	}

	if ( setreuid(geteuid(), -1) == -1 )
		goto done;

	if ( unlink(ROOT_PWD) == 0 )
		retn = true;
	if ( retn ) {
		fputs("Sealed root and config passwords.\n", stderr);
		sync();
		sleep(5);
		do_reboot(false);
	}


 done:
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
		fprintf(stderr, "Mount failed for root=%s: %s\n", rootdev, \
			strerror(errno));
		goto done;
	}


	/* Check to see if password systems needs sealing. */
	if ( !seal_pwd() )
		goto done;

	/* Load the system and configuration images with sealed passwords. */
	if ( system("/sbin/load-image -u 1 -r /mnt/boot/root " \
		    "-t -k /mnt/boot/root.seal -o /dev/hpd0") != 0 )
		goto done;

	if ( system("/sbin/load-image -u 1 -r /mnt/boot/config " \
		    "-t -k /mnt/boot/config.seal -o /dev/hpd1") != 0 ) {
		fputs("Configuration load failed.\n", stderr);
		goto done;
	}

	if ( mount("/mnt", "/boot", NULL, MS_MOVE, NULL) == -1 )
		goto done;
	retn = true;


 done:
	WHACK(root);

	return retn;
}

static inline int sys_behavior(unsigned char *bufr, size_t cnt, \
			       unsigned long flags)
{
	return syscall(SYS_set_behavior, bufr, cnt, flags);
}

/**
 * Internal private function.
 *
 * This function is a helper function for the
 * initialize_behavior_map() function.  It is responsible for reading
 * a behavioral configuration file and writing the contents of it to
 * the designed pseudo-file.
 *
 * \param config	A pointer to the null-terminated character
 * 			array containing the configuration entries.
 *
 * \param flag		The ISO_identity system call flag of the
 *			behavior which is to be set.
 *
 * \return	No return value is specified.
 */

static void _init_behavior(CO(char *, config), const unsigned long flag)

{
	char inbufr[NAAAIM_IDSIZE * 2 + 2];

	FILE *config_file = NULL;


	if ( (config_file = fopen(config, "r")) == NULL )
		goto done;

	while ( fgets(inbufr, sizeof(inbufr), config_file) != NULL ) {
		fprintf(stdout, "%s", inbufr);
		if ( sys_behavior((unsigned char *) inbufr, strlen(inbufr), \
				  flag) < 0 ) {
			fprintf(stderr, "Behavior %lu, returned %s\n", \
				flag, strerror(errno));
			goto done;
		}
	}


 done:
	memset(inbufr, '\0', sizeof(inbufr));

	if ( config_file != NULL )
		fclose(config_file);

	return;
}


/**
 * Private function.
 *
 * This function is responsible for initializing the iso-identity
 * behavior map for the system being booted.  Initialization of
 * the system behavior map is triggered by the presence of a
 * contours file in the system boot directory.
 *
 * No arguements are specified.
 *
 * \return	No return value is specified.
 */

static void initialize_behavior(void)

{
	struct stat statbufr;


	/* Map pseudonyms. */
	if ( stat(PSEUDONYMS, &statbufr) == 0 ) {
		fputs("Loading pseudonyms.\n", stdout);
		_init_behavior(PSEUDONYMS, IMA_SET_PSEUDONYM);
	}


	/* Read contours file and map the entries. */
	if ( stat(CONTOURS, &statbufr) == 0 ) {
		fputs("Loading contours.\n", stdout);
		_init_behavior(CONTOURS, IMA_SET_CONTOUR);
	}


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
	_Bool changed_uid = false;

	Buffer state = NULL;

	File tpm_state = NULL;


	if ( mount("/dev/hpd0", "/mnt", "ext3", 0, NULL) == -1 )
		return;
	if ( mount("/dev/hpd1", "/mnt/etc/conf", "ext3", 0, NULL) == -1 )
		return;

	INIT(HurdLib, Buffer, state, goto done);
	INIT(HurdLib, File, tpm_state, goto done);

	if ( setreuid(27, -1) == -1 )
		goto done;
	changed_uid = true;

	tpm_state->open_ro(tpm_state, "/mnt/etc/conf/system.data");
	if ( !tpm_state->slurp(tpm_state, state) )
		goto done;

	tpm_state->reset(tpm_state);
	tpm_state->open_wo(tpm_state, "/mnt/var/lib/tpm/system.data");
	if ( !tpm_state->write_Buffer(tpm_state, state) )
		goto done;

	if ( setreuid(geteuid(), -1) == -1 )
		goto done;
	changed_uid = false;

	WHACK(state);
	WHACK(tpm_state);


	if ( mount("/boot", "/mnt/mnt", NULL, MS_MOVE, NULL) == -1 )
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

	if ( mount("shm", "/dev/shm", "tmpfs", 0, NULL) == -1 )
		return;
	if ( mount("cgroup", "/sys/fs/cgroup", "cgroup", 0, NULL) == -1 )
		return;

	initialize_behavior();

	execl("/sbin/init", "/sbin/init", NULL);
	return;

 done:
	if ( changed_uid )
		setreuid(geteuid(), -1);

	WHACK(state);
	WHACK(tpm_state);

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

	fputs("Initializing behavior.\n", stderr);
	initialize_behavior();

	fputs("Starting TPM daemon.\n", stderr);
	if ( !tpm_daemon(true) )
		goto done;

	fputs("Loading images.\n", stderr);
	if ( !load_root() )
		goto done;

	fputs("Shutting down TPM daemon.\n", stderr);
	if ( !tpm_daemon(false) )
		goto done;

	fputs("Releasing mounts.\n", stderr);
	if ( !do_mounts(false) )
		goto done;

	fputs("Changing root.\n", stderr);
	switch_root();

 done:
	do_mounts(false);
	do_reboot(false);
	return 0;
}
