/** \file
 * This file contains definitions for the TSEM security events and
 * characteristics.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

enum tsem_event_type {
	TSEM_UNDEFINED=0,
	TSEM_BPRM_SET_CREDS,
	TSEM_GENERIC_EVENT,
	TSEM_FILE_OPEN,
	TSEM_MMAP_FILE,
	TSEM_FILE_IOCTL,
	TSEM_FILE_LOCK,
	TSEM_FILE_FCNTL,
	TSEM_FILE_RECEIVE,
	TSEM_UNIX_STREAM_CONNECT,
	TSEM_UNIX_MAY_SEND,
	TSEM_SOCKET_CREATE,
	TSEM_SOCKET_CONNECT,
	TSEM_SOCKET_BIND,
	TSEM_SOCKET_ACCEPT,
	TSEM_SOCKET_LISTEN,
	TSEM_TASK_KILL,
	TSEM_PTRACE_TRACEME,
	TSEM_KERNEL_MODULE_REQUEST,
	TSEM_KERNEL_LOAD_DATA,
	TSEM_KERNEL_READ_FILE,
	TSEM_SB_MOUNT,
	TSEM_SB_UMOUNT,
	TSEM_SB_REMOUNT,
	TSEM_SB_PIVOTROOT,
	TSEM_SB_STATFS,
	TSEM_MOVE_MOUNT,
	TSEM_SHM_ASSOCIATE,
	TSEM_SHM_SHMCTL,
	TSEM_SHM_SHMAT,
	TSEM_SEM_ASSOCIATE,
	TSEM_SEM_SEMCTL,
	TSEM_SEM_SEMOP,
	TSEM_SYSLOG,
	TSEM_SETTIME,
	TSEM_QUOTACTL,
	TSEM_QUOTA_ON,
	TSEM_MSG_QUEUE_ASSOCIATE,
	TSEM_MSG_QUEUE_MSGCTL,
	TSEM_MSG_QUEUE_MSGSND,
	TSEM_MSG_QUEUE_MSGRCV,
	TSEM_EVENT_CNT
};
