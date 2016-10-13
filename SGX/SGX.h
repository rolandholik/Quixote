/** \file
 * This file contains the definitions for the interface between a
 * userspace program and the Intel Linux SGX driver.  They are largely
 * taken from the Linux driver and are consolidated here to avoid the
 * need to have a reference to an external header file.
 *
 * The structure definitions are copyright Intel but their
 * organization and implemenation in this file are under the following
 * copyright.
 */

/**************************************************************************
 * (C)Copyright 2016, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include kernel specific IOCTL information. */
#include <linux/ioctl.h>

/* The name of the device node used to access the OS driver. */
#define SGX_DEVICE "/dev/isgx"

/* Add bit operators if they are not defined. */
#if !defined(BIT_ULL)
#define BIT_ULL(nr)	  (1ULL << (nr))
#define GENMASK_ULL(h, l) (((U64_C(1) << ((h) - (l) + 1)) - 1) << (l))
#endif

#define SGX_HASH_SIZE 32


/**
 * Definition of an enclaves attributes.
 */
typedef uint32_t sgx_misc_select_t;

typedef struct _attributes_t {
	uint64_t flags;
	uint64_t xfrm;
} __attribute__((packed)) sgx_attributes_t;

typedef struct _sgx_measurement_t {
	uint8_t m[SGX_HASH_SIZE];
} sgx_measurement_t;


/**
 * Definitions and structures used for the enclave signature.
 *
 * In the Intel SDK this structure is referred to as the enclave_css_t
 * structure which is then subsequently decomposed into four
 * subordinate structures which are referred to as follows:
 *
 *	css_header_t
 *	css_key_t
 *	css_body_t
 *	css_buffer_t
 *
 * This is somewhat confusing as the Intel Software Developer's Manual
 * (SDM) refers to this as the sigstruct structure.   The focus of
 * this work is to stay consistent with the SDM since that document
 * is the canonical reference for the hardware implementation.
 * Secondary to this we will use a structure consistent with its
 * description in the SDM.
 */
#define SE_KEY_SIZE 384
#define SE_EXPONENT_SIZE 4

typedef struct _css_header_t {
	uint8_t header[12];
	uint32_t type;
	uint32_t module_vendor;
	uint32_t date;
	uint8_t header2[16];
	uint32_t hw_version;
	uint8_t reserved[84];
} __attribute__((packed)) css_header_t;

typedef struct _css_key_t {
	uint8_t modulus[SE_KEY_SIZE];
	uint8_t exponent[SE_EXPONENT_SIZE];
	uint8_t signature[SE_KEY_SIZE];
} __attribute__((packed)) css_key_t;

typedef struct _css_body_t {
	sgx_misc_select_t misc_select;
	sgx_misc_select_t misc_mask;
	uint8_t reserved[20];
	sgx_attributes_t attributes;
	sgx_attributes_t attribute_mask;
	sgx_measurement_t enclave_hash;
	uint8_t reserved2[32];
	uint16_t isv_prod_id;
	uint16_t isv_svn;
} __attribute__((packed)) css_body_t;

typedef struct _css_buffer_t {
	uint8_t reserved[12];
	uint8_t q1[SE_KEY_SIZE];
	uint8_t q2[SE_KEY_SIZE];
} __attribute__((packed)) css_buffer_t;

typedef struct _enclave_css_t {
	css_header_t header;
	css_key_t key;
	css_body_t body;
	css_buffer_t buffer;
} __attribute__((packed)) enclave_css_t;

struct SGX_sigstruct {
	uint8_t header[16];
	uint32_t vendor;
	uint32_t date;
	uint8_t header2[16];
	uint32_t sw_defined;
	uint8_t reserved1[84];
	uint8_t modulus[SE_KEY_SIZE];
	uint32_t exponent;
	uint8_t signature[SE_KEY_SIZE];
	uint32_t miscselect;
	uint32_t miscmask;
	uint8_t reserved2[20];
	sgx_attributes_t attributes;
	sgx_attributes_t attribute_mask;
	uint8_t enclave_hash[32];
	uint8_t reserved3[32];
	uint16_t isv_prodid;
	uint16_t isv_svn;
	uint8_t reserved[12];
	uint8_t q1[SE_KEY_SIZE];
	uint8_t q2[SE_KEY_SIZE];
} __attribute__((packed));


/**
 * Definitions and structures used to define the SGX metadata structure.
 *
 * This structure is imbedded in the .note.sgxmeta section of the
 * enclave shared object file.
 *
 * Among other important data this structure contains the measurement
 * of the enclave.
 */

typedef enum {
	DIR_PATCH,
	DIR_LAYOUT,
	DIR_NUM
} dir_index_t;

struct _patch_entry_t {
	uint64_t dst;
	uint32_t src;
	uint32_t size;
	uint32_t reserved[4];
} __attribute__((packed));

struct _layout_entry_t {
	uint16_t id;
	uint16_t attributes;
	uint32_t page_count;
	uint64_t rva;
	uint32_t content_size;
	uint32_t content_offset;
	uint64_t si_flags;
} __attribute__((packed));

typedef struct _data_directory_t {
	uint32_t offset;
	uint32_t size;
} __attribute__((packed)) data_directory_t;

typedef struct _metadata_t 
{
	uint64_t magic_num;
	uint64_t version;
	uint32_t size;
	uint32_t tcs_policy;
	uint32_t ssa_frame_size;
	uint32_t max_save_buffer_size;
	uint32_t desired_misc_select;
	uint32_t reserved;
	uint64_t enclave_size;
	sgx_attributes_t attributes;
	struct SGX_sigstruct enclave_css;
	data_directory_t dirs[DIR_NUM];
	uint8_t data[2208];
} __attribute__((packed)) metadata_t;


/**
 * Definitions and structures used to define the SGX Enclave Control
 * Structure (SECS).
 *
 * It should be noted that this structure is functionally equivalent
 * to the structure defined in the kernel driver sources but is
 * modified to be identical to the structure definitions used in the
 * Intel Software Development Kit.
 *
 * The kernel driver folds the miscselect field into the first
 * reserved section which can cause confusion when working between the
 * source code bases.
 */

#define SGX_SECS_RESERVED1_SIZE 24
#define SGX_SECS_RESERVED2_SIZE 32
#define SGX_SECS_RESERVED3_SIZE 96
#define SGX_SECS_RESERVED4_SIZE 3836
                                                                       
struct SGX_secs {
	uint64_t size;
	uint64_t base;
	uint32_t ssaframesize;
	uint32_t miscselect;
	uint8_t reserved1[SGX_SECS_RESERVED1_SIZE];
	uint64_t attributes;
	uint64_t xfrm;
	uint32_t mrenclave[8];
	uint8_t reserved2[SGX_SECS_RESERVED2_SIZE];
	uint32_t mrsigner[8];
	uint8_t reserved3[SGX_SECS_RESERVED3_SIZE];
	uint16_t isvprodid;
	uint16_t isvsvn;
	uint8_t reserved[SGX_SECS_RESERVED4_SIZE];
};


/*
 * The following definitions are used to define the arguements to the
 * SGX driver ioctl which implements access to the privileged ENCLS
 * instructions.
 */
#define SGX_IOCTL_ENCLAVE_INIT	    _IOW('p', 0x04, struct SGX_init_param)


/**
 * Structure used as the arguement to the ioctl which creates an
 * SGX enclave.
 */
#define SGX_IOCTL_ENCLAVE_CREATE   _IOWR('p', 0x02, struct SGX_create_param)

struct SGX_create_param {
	void *secs;
	unsigned long addr;
};


/**
 * Structure and definitions used to extend an SGX enclave with an
 * additional page.
 */

/*
 * The following definition is used to indicate the contents of the
 * page should NOT be extended into the measurement of the enclave.
 */
#define SGX_SKIP_EXTENSION 0x1

#define SGX_IOCTL_ENCLAVE_ADD_PAGE _IOW('p', 0x03, struct SGX_add_param)

/**
 * The following defines an enumeration which indicate the access
 * state of the page being committed to the enclave.
 */
enum SGX_secinfo_flags {
	SGX_SECINFO_R = BIT_ULL(0),
	SGX_SECINFO_W = BIT_ULL(1),
	SGX_SECINFO_X = BIT_ULL(2)
};

 /**
  * The following defines an enumeration which indictes the type of
  * page being commited to the enclave.
  */
enum SGX_secinfo_pt {
	SGX_SECINFO_SECS = 0x000ULL,
	SGX_SECINFO_TCS  = 0x100ULL,
	SGX_SECINFO_REG  = 0x200ULL
};

/**
 * The following structure defines the security information and
 * attributes a an enclave page.
 */

struct SGX_secinfo {
	uint64_t flags;
	uint64_t reserved[7];
} __attribute__((aligned(128)));

/**
 * The following structure defines the Task Control Structure (TCS)
 * which describes an executable page for an enclave.
 */
struct SGX_tcs {
	uint64_t state;
	uint64_t flags;
	uint64_t ossa;
	uint32_t cssa;
	uint32_t nssa;
	uint64_t oentry;
	uint64_t aep;
	uint64_t ofsbase;
	uint64_t ogsbase;
	uint32_t fslimit;
	uint32_t gslimit;
	uint64_t reserved[503];
};

/**
 * The following structure is used to encapsulate the information
 * which is passed to the ioctl which request addition of a page
 * to an enclave.
 */

struct SGX_add_param {
	unsigned long addr;
	unsigned long user_addr;
	struct SGX_secinfo *secinfo;
	unsigned int flags;
};


/**
 * Definitions and structures used to destroy an enclave.
 */
#define SGX_IOCTL_ENCLAVE_DESTROY  _IOW('p', 0x06, struct SGX_destroy_param)

struct SGX_destroy_param {
	unsigned long addr;
};