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


/* Add bit operators if they are not defined. */
#if !defined(BIT_ULL)
#define BIT_ULL(nr)	  (1ULL << (nr))
#define GENMASK_ULL(h, l) (((U64_C(1) << ((h) - (l) + 1)) - 1) << (l))
#endif

#define SGX_HASH_SIZE 32

#define SPID_FILENAME "/opt/IDfusion/etc/spid.txt"


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

struct _layout_group_t
{
    uint16_t    id;
    uint16_t    entry_count;
    uint32_t    load_times;
    uint64_t    load_step;
    uint32_t    reserved[4];
} __attribute__((packed));

typedef union _layout_t
{
	struct _layout_entry_t entry;
	struct _layout_group_t group;
} layout_t;


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
	uint8_t data[18592];
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
#define SGX_IOCTL_ENCLAVE_INIT	    _IOW(0xa4, 0x02, struct SGX_init_param)


/**
 * Structure used as the arguement to the ioctl which creates an
 * SGX enclave.
 */
#define SGX_IOCTL_ENCLAVE_CREATE   _IOW(0xa4, 0x00, struct SGX_create_param)

struct SGX_create_param {
	void *secs;
};


/**
 * Structure and definitions used to extend an SGX enclave with an
 * additional page.
 */

/*
 * The following definition is used to indicate the contents of the
 * page should NOT be extended into the measurement of the enclave.
 */
#define SGX_PAGE_ADD	0x1
#define SGX_PAGE_EXTEND	0x2

#define SGX_IOCTL_ENCLAVE_ADD_PAGE _IOW(0xa4, 0x01, struct SGX_add_param)

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
	uint16_t mrmask;
} __attribute__((packed));


/**
 * Definitions and structures used to initialize an enclave.
 */
#define ISGX_IOCTL_ENCLAVE_INIT		_IOW('p', 0x04, struct isgx_init_param)

/**
 * The definition of an initialization token.  The driver and Intel
 * SDK treats this as two structures, the first embedded in the
 * second.  The SDK treats this as a type definition of token_t.
 */
struct SGX_einittoken {
	/* Referred to as the launch_body_t in the SDK .*/
	uint32_t valid;
	uint32_t reserved1[11];
	sgx_attributes_t attributes;
	sgx_measurement_t mr_enclave;
	uint8_t reserved2[32];
	sgx_measurement_t mr_signer;
	uint8_t reserved3[32];

	/* Referred to as the _launch_t structure. */
	uint8_t cpusvnle[16];
	uint16_t isvprodidle;
	uint16_t isvsvnle;
	uint8_t reserved4[24];
	uint32_t maskedmiscselectle;
	uint64_t maskedattributesle;
	uint64_t maskedxfrmle;
	uint8_t keyid[32];
	uint8_t mac[16];
} __attribute__((aligned(512)));

struct SGX_init_param {
	unsigned long addr;
	void *sigstruct;
	struct SGX_einittoken *einittoken;
} __attribute__((packed));


/**
 * The following structure definition is used as the API definition for
 * OCALL's from an enclave to userspace.  It consists of a list of
 * function points which referenced by a 'slot' or array index passed
 * by the OCALL to userspace.
 */
struct OCALL_api {
	size_t nr_ocall;
	void *table[];
};


/**
 * The following structure definitions are used to generate reports
 * from an enclave which allow up to 64 bytes of data to be securely
 * conveyed from one enclave to another.  These structures are the
 * base of enclave<->enclave trust relationships.
 */

/**
 * The following structure is created by an enclave requesting a
 * report from an enclave running on the current platform.
 */
struct SGX_targetinfo {
	sgx_measurement_t mrenclave;
	sgx_attributes_t attributes;
	uint8_t reserved1[4];
	uint32_t miscselect;
	uint8_t reserved2[456];
} __attribute__((aligned(512)));


/**
 * The following structure is the report which is returned by an
 * enclave in response to a request from an enclave which is described
 * by an SGX_targetinfo tructure.
 *
 * When used in an enclave the SGX_report structure must be 512 byte
 * aligned.  The alignment constraint is not specified here as it
 * is for other structures since the SGX_report structure is imbedded
 * in structures and can cause the size of the structure to be
 * larger then what they are in the Intel development kit.
 */

struct SGX_reportbody {
	uint8_t cpusvn[16];
	uint32_t miscselect;
	uint8_t reserved1[28];
	sgx_attributes_t attributes;
	sgx_measurement_t mr_enclave;
	uint8_t reserved2[32];
	uint8_t mrsigner[32];
	uint8_t reserved3[96];
	uint16_t isvprodid;
	uint16_t isvsvn;
	uint8_t reserved4[60];
	uint8_t reportdata[64];
};

struct SGX_report {
	struct SGX_reportbody body;
	uint8_t keyid[32];
	uint8_t mac[16];
};


/**
 * The following definitions are used to request various keys which
 * can be retrieved with the ENCLU[EGETKEY] instruction.  This instruction
 * returns keys which are derived from the current processor identity.
 */

/* Definition of numeric constants used to select various keys. */
#define SGX_KEYPOLICY_SIGNER	0x1
#define SGX_KEYPOLICY_ENCLAVE	0x2

#define SGX_KEYSELECT_REPORT	0x3
#define SGX_KEYSELECT_SEAL	0x4

struct SGX_keyrequest {
	uint16_t keyname;
	uint16_t keypolicy;
	uint16_t isvsvn;
	uint8_t reserved1[2];
	uint8_t cpusvn[16];
	sgx_attributes_t attributes;
	uint8_t keyid[32];
	uint32_t miscselect;
	uint8_t reserved2[436];
} __attribute__((aligned(512)));


/**
 * The following structure is returned by the SGX provisioning servers
 * and contains the key that will be used to secure provisioning
 * communications with the server.
 */
struct SGX_pek {
	uint8_t n[384];
	uint8_t e[4];
	uint8_t sha1_ne[20];
	uint8_t pek_signature[2 * 32];
	uint8_t sha1_sign[20];
} __attribute__((packed));


/**
 * The following structure defines the EPID 'blob'.
 */
struct SGX_extended_epid {
	uint16_t format_id;
	uint16_t data_length;
	uint32_t xeid;
	uint8_t epid_sk[64];
	uint8_t pek_sk[64];
	uint8_t qsdk_exp[4];
	uint8_t qsdk_mod[256];
	uint8_t signature[64];
} __attribute__((packed));


/**
 * The following structure defines the PVE generated provisioning
 * message three.
 */
struct SGX_message3 {
	uint8_t field1_iv[12];
	uint8_t field1_data[4 + 192];
	uint8_t field1_mac[16];
	uint8_t n2[16];
	uint8_t epid_sig_iv[12];
	uint8_t epid_sig_mac[16];
	uint8_t encrypted_pwk2[384];
	struct SGX_report pwk2_report;
	uint32_t epid_sig_output_size;
	uint8_t is_join_proof_generated;
	uint8_t is_epid_sig_generated;
} __attribute__((packed));


/**
 * The following structure defines the structure which contains platform
 * version.
 */
struct SGX_platform_info {
	uint8_t  cpu_svn[16];
	uint16_t pve_svn;
	uint16_t pce_svn;
	uint16_t pce_id;
	uint8_t  fmsp[4];
} __attribute__((packed));


/**
 * The following structure defines the information which represents
 * the security version of an enclave.
 */
struct SGX_psvn {
	uint8_t cpu_svn[16];
	uint16_t isv_svn;
} __attribute__((packed));


/**
 * The following structure defines the quote information returned in
 * response to a request to the Quoting Enclave to generate an
 * remote attestation report for an enclave.
 */
struct SGX_quote {
	uint16_t version;
	uint16_t sign_type;
	uint8_t epid_group_id[4];
	uint16_t qe_svn;
	uint8_t reserved[6];
	uint8_t basename[32];
	struct SGX_reportbody report_body;
	uint32_t signature_len;
	uint8_t signature[];
} __attribute__((packed));
