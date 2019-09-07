/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Code generation macros. */
/* Macro for setting error location. */
#if 0
#define NAAAIM_DEBUG
#endif

#if defined(NAAAIM_DEBUG)
#define SAY(msg) {fprintf(stdout, "%s: %s\n", __func__, msg); fflush(stdout);}
#else
#define SAY(msg) {}
#endif


/* Include files. */
#if defined(DMALLOC)
#include "dmalloc.h"
#endif

/* The size of an individual identity in bytes. */
#define NAAAIM_IDSIZE 32


/* Numeric library identifier. */
#define NAAAIM_LIBID 3

/* Object identifiers. */
#define NAAAIM_SHA256_OBJID		1
#define NAAAIM_SHA256_hmac_OBJID	2
#define NAAAIM_RSAkey_OBJID		3
#define NAAAIM_OrgID_OBJID		3
#define NAAAIM_PatientID_OBJID		4
#define NAAAIM_RandomBuffer_OBJID	5
#define NAAAIM_IDtoken_OBJID		6
#define NAAAIM_Duct_OBJID		7
#define NAAAIM_Authenticator_OBJID	8
#define NAAAIM_AES256_cbc_OBJID		9
#define NAAAIM_AuthenReply_OBJID	10
#define NAAAIM_OrgSearch_OBJID		11
#define NAAAIM_IDqueryReply_OBJID	12
#define NAAAIM_DBduct_OBJID		13
#define NAAAIM_ProviderQuery_OBJID	14
#define NAAAIM_LCDriver_OBJID		15
#define NAAAIM_SmartCard_OBJID		16
#define NAAAIM_SSLDuct_OBJID		17
#define NAAAIM_OTEDKS_OBJID		18
#define NAAAIM_Curve25519_OBJID		19
#define NAAAIM_IPC_OBJID		20
#define NAAAIM_SoftwareStatus_OBJID	21
#define NAAAIM_PossumPacket_OBJID	22
#define NAAAIM_IDmgr_OBJID		23
#define NAAAIM_Ivy_OBJID		24
#define NAAAIM_TPMcmd_OBJID		25
#define NAAAIM_PossumPipe_OBJID		26
#define NAAAIM_TPM2cmd_OBJID		27
#define NAAAIM_LocalDuct_OBJID		28
#define NAAAIM_Base64_OBJID		29

#define NAAAIM_Netconfig_OBJID		30
#define NAAAIM_IPsec_OBJID		31
#define NAAAIM_SoftwareTPM_OBJID	32
#define NAAAIM_IDengine_OBJID		33
#define NAAAIM_Identity_OBJID		34
#define NAAAIM_EDIpacket_OBJID		35
#define NAAAIM_MGMTsupvr_OBJID		36

#define NAAAIM_SRDEmetadata_OBJID	37
#define NAAAIM_SRDEloader_OBJID		38
#define NAAAIM_SRDEenclave_OBJID	39
#define NAAAIM_SRDEsigstruct_OBJID	40

#define NAAAIM_Actor_OBJID		41
#define NAAAIM_Subject_OBJID		42
#define NAAAIM_ExchangeEvent_OBJID	43
#define NAAAIM_ISOidentity_OBJID	44
#define NAAAIM_ContourPoint_OBJID	45
#define NAAAIM_SRDEquote_OBJID		46
