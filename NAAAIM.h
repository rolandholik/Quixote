/**************************************************************************
 * (C)Copyright 2003, The Open Hurderos Foundation. All rights reserved.
 **************************************************************************/


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

#define NAAAIM_Netconfig_OBJID		21
#define NAAAIM_IPsec_OBJID		22
#define NAAAIM_PossumPacket_OBJID	23
#define NAAAIM_SoftwareStatus_OBJID	24
#define NAAAIM_SoftwareTPM_OBJID	25
#define NAAAIM_TPMcmd_OBJID		26
#define NAAAIM_IDmgr_OBJID		27
#define NAAAIM_Ivy_OBJID		28
#define NAAAIM_IDengine_OBJID		29
