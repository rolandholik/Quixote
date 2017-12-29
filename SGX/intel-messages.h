/** \file
 * This file contains definitions for messages which are processed by
 * the Intel servers.  The enumerated values are used to query the
 * SGXmessage object for messages which match a specified type.
 *
 * The contents of this file are taken from the following file in
 * the Intel Linux SDK:
 *
 * psw/ae/internal/tlv_message.h
 */



enum SGX_message_types {
	TLV_CIPHER_TEXT=0,
	TLV_BLOCK_CIPHER_TEXT,
	TLV_BLOCK_CIPHER_INFO,
	TLV_MESSAGE_AUTHENTICATION_CODE,
	TLV_NONCE,
	TLV_EPID_GID,
	TLV_EPID_SIG_RL,
	TLV_EPID_GROUP_CERT,
	/*SE Provisioning Protocol TLVs*/
	TLV_DEVICE_ID,
	TLV_PS_ID,
	TLV_EPID_JOIN_PROOF,
	TLV_EPID_SIG,
	TLV_EPID_MEMBERSHIP_CREDENTIAL,
	TLV_EPID_PSVN,
	/*PSE Provisioning Protocol TLVs*/
	TLV_QUOTE,
	TLV_X509_CERT_TLV,
	TLV_X509_CSR_TLV,
	/*End-point Selection Protocol TLVs*/
	TLV_ES_SELECTOR,
	TLV_ES_INFORMATION,
	/* EPID Provisioning Protocol TLVs Part 2*/
	TLV_FLAGS,
	/* PSE Quote Signature*/
	TLV_QUOTE_SIG,
	TLV_PLATFORM_INFO_BLOB,
	/* Generic TLVs*/
	TLV_SIGNATURE,
	/* End-point Selection Protocol TLVs*/
	TLV_PEK,
	TLV_PLATFORM_INFO,
	TLV_PWK2,
	TLV_SE_REPORT
};
