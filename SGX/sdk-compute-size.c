/** \file
 * This file contains the implementation of a utility which is
 * used to compute the sizes of various structures used in the Intel
 * SGX System Development Kit.
 *
 * The strategy in SGX fusion is to have very limited dependency on
 * the Intel SDK.  As a result structure definitions are kept
 * statically scoped to the objects or utilities which actually use
 * them.
 *
 * Since many of the structures used with the SGX service enclaves and
 * provisioning tools are composite structures it becomes extremely
 * difficult to compute the correct sizes and configurations of the
 * structures.  This utility is designed to use the SGXSDK include
 * files to compute the sizes of various structures to create
 * equivalent sized structures in the SGXfusion runtime.
 */

/*
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 */

/* Definitions local to this file. */
#define PGM "sdk-compute-size"


#include <stdio.h>

#include <epid_pve_type.h>
#include <sgx_tseal.h>
#include <provision_msg.h>


/*
 * Main program.
 */

extern int main(int argc, char *argv[])

{
	fprintf(stdout, "Blob size: %u\n", SGX_TRUSTED_EPID_BLOB_SIZE_SDK);
	fprintf(stdout, "EpidSignature: %lu\n", sizeof(EpidSignature));
	fprintf(stdout, "NrProof: %lu\n", sizeof(NrProof));
	fprintf(stdout, "Join proof with escrow: %lu\n", \
		sizeof(join_proof_with_escrow_t));
	fprintf(stdout, "message 2 blob input: %lu\n", \
		sizeof(proc_prov_msg2_blob_input_t));

	return 0;
}
