#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <SGX.h>
#include <SGXfusion.h>

#include "LocalTarget-interface.h"


/**
 * External ECALL 0.
 *
 * This method implements the generation of a REPORTDATA structure
 * destined for the specified target enclave.
 *
 * \return	A boolean value is used to indicate whether or not
 *		generation of the report succeeded.  A false value
 *		indicates the report data is not valid.  A true
 *		value indicates the report data is valid.
 */

void get_report(struct SGX_targetinfo *target, struct SGX_report *report)

{
	char report_data[64] __attribute__((aligned(128)));


	memset(report, '\0', sizeof(struct SGX_report));
	memset(report_data, '\0', sizeof(report_data));

	enclu_ereport(target, report, report_data);

	return;
}
