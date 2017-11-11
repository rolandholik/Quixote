#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <SHA256.h>

#include "ISOidentity-interface.h"


void update_model(char *update)

{
	fprintf(stdout, "%s: Update: %s.\n", __func__, update);
	return;
}
