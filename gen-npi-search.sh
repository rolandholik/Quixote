#! /bin/bash

# **************************************************************************
# * (C)Copyright IDfusion, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/

#
# Utility program to generate an originating identity databse.
#


function gen_id() {
	/u/usr/src/NAAAIM/genid -D -f /u/usr/sources/NAAAIM/orgid.txt -c $1 \
		-a $2 -i 000-00-0000 -o org1;
	return;
}


if [ -n "$*" ]; then
	for NPI in $*;
	do
		set `psql -A -F " " -t -c "select number, orgkey from npi \
			where number = $NPI" keys`;
		gen_id $1 $2;
	done;
else
	# export FETCH_COUNT=1000;
	# psql -A -F " " -t -c "select number, orgkey from npi" keys | \
	while read Input
	do
		set $Input;
		gen_id $1 $2;
	done;
fi;


exit 0;

