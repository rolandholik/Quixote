# **************************************************************************
# * (C)Copyright IDfusion, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/

#! /bin/sh

#
# Utility script to convert an old format identity token to a new format
# token.
#

if [ -z "$1" ]; then
	echo "No token specified.";
	exit 1;
fi;
New_Token="$1.new";

if [ -e "$New_Token" ]; then
	echo "Cannot overwrite file: $New_Token";
	exit 1;
fi;


sed -e 's/ORGANIZATION IDENTITY/ASSERTION/'	\
	-e 's/PATIENT IDENTITY/IMPLEMENTATION/' \
	-e 's/TOKEN KEY/AUTHENTICATION/' $1 > $New_Token;
if [ $? -ne 0 ]; then
	echo "Conversion failed: $1";
	exit 1;
fi;

mv $New_Token $1;
if [ $? -ne 0 ]; then
	echo "Error replacing token.";
	exit 1;
fi;

