# ***************************************************************************
# (C)Copyright 2010, Enjellic Systems Development, LLC. All rights reserved.
# ***************************************************************************


#
# Java compiler.
#
JAVAC = javac


#
# Source definitions and automatic definitions of classes.
#
SRCS =	naaaim.java

CLASSES = ${SRCS:java=class}


#
# Compilation directives.
#
%.class: %.java
	${JAVAC} $<;


#
# Targets.
#
classes: ${CLASSES}

docs:
	javadoc ${SRCS}

clean-docs:
	rm -f *.html *.css package-list
	rm -rf com

clean:
	/bin/rm -f *.class *~ debug.out
