# **************************************************************************
# * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
# *
# * Please refer to the file named Documentation/COPYRIGHT in the top of
# * the source tree for copyright and licensing information.
# **************************************************************************/

#
# Java source definitions.
#
SRCS = AImanager.java LoginPanel.java Target.java CbootManager.java	 \
	ContourManager.java TrajectoryManager.java ForensicsManager.java \
	CanisterMonitor.java ConnectionManager.java EventManager.java


#
# Variable definitions for Java development.
#
JAVAC = javac


#
# Compilation directives.
#
%.class: %.java
	$(JAVAC) $<


#
# Automatic definition of classes and objects.
#
CLASSES = ${SRCS:java=class}


#
# Targets
#
classes: $(CLASSES)

jar: classes
	rm -f AImanager.jar;
	jar cf AImanager.jar *.class;

docs:
	javadoc ${SRCS}

clean-docs:
	rm -f *.html *.css package-list
	rm -rf com

clean:
	/bin/rm -f *.class *~
