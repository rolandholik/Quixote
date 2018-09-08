# ***************************************************************************
# (C)Copyright 2018, IDfusion, LLCLLC. All rights reserved.
# ***************************************************************************

#
# Java source definitions.
#
SRCS = AImanager.java LoginPanel.java Target.java CbootManager.java \
	ContourManager.java TrajectoryManager.java ForensicsManager.java


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

docs:
	javadoc ${SRCS}

clean-docs:
	rm -f *.html *.css package-list
	rm -rf com

clean:
	/bin/rm -f *.class *~
