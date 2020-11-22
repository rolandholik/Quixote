/**
 * \file
 * This file defines a class that implements polling of all the
 * available canister targets.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Package and import statements follow below. */
import javax.swing.JTabbedPane;


/**
 * The <code>CanisterMonitor</code> object encapsulates all of the
 * functionality for the management of the tab that displays the behavioral
 * contour map of a canister.
 */

public class CanisterMonitor
    extends Thread {


    /**
     * The following integer value counts the number of

    /**
     * A reference to the tabbed pane that manages all of the currently
     * active canister targets.
     */
    private JTabbedPane Targets;


    /**
     * A single arguement constructor call for creating a
     * <code>CanisterMonitor</code> object.
     *
     * @param targeta the <code>JTabbedPane</code> object which manages
     * the set of remote canisters which are under management.
     */
    public CanisterMonitor(JTabbedPane targets) {

	Targets = targets;
	return;
    }


    /**
     * The <code>run</code> method drives the polling of the available
     * canister instances.
     *
     * @return A <code>boolean</code> value is used to indicate the status
     * of the contour retrieval.  A true command is used to indicate the
     * update was successful.
     */
    public void run() {

	int tabcnt,
	    lp = 0;

	Target target;


	while ( true ) {
	    System.err.println("Monitor loop: " + lp++ + " active tabs = " +
			       Targets.getTabCount());

	    tabcnt = Targets.getTabCount();
	    if ( tabcnt > 0 ) {
		for (lp= 0; lp < tabcnt; ++lp) {
		    target = (Target) Targets.getComponentAt(lp);
		    if ( target.poll_forensics() )
			Targets.setForegroundAt(lp, java.awt.Color.RED);
		}
	    }

	    try {
		Thread.sleep(10 * 1000);
	    } catch ( InterruptedException ie) {
		System.err.println("Interrupt exception: " + ie);
	    }
	}
    }

}
