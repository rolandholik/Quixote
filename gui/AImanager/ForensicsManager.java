/**
 * \file
 * This file implements an object which has the responsibility of
 * managing the forensics path of an ISOidentity model instance.
 */

/*
 * (C)Copyright 2018, IDfusion, LLC. All rights reserved.
 */


/* Package and import statements follow below. */
import java.util.ArrayList;

import java.awt.Font;

import javax.swing.JTextArea;


/**
 * The <code>ForensicsManager</code> object encapsulates all of the
 * functionality for the management of the tab that displays the behavioral
 * forensics of a remote canister.
 */

public class ForensicsManager
    extends JTextArea {


    /**
     * The following integer value is used to count the number of
     * forensics events.
     */
    int forensics_cnt = 0;

    /**
     * The following boolean value is used to indicate if new forensics
     * information has become available.
     */
    boolean new_forensics;


    /**
     * Set to an error message generated by the communication parsers.
     */
    private String Error_Message;

    /**
     * The object linking this instance of a <code>ContourManager</code>
     * to a canister manager that is being interrogated.
     */
    private CbootManager Target;


    /**
     * The constructor call for creating a <code>ForensicsManager</code>
     * object.
     *
     * @param target A <code>CbootManager</code> object which
     * provides a communication channel to a canister instance.
     */
    public ForensicsManager(CbootManager target) {

	Target = target;
	super.setFont(new Font("monospaced", Font.PLAIN, 16));

	return;
    }


    /**
     * The <code>update_forensics</code> sends a command request to obtain
     * the current set of behavioral contour points from a canister instance.
     *
     * @return A <code>boolean</code> value is used to indicate the status
     * of the forensics interrogation.  A true value indicates that new
     * forensics information is available.
     */
    public boolean update_forensics() {

	int lp;

	ArrayList<String> forensics = new ArrayList<String>();


	if ( !Target.get_forensics(forensics) )
	    return false;

	if ( forensics.size() > forensics_cnt ) {
	    this.selectAll();
	    this.replaceSelection("");

	    for (lp= 0; lp < forensics.size(); ++lp)
		this.append(forensics.get(lp) + "\n");

	    new_forensics = true;
	    forensics_cnt = forensics.size();
	}


	return true;
    }


    /**
     * The <code>have_forensics</code> method is an accessor method that
     * returns the state variable that indicates the presence of new
     * forensics information.
     *
     * @return The value of the new_forensics private variable is
     * returned.
     */
    public boolean have_forensics() {

	return new_forensics;
    }


    /**
     * The <code>clear_forensics</code> method is an accessor method that
     * is used to clear the state of the new_forensics variable.
     */
    public void clear_forensics() {

	new_forensics = false;
	return;
    }

}