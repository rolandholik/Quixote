/**
 * \file
 * This file implements an object which has the responsibility of
 * managing the display of connection information for a remote
 * host.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Package and import statements follow below. */
import java.util.ArrayList;

import java.awt.Container;
import java.awt.Font;
import java.awt.Component;

import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

import javax.swing.JTextArea;
import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JButton;
import javax.swing.BoxLayout;


/**
 * The <code>ContoursManager</code> object encapsulates all of the
 * functionality for the management of the tab that displays the behavioral
 * contour map of a canister.
 */

public class ConnectionManager
    extends JFrame {


    /**
     * The <code>JTextArea</code> object that will be used to manage
     * the connection information from the remote target.
     */
    private JTextArea Connection;


    /**
     * A no arguement constructor call for creating a
     * <code>ConnectionManager</code> object.
     *
     * @param target A <code>CbootManager</code> object which
     * provides a communication channel to a canister instance.
     */
    public ConnectionManager() {

	super("Connection information.");

	Connection = new JTextArea(20, 80);
	Connection.setFont(new Font("monospaced", Font.PLAIN, 16));


	/* Set the window up to be destroy if it is closed. */
	this.addWindowListener(new WindowAdapter() {
		public void windowClosing(WindowEvent e) {
		    ConnectionManager.this.setVisible(false);
		    ConnectionManager.this.dispose();
		}
	    });

	/* Setup a vertical layout for the text pane and control buttons. */
	Container cp = getContentPane();
	cp.setLayout(new BoxLayout(cp, BoxLayout.Y_AXIS));
	cp.add(new JScrollPane(Connection));

	JButton close = new JButton("Close");
	close.setActionCommand("cancel");
	close.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent evt) {
		    ConnectionManager.this.dispose();
		    return;
		}
	    });
	close.setAlignmentX(Component.CENTER_ALIGNMENT);
	cp.add(close);

	return;
    }


    /**
     * The <code>display</code> object sends a request to the
     * remote target and loads the information information into
     * the current set of behavioral contour points from a canister instance.
     *
     * @return A <code>boolean</code> value is used to indicate the status
     * of the contour retrieval.  A true command is used to indicate the
     * update was successful.
     */
    public boolean display_connection(CbootManager Target) {

	int lp;

	ArrayList<String> lines = new ArrayList<String>();


	if ( !Target.get_connection(lines) )
	    return false;

	for (lp= 0; lp < lines.size(); ++lp)
	    Connection.append(lines.get(lp) + "\n");
	Connection.setCaretPosition(0);

	return true;
    }

}
