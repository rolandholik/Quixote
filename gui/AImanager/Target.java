/**
 * \file
 * This file implements an object responsible for managing communications
 * to to multiple remote canister instances.
 */

/*
 * (C)Copyright 2018, Enjellic Systems Development, LLC. All rights reserved.
 */


/* Package and import statements here. */
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JScrollPane;

import javax.swing.JTree;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;


/**
 * The <code>Target</code> class manages communications between
 * the client and a remote server.  The server communications are
 * managed by an instance of a <code>TargetConnection</code> imbedded
 * in this class.
 * <p>
 * The interface with the user is presented through a tabbed pane
 * which this object is imbedded in.
 */

public class Target
    extends JPanel {

    private int forensics_cnt = 0;

    private String Error_Message;
    private String host = null;
    private String port = null;
    private String user = null;
    private String pwd  = null;

    private CbootManager Remote;

    private JTabbedPane ModelTabs;

    private ContourManager Contours;
    private TrajectoryManager Trajectory;
    private ForensicsManager Forensics;


    /**
     * The <code>initialize_graphics</code> is called by the constructor
     * to create the widgets which are imbedded in the panel managed
     * by the object.
     */
    private void initialize_graphics() {


	/* Setup tabs for ISOidentity parameters. */
	ModelTabs = new JTabbedPane();
//	ModelTabs.addChangeListener(new ChangeListener() {
//		public void stateChanged(ChangeEvent evt) {
//		    CurrentTarget = (Target) TargetTabs.getSelectedComponent();
//		    return;
//		}
//	    });

	Contours = new ContourManager(Remote);
	ModelTabs.addTab("Contours", new JScrollPane(Contours));

	Trajectory = new TrajectoryManager(Remote);
	ModelTabs.addTab("Trajectory", new JScrollPane(Trajectory));

	Forensics = new ForensicsManager(Remote);
	ModelTabs.addTab("Forensics", new JScrollPane(Forensics));


	/* Layout the panes containing the two trees. */
	this.setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
	this.add(ModelTabs);
	this.revalidate();
	this.repaint();


	return;
    }


    /**
     * Constructor to create a new <code>msgListener</code> instance.
     *
     * @param name <code>String</code> value containing the name of
     * the host to initiate a connection to.
     * @param port <code>String</code> value containing the port number
     * on the remote host to connect to.
     * @param user <code>String</code> value containing the username
     * to be used to log into the target server.
     * @param pwd <code>String></code> value containing the password to
     * be used with the specified username to authenticate the login.
     */
    public Target(String host, String port, String user, String pwd) {

        this.host = host;
        this.port = port;
	this.user = user;
	this.pwd  = pwd;

	Remote = new CbootManager();
	initialize_graphics();
    }


    /**
     * The <code>init</code> method initializes a secured conduit
     * connection to a remote ISME implementation.
     *
     * @param user a <code>String</code> value containing the name of
     * the user which will be used to initiate the secured conduit.
     * @return a <code>boolean</code> value indicating whether or not the
     * connection conduit was properly setup.
     */
    public boolean init() {

	if ( !Remote.init(host, port) ) {
	    System.err.println("Cannot open connection");
	    return false;
	}

	if ( !login() )
	    return false;

	synchronized ( this ) {
	    if ( !Contours.update_contours() )
		return false;
	    if ( !Trajectory.update_trajectory() )
		return false;
	    if ( !Forensics.update_forensics() )
		return false;
	}


	return true;
    }


    /**
     * The <code>poll_forensics</code> is a method that implements the
     * polling of a remote canister instance for the presence of behavioral
     * violations.
     *
     * @return A <code>boolean</code> value is returned to indicate the
     * status of whether or not additional forensics information has
     * become available.  A true value indicates that new entries are
     * present for this target.
     */
    public synchronized boolean poll_forensics() {

	boolean retn = false;

	synchronized ( this ) {
	    System.err.println("\tPolling: " + host + ":" + port);
	    retn = Forensics.update_forensics();

	    System.err.println("Forensics lines: " + Forensics.getLineCount());
	    System.err.println("Forensics rows:  " + Forensics.getRows());
	}

	return Forensics.have_forensics();
    }


    /**
     * The <code>get_error</code> is an accessor method which returns
     * the error status of the underying connection.
     *
     * @return A <code>String</code> value containing the current
     * error message assigned to the remote target connection.
     */
    public String get_error() {

/*
	return Remote.get_error();
*/
	return "get_error";
    }


    /**
     * The <code>ping</code> method sends and processes a ping command
     * to the remote target.
     *
     * @return A <code>boolean</code> value is used to indicate if the
     * ping command was successful.  A true value indicates the target
     * server responded that its status was ok.  A false value indicates
     * an error.
     */
    public boolean ping() {

//	TargetCommand cmd = new TargetCommand("ping");

//	return Remote.send(cmd);
	return true;
    }


    /**
     * The <code>login</code> method sends the username and password to
     * the remote target and requests a login session to be started in
     * the security context of the specified user.
     *
     * @return A <code>boolen</code> value indicating whether or not the
     * login was successful.  A false value indicates the target server
     * was unable to authenticate the user.  A true value indicates the
     * login was successful.
     */
    public boolean login() {

//	TargetCommand cmd = new TargetCommand();


//	cmd.add_attribute("name", "login");
//	cmd.add_attribute("user", user);
//	cmd.add_attribute("pwd", pwd);
//	cmd.end_tag();

//	return Remote.send(cmd);
	return true;
    }


    /**
     * The <code>logout</code> method closes the remote canister
     * connection.
     *
     * @return A <code>boolean</code> value indicating whether or not the
     * logout request was successfully processed by the remote
     * target.  Regardless of the remote processing status the logout
     * request will physically terminate the socket connection.
     */
    public boolean logout() {

	boolean retn;


	retn = Remote.logout();
	return retn;
    }

}
