/**

* This file contains the entry point for managing an instance of
* the cboot-mgr utility.  This utility is used to implement
* enclave<-> based communications with a remote canister instance.
*/

/**
 * (C)Copyright 2018, IDfusion, LLC. All rights reserved.
 */


/*
 * Package and import statements follow below.
 */

import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.io.IOException;

import java.util.ArrayList;


/**
 * General class documentation goes here.
 */

public class CbootManager {

    private String Hostname;
    private String Port;

    /**
     * The cboot-mgr process descriptor.
     */
    Process Cboot_mgr;

    /**
     * The standard input to the cboot-mgr instance.
     */
    OutputStream Stdin;

    /**
     * The standard output reader.
     */
    BufferedReader Stdout;

    /**
     * The standard error reader.
     */
    BufferedReader Stderr;



    /**
     * A no arguement constructor for a <code>CbootManager</code> instance.
     */
    public CbootManager() {

	return;
    }


    /**
     * The <code>init</code> method starts a cboot-mgr process
     * instance and sets up the I/O channels that will be used
     * to fetch output from the process.
     *
     * @param hostname is a <code>String</code> variable containing the
     * message to connect to.
     * @param port is a <code>String</code> variable the port number
     * on the remote host to connect to.
     * @return a <code>boolean</code> value is used to indicate the
     * status of the transaction.
     */
    public boolean init(String hostname, String port) {

	boolean retn = false;

	System.out.println("Hostname: " + hostname);
	System.out.println("Port: " + port);
	if ( port == null )
	    port = "11990";
	String cmd[] = {"cboot-mgr", "-h", hostname, "-p", port};

	Hostname = hostname;
	Port = port;


	try {
	    ProcessBuilder cboot = new ProcessBuilder(cmd);
	    Cboot_mgr = cboot.start();

	    /* Setup stdout and stderr. */
	    InputStream outs = Cboot_mgr.getInputStream();
	    Stdout = new BufferedReader(new InputStreamReader(outs));

	    InputStream errs = Cboot_mgr.getInputStream();
	    Stderr = new BufferedReader(new InputStreamReader(errs));

	    Stdin = Cboot_mgr.getOutputStream();

	    /* Capture the connection message. */
	    Stdout.readLine();
	    retn = true;
	}
	catch (IOException ex) {
	    System.err.println("Execution error: " + ex);
	}


	return retn;
    }


    /**
     * The <code>get_contours</code> method that prints the content of the
     * current behavioral map.
     *
     * @param hostname is a <code>String</code> variable containing the
     * message to connect to.
     * @param port is a <code>String</code> variable the port number
     * on the remote host to connect to.
     * @return a <code>boolean</code> value is used to indicate the
     * status of the transaction.
     */
    public boolean get_contours(String hostname, String port) {

	boolean retn = false;

	String output;


	try {
	    /* Send command input to the cboot-mgr. */
	    Stdin.write("show contours\n".getBytes());
	    Stdin.flush();


	    /* Extract command output. */
	    while ( (output = Stdout.readLine()) != null ) {
		System.out.println(output);
	    }
	}
	catch (IOException ex) {
	    System.err.println("Execution error: " + ex);
	}


	return true;
    }


    /**
     * The <code>get_contours</code> method that returns the current
     * behavioral map in the form of a list.
     *
     * @param contours is a <code>ArrayList<String></code> object that
     * will be loaded with the contours.
     *
     * @return a <code>boolean</code> value is used to indicate the
     * status of the transaction.
     */
    public boolean get_contours(ArrayList<String> contours) {

	boolean retn = false;

	int lp,
	    linecnt;

	String output,
	       size = "size: ";


	try {
	    /* Send command input to the cboot-mgr. */
	    Stdin.write("show contours\n".getBytes());
	    Stdin.flush();


	    /* Extract command output. */
	    output = Stdout.readLine();
	    if ( !output.matches(".*Contour size: [0-9]*") )
		return false;

	    linecnt = output.lastIndexOf(size);
	    linecnt = Integer.parseInt(output.substring(linecnt +
							size.length()));
	    for (lp= 0; lp < linecnt; ++lp) {
		output = Stdout.readLine();
		contours.add(output);
	    }
	}
	catch (IOException ex) {
	    System.err.println("Execution error: " + ex);
	}


	return true;
    }


    /**
     * The <code>get_trajectory</code> method that returns the current
     * behavioral map in the form of a list.
     *
     * @param trajectory is a <code>ArrayList<String></code> object that
     * will be loaded with the contours.
     *
     * @return a <code>boolean</code> value is used to indicate the
     * status of the transaction.
     */
    public boolean get_trajectory(ArrayList<String> trajectory) {

	boolean retn = false;

	int lp,
	    linecnt;

	String output,
	       size = "size: ";


	try {
	    /* Send command to the cboot-mgr. */
	    Stdin.write("show trajectory\n".getBytes());
	    Stdin.flush();


	    /* Extract command output. */
	    output = Stdout.readLine();
	    if ( !output.matches(".*Trajectory size: [0-9]*") )
		return false;

	    linecnt = output.lastIndexOf(size);
	    linecnt = Integer.parseInt(output.substring(linecnt +
							size.length()));
	    for (lp= 0; lp < linecnt; ++lp) {
		output = Stdout.readLine();
		trajectory.add(output);
	    }
	}
	catch (IOException ex) {
	    System.err.println("Execution error: " + ex);
	}


	return true;
    }


    /**
     * The <code>get_forensics</code> method that returns the current
     * forensics path in the form of a list of events.
     *
     * @param forensics is a <code>ArrayList<String></code> object that
     * will be loaded with the contours.
     *
     * @return a <code>boolean</code> value is used to indicate the
     * status of the transaction.
     */
    public boolean get_forensics(ArrayList<String> forensics) {

	boolean retn = false;

	int lp,
	    linecnt;

	String output,
	       size = "size: ";


	try {
	    /* Send command to the cboot-mgr. */
	    Stdin.write("show forensics\n".getBytes());
	    Stdin.flush();


	    /* Extract command output. */
	    output = Stdout.readLine();
	    if ( !output.matches(".*Forensics size: [0-9]*") )
		return false;

	    linecnt = output.lastIndexOf(size);
	    linecnt = Integer.parseInt(output.substring(linecnt +
							size.length()));
	    for (lp= 0; lp < linecnt; ++lp) {
		output = Stdout.readLine();
		forensics.add(output);
	    }
	}
	catch (IOException ex) {
	    System.err.println("Execution error: " + ex);
	}


	return true;
    }


    /**
     * The <code>get_connection</code> method that returns the connection
     * information from the remote canister instances.
     *
     * @param lines is a <code>ArrayList<String></code> object that
     * will be loaded with the connection information..
     *
     * @return a <code>boolean</code> value is used to indicate the
     * status of the transaction.
     */
    public boolean get_connection(ArrayList<String> lines) {

	boolean retn = false;

	int lp,
	    linecnt;

	String output,
	       size = "size: ";


	try {
	    /* Send command to the cboot-mgr. */
	    System.err.println("Sending connection request.");
	    Stdin.write("show connection\n".getBytes());
	    Stdin.flush();


	    /* Extract command output. */
	    output = Stdout.readLine();
	    while ( !retn ) {
		output = Stdout.readLine();
		lines.add(output);
		if ( output.matches("Platform status: OK") )
			return true;
		if ( output.matches(".*Extended group id.*") )
		    return true;
	    }
	}
	catch (IOException ex) {
	    System.err.println("Execution error: " + ex);
	}


	return true;
    }


    /**
     * The <code>get_events</code> method that returns the current
     * forensics path in the form of a list of events.
     *
     * @param events is a <code>ArrayList<String></code> object that
     * will be loaded with the contours.
     *
     * @return a <code>boolean</code> value is used to indicate the
     * status of the transaction.
     */
    public boolean get_events(ArrayList<String> events) {

	boolean retn = false;

	int lp,
	    linecnt;

	String output,
	       size = "size: ";


	try {
	    /* Send command to the cboot-mgr. */
	    System.err.println("Sending events request.");
	    Stdin.write("show events\n".getBytes());
	    Stdin.flush();


	    /* Extract command output. */
	    output = Stdout.readLine();
	    if ( !output.matches(".*AI event size: [0-9]*") )
		return false;

	    linecnt = output.lastIndexOf(size);
	    linecnt = Integer.parseInt(output.substring(linecnt +
							size.length()));
	    for (lp= 0; lp < linecnt; ++lp) {
		output = Stdout.readLine();
		events.add(output);
	    }
	}
	catch (IOException ex) {
	    System.err.println("Execution error: " + ex);
	}


	return true;
    }


    /**
     * The <code>logout</code> method is a no arguement method that
     * sends a termination command to the remote canister instance.
     *
     * @return a <code>boolean</code> value is used to indicate the
     * status of the transaction.
     */
    public boolean logout() {

	boolean retn = true;


	try {
	    /* Send the quit command to the cboot-mgr. */
	    Stdin.write("quit\n".getBytes());
	    Stdin.flush();

	    if ( Cboot_mgr.waitFor(5, java.util.concurrent.TimeUnit.SECONDS) )
		retn = true;
	    else
		System.err.println("cboot-mgr not responding to termination.");
	}
	catch (IOException ex) {
	    System.err.println("I/O error: " + ex);
	}
	catch (InterruptedException ex ) {
	    System.err.println("Interrupt error: " + ex);
	}


	return retn;
    }

}
