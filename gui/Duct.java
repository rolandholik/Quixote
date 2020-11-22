/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/
/**
 *
 * @author  $Author$
 * @version $Revision$
 */


/*
 * Package and import statements follow below.
 */

import java.io.*;
import javax.net.ssl.*;


/**
 * General class documentation goes here.
 */

public class Duct {

    /**
     * The array <code>tls</code> is loaded with the protocols which
     * will be accepted by the client connection.
     */
    static String protocols[] = {"TLSv1"};

    /**
     * The variable <code>sock</code> represents the communication state
     * for an instance of a secured connection.
     */
    private SSLSocket sock = null;

    /**
     * The <code>buffer</code> variable holds the send/receive message
     * buffer.
     */
    private java.nio.ByteBuffer Buffer;

    /**
     * The <code>input</code> and <code>output</code> variables hold
     * the stream descriptors which will be used for I/O to and from
     * the remote host.
     */
    private java.io.DataInputStream input;
    private java.io.DataOutputStream output;


    /**
     * A no arguement constructor for a <code>Duct</code> instance.
     */
    public Duct() {

	return;
    }


    /**
     * The <code>connect</code> method initializes a secured TLSv1
     * connection to the specified port on a remote host.
     *
     * @param hostname is a <code>String</code> variable containing
     * the name of the remote host to connect to.
     * @param port is a <code>int</code> variable containing the name
     * of the remote port to connect to.
     * @return a <code>boolean</code> value is reurned to indicate
     * whether or not the connection was successful.
     */
    public boolean connect(String hostname, int port) {

	boolean retn = true;

	SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();

	try {
	    sock = (SSLSocket) f.createSocket(hostname, port);

	    sock.setEnabledProtocols(protocols);
	    sock.startHandshake();

	    input  = new java.io.DataInputStream(sock.getInputStream());
	    output = new java.io.DataOutputStream(new BufferedOutputStream(sock.getOutputStream()));
	} catch (Exception e) {
	    retn = false;
	}
	    
	return retn;
    }


    /**
     * The <code>send</code> method sends the contents of a
     * <code>String</code> over the duct.
     *
     * @param msg is a <code>String</code> variable containing the
     * message to be sent.
     * @return a <code>boolean</code> value is used to indicate the
     * status of the send.
     */
    public boolean send(String msg) {

	try {
	    output.writeInt(msg.length());
	    output.writeBytes(msg);
	    output.flush();
	}
	catch (Exception e) {
	    return false;
	}

	return true;
    }


    /**
     * The <code>receive</code> method receives a message sent from
     * the remote host and loads it into the <code>buffer</code>
     * variable.
     *
     * @return a <code>boolean</code> value is used to indicate the
     * status of the send.
     */
    public boolean receive() {


	try {
	    int length = input.readInt();
	    Buffer = java.nio.ByteBuffer.allocate(length);
		
	    for (int lp= 0; lp < length; ++lp)
		Buffer.put(input.readByte());
	}
	catch (Exception e) {
	    System.err.println("receive exception: " + e);
	    return false;
	}


	return true;
    }


    /**
     * The <code>toString</code> method returns a string representation
     * of the receive buffer.
     *
     * @return a <code>String</code> value representation of a received
     * buffer.  If the receive method has not been called a <null>
     * message is returned.
     */
    public String toString() {

	if ( Buffer == null )
	    return "<null>";

	return new String(Buffer.array());
    }


    /**
     * The <code>close</code> method closes the connection to the
     * remote host.
     *
     * @return a <code>boolean</code> value is used to indicate the
     * status of the close.
     */
    public boolean close() {

	try {
	    sock.close();
	}
	catch (Exception e) {
	    return false;
	}

	return true;
    }


    /**
     * The <code>getBuffer</code> method is an accessor method for
     * obtaining a copy of the receive buffer.
     */
    public java.nio.ByteBuffer getBuffer() {

	return Buffer;
    }


    /**
     * The <code>isprint</code> method tests whether or not the specified
     * character is printable.  This is a private help function for the
     * <code>isprint</code> meethod.
     *
     * @param A <code>char</code> value specifying the character to be
     * evaluated as being printable.
     * @return A <code>boolean</code> indicating whether or not the
     * character is printable.  A true value indicates the value is
     * printable.
     */
    private boolean isprint(char ch) {

	if (ch >= 'a' && ch <= 'z')
	    return true;
	if (ch >= 'A' && ch <= 'Z')
	    return true;
	if (ch >= '0' && ch <= '9')
	    return true;
	switch (ch) {
	    case '"':
	    case '/':
	    case '-':
	    case ':':
	    case '.':
	    case ',':
	    case '_':
	    case '$':
	    case '%':
	    case '\'':
	    case '(':
	    case ')':
	    case '[':
	    case ']':
	    case '<':
	    case '>':
	    case ' ':
	    case '=':
		return true;
	}

	return false;
    }


    /**
     * The <code>hexdump</code> method prints the contents of the I/O
     * buffer in hexadecimal dump format.
     */
    public void hexdump() {

	char cv;

	int lp  = 0,
	    col = 1;

	StringBuilder ascii = new StringBuilder(32);


	System.err.println("Buffer dump: " + Buffer.array().length + " bytes");

	while ( lp < Buffer.position() ) {
	    System.err.printf("%02x ", Buffer.get(lp));
	    cv = (char) Buffer.get(lp);
	    if ( isprint(cv) )
		ascii.append(cv);
	    else
		ascii.append(".");

	    if ( (col % 16) == 0 ) {
		col = 0;
		System.err.println(ascii);
		ascii.delete(0, ascii.length());
	    }
	    ++col;
	    ++lp;
	}

	if ( (--col % 16) != 0 ) {
	    while ( (col++ % 16) != 0 )
		System.err.print("   ");
	}
	if ( ascii.length() > 0 )
	    System.err.println(ascii);

	return;
    }

}
