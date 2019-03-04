/**
 * \file
 * This file contains the class which implements the entry point for
 * initiating a CbootManager based communicatioo channel with a remote
 * canister instance.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Package and import statements here. */
import java.util.Vector;

import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.event.KeyListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;

import javax.swing.*;


/**
 * The class <code>LoginPanel</code> implements a window for initiating
 * login to a storage target server.
 */
public class LoginPanel
    extends JFrame {

    private JButton loginb;

    private JMenuBar mb;

    private JPanel TargetPane;

    private JTextField hosttext,
		       porttext,
		       canname;

    private JPasswordField pintext;

    private JTabbedPane TargetTabs;

    private Target target;


    /**
     * Creates a new instance of widget for <code>LoginPanel</code>
     * implmenting out a target login.
     *
     * @param mb a <code>JMenuBar</code> value which is <bold>CURRENTLY
     * UNKNOWN</bold> as to its need.
     * @param smta A <code>SysMsgTextArea</code> value which serves as
     * the destination for error messages.
     */
    public LoginPanel(final JMenuBar mb, JTabbedPane tabs) {

        this.mb = mb;
	this.setTitle("Target login.");

	TargetTabs = tabs;

        // first we create the layout and constraint objects for all to share
        GridBagLayout gbl      = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gbl);


        /* Setup the storage target pane. */
        TargetPane = new JPanel();
        TargetPane.setLayout(gbl);
        TargetPane.setBorder(BorderFactory.createCompoundBorder(
		BorderFactory.createTitledBorder("Canister Target:"),
        	BorderFactory.createEmptyBorder(5,5,5,5))
	);

	/*        java.awt.Dimension ptfs = new java.awt.Dimension(200, 20); */

	java.awt.Dimension ptfs = new java.awt.Dimension(200, 30);

        JLabel hostlabel = new JLabel("Hostname:");
        hostlabel.setHorizontalAlignment(SwingConstants.RIGHT);
        JLabel portlabel = new JLabel("Port:");
	portlabel.setHorizontalAlignment(SwingConstants.RIGHT);
        hosttext = new JTextField();
        hosttext.setPreferredSize(ptfs);
	hosttext.setText("localhost");
        porttext = new JTextField();
        porttext.setPreferredSize(ptfs);
	porttext.setText("11990");

        gbc.insets = new Insets(5,5,5,5);
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor =  GridBagConstraints.WEST;
        gbc.weightx = 1;
        gbc.weighty = 0;
        gbc.gridwidth = 1;

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbl.setConstraints(hostlabel, gbc);
        TargetPane.add(hostlabel);

	gbc.gridx = 1;
        gbl.setConstraints(hosttext, gbc);
	TargetPane.add(hosttext);

	gbc.gridx = 0;
        gbc.gridy = 1;
        gbl.setConstraints(portlabel, gbc);
        TargetPane.add(portlabel);

	gbc.gridx = 1;
        gbl.setConstraints(porttext, gbc);
        TargetPane.add(porttext);


        /* Setup user login pane. */
        JPanel UserLoginPane = new JPanel();

        UserLoginPane.setLayout(gbl);
        UserLoginPane.setBorder(BorderFactory.createCompoundBorder(
		BorderFactory.createTitledBorder("Canister:"),
		BorderFactory.createEmptyBorder(5,5,5,5))
	);

        JLabel Userl = new JLabel("Name:");
        Userl.setHorizontalAlignment(SwingConstants.RIGHT);
        JLabel Passwordl = new JLabel("Pincode:");
        Passwordl.setHorizontalAlignment(SwingConstants.RIGHT);
        canname = new JTextField();
        canname.setPreferredSize(ptfs);
        pintext = new JPasswordField();
        pintext.setPreferredSize(ptfs);

        gbc.insets = new Insets(5,5,5,5);
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor =  GridBagConstraints.EAST;
        gbc.weightx = 0.0;
        gbc.weighty = 0.0;
        gbc.gridwidth = 1;

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbl.setConstraints(Userl, gbc);
        UserLoginPane.add(Userl);

        gbc.gridy = 1;
        gbl.setConstraints(Passwordl, gbc);
        UserLoginPane.add(Passwordl);

        gbc.anchor =  GridBagConstraints.WEST;
        gbc.weightx = 1.0;
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbl.setConstraints(canname, gbc);
        UserLoginPane.add(canname);

        gbc.gridy = 1;
        gbl.setConstraints(pintext, gbc);
        UserLoginPane.add(pintext);

        /* Configure button panel. */
        JPanel ButtonPane = new JPanel();
        ButtonPane.setLayout(gbl);

        loginb = new JButton("Login");
	loginHandler login = new loginHandler();
        loginb.addActionListener(login);
	loginb.addKeyListener(login);

        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor =  GridBagConstraints.CENTER;
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbl.setConstraints(loginb, gbc);
        ButtonPane.add(loginb);


	/* Add objects to main pane. */
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor =  GridBagConstraints.NORTH;
        gbc.gridwidth = 4;

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbl.setConstraints(TargetPane, gbc);
        add(TargetPane);

        gbc.gridy = 2;
        gbl.setConstraints(UserLoginPane, gbc);
        add(UserLoginPane);

        gbc.gridy = 3;
        gbc.weighty = 1.0;
        gbl.setConstraints(ButtonPane, gbc);
        add(ButtonPane);
    }


    /**
     * The inner class <code>loginHandler</code> is invoked when the Login
     * button is pressed and handles creation of the secured login
     * session with ISME.
     */
    class loginHandler
	implements ActionListener, KeyListener {

	/**
	 * The <code>canister</code> variable holds the username to be used to
	 * authenticate to the target.
	 */
	private String canister;

	/**
	 * The <code>pin</code> variable holds pincode to be used to
	 * authenticate the user.
	 */
	private String pin;


	/**
	 * The <code>getCredentials</code> method checks to see whether or
	 * not the user has entered an authentication identity and
	 * password.  If so it attempts to use those to obtain a set of
	 * Kerberos credentials to use as the basis for obtaining a
	 * secured context with ISME.
	 *
	 * @return a <code>boolean</code> value indicating whether or not
	 * an error was encountered while acquiring the credentials.
	 */
	private boolean getCredentials() {

	    /* Fetch the username and password to be used for the login. */
	    try {
		canister = canname.getText();
		pin = new String(pintext.getPassword());
		canname.setText("");
		pintext.setText("");
	    } catch ( NullPointerException e ) {
		return(true);
	    }

	    if ( canister.equals("") )
		return(true);

 	    return(true);
 	}


	/**
	 * The <code>actionPerformed</code> method is overridden to
	 * carry out the actions necessary for crating a secured
	 * communications conduit.
	 *
	 * This involves acquisition of necessary credentials if a
	 * administrative user identity and password were specified
	 * in the login panel.
	 *
	 * @param e an <code>ActionEvent</code> value describing the
	 * action which is being handled.
	 */
	public void actionPerformed(ActionEvent e) {

	    /*
	     * Sanity checks.  Return without login if an error was
	     * encountered while obtaining credentials or if a username
	     * was not specified.
	     */
	    if ( getCredentials() != true )
		return;

	    if ( canister.equals("") )
		return;

	    target = new Target(hosttext.getText(), porttext.getText(),
				canister, pin);

	    if ( !target.init() ) {
		JOptionPane.showMessageDialog(loginb, "Target connection "
					      + "error: "
					      + target.get_error(),
					      "Target Login Error",
					      JOptionPane.ERROR_MESSAGE);
		LoginPanel.this.setVisible(false);
		LoginPanel.this.dispose();
		return;
	    }

	    TargetTabs.addTab(hosttext.getText() + "[" + porttext.getText() +
			      "]:" + canister, target);

	    LoginPanel.this.setVisible(false);
	    LoginPanel.this.dispose();
	    return;
	}


	/**
	 * The <code>keyType</code> method is overidden to catch keypress
	 * events.  If a carriage return is pressed the method which would
	 * normally be bound to the button click event is called.
	 *
	 * @param kev a <code>KevyEvent</code> value describing the key
	 * action being processed.
	 */
	public void keyTyped(KeyEvent kev) {

	    if ( kev.getKeyChar() == KeyEvent.VK_ENTER ) {
		actionPerformed(null);
	    }
	    return;
	}


	/* Stub methods to fulfill the KeyListener interface. */
	public void keyPressed(KeyEvent kev) {}
	public void keyReleased(KeyEvent kev) {}
    }

}
