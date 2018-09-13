/**
* \file
* This file contains the entry point for a graphical user interface
* utility for managing a remote Autonomous Introspection instance.
*/

/**
 * (C)Copyright 2018, IDfusion, LLC. All rights reserved.
 */


/* Package and import statements here. */
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.border.*;

import java.awt.event.*;
import java.awt.Component;
import java.awt.Point;


/**
 * General class documentation goes here.
 */

public class AImanager
	extends JFrame
	implements ComponentListener {

    static final int WIDTH = 800;
    static final int HEIGHT = 600;

    static final int MIN_WIDTH = 800;
    static final int MIN_HEIGHT = 600;

    static Target CurrentTarget;

    // Variables declaration - do not modify
    private JMenuBar mbMain;

    private JMenu FileMenu;
    private JMenu EditMenu;
    private JMenu ViewMenu;
    private JMenu HelpMenu;

    private JPanel SystemPanel;
    private JPanel UsersPanel;
    private JPanel jPanel1;
    private JPanel ServersPanel;
    private JPanel ServicesPanel;

    private JButton QuitButton;

    private JTabbedPane TargetTabs;

    private LoginPanel LoginPanel;


    /**
     * The <code>check_exit</code> method implements a confirmation to
     * verify whether or not an action should be taken.  Its primary
     * role is to ease indentation issues with private methods which
     * are attached to actions.
     *
     * @param locn a <code>Component</code> value describing the
     * screen location which the action is to be pinned to.
     * @param msg a <code>String</code> value containing the
     * message to be displayed requesting confirmation.
     * @param title a <code>String</code> value containing the title
     * of the window.
     *
     * @return a <code>boolean</code> value indicating whether a yes or
     * no option was selected.  A value of true implies a yes response.
     */
    private boolean confirm_action(Component locn, String msg, String title) {

        int n = JOptionPane.showConfirmDialog(locn, msg, title,
					      JOptionPane.YES_NO_OPTION);

        if ( n == JOptionPane.YES_OPTION )
	    return true;
	return false;
    }


    /**
     * Entry point for the graphical storage target management utility.
     *
     * @param args The command line arguments.
     */
    public static void main(String args[]) {

	CbootManager mgr = new CbootManager();

	try {
	    UIManager.setLookAndFeel(
	    	UIManager.getSystemLookAndFeelClassName()
	    );
	}
	catch ( UnsupportedLookAndFeelException e ) {
	    System.err.println("Unsupported look and feel.");
	}
	catch ( ClassNotFoundException e ) {
	    System.err.println("Class not found.");
	}
	catch ( InstantiationException e ) {
	    System.err.println("Instantiation exemption.");
	}
	catch ( IllegalAccessException e ) {
	    System.err.println("Illegal access.");
	}

	new AImanager();

	return;
    }


    /**
     * This method implements the initialization of the objects which
     * will be used to populate the primary pane.
     */
    private void initComponents() {

        mbMain = new JMenuBar();

	TargetTabs = new JTabbedPane();
	TargetTabs.addChangeListener(new ChangeListener() {
		public void stateChanged(ChangeEvent evt) {
		    CurrentTarget = (Target) TargetTabs.getSelectedComponent();
		    return;
		}
	    });


        /* Configure the menu bar and its dropdown components. */
        FileMenu = new JMenu("Target");
	FileMenu.setMnemonic(KeyEvent.VK_T);

        JMenuItem miLogin = new JMenuItem("Open", KeyEvent.VK_O);
        miLogin.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent evt) {
		    Component cmpt = (Component) FileMenu.getComponent();
		    Point pt = cmpt.getLocationOnScreen();
		    pt.translate(65, 27);

		    JFrame login = new LoginPanel(mbMain, TargetTabs);
		    login.setLocation(pt);
		    login.pack();
		    login.setVisible(true);
		}
	    });
        FileMenu.add(miLogin);


        JMenuItem miClose = new JMenuItem("Close", KeyEvent.VK_C);
        miClose.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
		if ( TargetTabs.getSelectedIndex() == -1 )
		    return;

		if ( !confirm_action(FileMenu, "Close target connection?",
				     "Close target connection.") )
		     return;

		Target tgt = (Target) TargetTabs.getSelectedComponent();
		tgt.logout();
		TargetTabs.remove(tgt);
		return;
            }
        });
        FileMenu.add(miClose);

        final JMenuItem miExit = new JMenuItem("Exit", KeyEvent.VK_E);
        miExit.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
		if ( !confirm_action(FileMenu, "Exit application?",
				     "Exit application.") )
		    return;

		AImanager.this.setVisible(false);
		AImanager.this.dispose();
		System.exit(0);
	    }
	 });
        FileMenu.add(miExit);

        mbMain.add(FileMenu);


        EditMenu = new JMenu("Edit");

        JMenuItem miUsers = new JMenuItem("Users");
//         miUsers.addActionListener(new ActionListener() {
//             public void actionPerformed(ActionEvent evt) {
//                 jTabbedPane1.setSelectedIndex(2);
//             }
//         });
        EditMenu.add(miUsers);

        JMenuItem miServers = new JMenuItem("Servers");
//         miServers.addActionListener(new ActionListener() {
//             public void actionPerformed(ActionEvent evt) {
//                 jTabbedPane1.setSelectedIndex(3);
//             }
//         });
        EditMenu.add(miServers);

        JMenuItem miServices = new JMenuItem("Services");
//         miServices.addActionListener(new ActionListener() {
//             public void actionPerformed(ActionEvent evt) {
//                 jTabbedPane1.setSelectedIndex(4);
//             }
//         });
        EditMenu.add(miServices);

        // disable Editing until logged in
        EditMenu.setEnabled(false);
        mbMain.add(EditMenu);


	/* Configure view options. */
        ViewMenu = new JMenu("View");
	FileMenu.setMnemonic(KeyEvent.VK_V);

        JMenuItem clear = new JMenuItem("Clear", KeyEvent.VK_C);
        clear.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent evt) {
		    int cnt = TargetTabs.getTabCount();
		    System.err.println("Clear tabs: " + cnt);
		    if ( cnt == 0 )
			return;

		    int index = TargetTabs.getSelectedIndex();
		    System.err.println("Clear index: " + index);
		    TargetTabs.setForegroundAt(index, java.awt.Color.BLACK);

		    Target tgt = (Target) TargetTabs.getSelectedComponent();
		    tgt.clear_forensics();
		}
	    });
        ViewMenu.add(clear);

//        JMenuItem miSystem = new JMenuItem("System Status");
//         miSystem.addActionListener(new ActionListener() {
//             public void actionPerformed(ActionEve/usr/srnt evt) {
//                 jTabbedPane1.setSelectedIndex(1);
//             }
//         });
//        ViewMenu.add(miSystem);

        ViewMenu.setEnabled(true);
        mbMain.add(ViewMenu);


	/* Configure help menu. */
        HelpMenu = new JMenu("Help");

        JMenuItem miAbout = new JMenuItem("About");
        HelpMenu.add(miAbout);

        JMenuItem miHelp = new JMenuItem("Help");
        HelpMenu.add(miHelp);

	mbMain.add(HelpMenu);

        getContentPane().add(TargetTabs, java.awt.BorderLayout.CENTER);
        setJMenuBar(mbMain);

//	getContentPane().add(new imageLogo(), java.awt.BorderLayout.CENTER);
    }


    /**
     * The <code>exitForm</code> method implements a confirmation dialogue
     * for terminatingn the application.
     */
    private void exitForm(Component locn) {
        int n = JOptionPane.showConfirmDialog(locn, "Exit application?",
					      "Exit target management",
					      JOptionPane.YES_NO_OPTION );

        if (n == JOptionPane.YES_OPTION) {
            AImanager.this.setVisible(false);
            AImanager.this.dispose();
            System.exit(0);
        }

	return;
    }


    /**
     * The <code>AImanager</code> method is the control object for
     * the cboot utility.
     */

    public AImanager() {

	CurrentTarget = null;

        setSize(WIDTH, HEIGHT);
        addComponentListener(this);
        initComponents();

	this.setLocation(228, 0);
	this.setVisible(true);

	CanisterMonitor monitor = new CanisterMonitor(TargetTabs);
	monitor.start();
    }


    /**
     * This method manages modifications to the window.  Thlpis method
     * prevents the window from being sized smaller then the values
     * specified by MIN_WIDTH and MIN_HEIGHT.
     */
     public void componentResized(ComponentEvent componentEvent) {

	 boolean resize = false;

	 int height = getHeight(),
	     width  = getWidth();


	 //we check if either the width
	 //or the height are below minimum
	 if ( width < MIN_WIDTH ) {
	     resize = true;
	     width = MIN_WIDTH;
	 }
	 if ( height < MIN_HEIGHT ) {
	     resize = true;
	     height = MIN_HEIGHT;
	 }

	 if ( resize )
	     setSize(width, height);

	 return;
     }


    public void componentMoved(ComponentEvent componentEvent) {}

    public void componentShown(ComponentEvent componentEvent) {}

    public void componentHidden(ComponentEvent componentEvent) {}


    /**
     * Private method for displaying a login image.
     */
    private class imageLogo
	extends Component {

	java.awt.image.BufferedImage Image;

	public void paint(java.awt.Graphics graphic) {

	    graphic.drawImage(Image, 0, 0, null);

	    return;
	}

	public imageLogo() {

	    try {
		Image = javax.imageio.ImageIO.read(new java.io.File("idfusion-logo.jpeg"));
	    } catch (java.io.IOException ioe) {
		System.err.println("Image I/O error: " + ioe);
	    }

	    return;
	}
    }

}
