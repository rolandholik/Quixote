/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Package and import statements here. */
import java.awt.EventQueue;
import java.awt.Container;
import java.awt.FlowLayout;
import java.awt.BorderLayout;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTextArea;
import javax.swing.JScrollPane;
import javax.swing.SwingWorker;


/**
 * General class documentation starts here.
 *
 * Original coe by @author mpiehl
 */

public class naaaim
    extends javax.swing.JFrame {


    private javax.swing.JButton jButton1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JTextField userpin;
    private javax.swing.JTextField ssnTextField;
    private JTextArea query_output;
    private JTextArea log_output;
    private BufferedReader ac;
    private BufferedReader br;

    /* Global Variable to hold program name. */
    public static String glob;


    /**
     *
     * This method is called from within the constructor to initialize
     *  the form.
     *
     * This code should not be modified if the Form Editor is used.
     * We are currently abandoning this in favor of EMACS...
     */

    private void initComponents() {

        userpin = new javax.swing.JTextField();
        jButton1 = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        ssnTextField = new javax.swing.JTextField();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("NAAAIM Identity Fabric Query Client");

        jButton1.setText("Run Query");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
		public void actionPerformed(java.awt.event.ActionEvent evt) {
		    jButton1ActionPerformed(evt);
		}
	    });

        jLabel1.setText("User PIN:");

        ssnTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ssnTextFieldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jLabel1)
                        .addGap(11, 11, 11)
                        .addComponent(userpin, javax.swing.GroupLayout.PREFERRED_SIZE, 136, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(37, 37, 37)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(ssnTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 151, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(121, 121, 121)
                        .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 211, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(45, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(userpin, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel1)
                    .addComponent(ssnTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jButton1)
                .addContainerGap())
        );

        pack();
    }


    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {

	/* Location information. */
	java.awt.Point locn = getLocation();

	/* Text areas for query output and console log. */
	query_output = new JTextArea();
	query_output.setEditable(false);
	query_output.setColumns(80);
	query_output.setRows(50);
	JScrollPane query_pane = new JScrollPane(query_output);

	log_output   = new JTextArea();
	log_output.setEditable(false);
	log_output.setColumns(80);
	log_output.setRows(50);
	JScrollPane log_pane = new JScrollPane(log_output);
	
	/* Frames for the two output windows. */
	JFrame query_frame = new JFrame("Query output.");
	JFrame log_frame   = new JFrame("Log output.");

	/* Setup content layouts. */
	Container query_content = query_frame.getContentPane();
	query_content.setLayout(new BorderLayout());
	query_content.add(query_pane);

	Container log_content = log_frame.getContentPane();
	log_content.setLayout(new BorderLayout());
	log_content.add(log_pane);

	/* Set screen sizes and the output and console windows. */
	log_frame.setSize(500, 500);
	log_frame.setVisible(true);
	locn.translate(0, 115);
	log_frame.setLocation(locn);

	query_frame.setSize(500, 500);
	query_frame.setVisible(true);
	locn = log_frame.getLocation();
	locn.translate(500, 0);
	query_frame.setLocation(locn);


	/*
	 * The following implements an inner class used to implement
	 * dynamic updates to the console and log outputs.
	 */

	SwingWorker worker = new SwingWorker<String, Void>() {
	    
	    public String doInBackground() {

		String line, error;

		try {
		    while ((error = ac.readLine()) != null) {
			log_output.append(error + "\n");
			System.out.println(error);
		    }

		    while ((line = br.readLine()) != null) {
			query_output.append(line + "\n");
			System.out.println(line);
		    }
		}
		catch (IOException ex) {
		    Logger.getLogger(naaaim.class.getName()).log(Level.SEVERE,
								 null, ex);
		}
		return null;
	    }

	    public void done() {
	    }
	};


        /*
	 * Get the user pin number and compose the executable command.
	 */
        String pin = userpin.getText();
        String run = glob + " -p " + pin;
	String[] cmd = {"/bin/bash", "-c", run};


	try {
	    /* Create a new process object bound to cmd. */
	    ProcessBuilder process = new ProcessBuilder(cmd);

	    /* Fork process to launch C binary. */
	    Process p = process.start();

	    /* Watch stdout stream. */
	    InputStream is = p.getInputStream();
	    InputStreamReader isr = new InputStreamReader(is);

	    /* Watch stderr stream. */
	    InputStream a = p.getErrorStream();
	    InputStreamReader ab = new InputStreamReader(a);

	    /*. Gather Stream information. */
	    ac = new BufferedReader(ab);
	    br = new BufferedReader(isr);

	    /* Strings to hold command line information. */
	    String error;
	    ArrayList<String> results = new ArrayList<String>();

	    worker.execute();
	}
	catch (IOException ex) {
            Logger.getLogger(naaaim.class.getName()).log(Level.SEVERE, null,
							 ex);
        }
    }


    private void ssnTextFieldActionPerformed(java.awt.event.ActionEvent evt) {
        // TODO add your handling code here:
    }


    /** Creates new form mainJFrame */
    public naaaim() {
        initComponents();
    }


    /**
    * @param args the command line arguments
    */
    public static void main(String args[]) {

	/*Set our global variable to program name*/
	glob = args[0];

        java.awt.EventQueue.invokeLater(new Runnable() {
		public void run() {
		    new naaaim().setVisible(true);
		}
	    });
    }
}
