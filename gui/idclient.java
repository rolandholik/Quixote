/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Package and import statements here. */
import java.awt.EventQueue;
import java.awt.Container;
import java.awt.FlowLayout;
import java.awt.BorderLayout;
import java.awt.Font;

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

public class idclient
    extends javax.swing.JFrame {


    private javax.swing.JButton jButton1;
    private JLabel jLabel1;
    private JLabel jLabel2;
    private JLabel jLabel3;
    private javax.swing.JTextField IDtype;
    private javax.swing.JTextField IDname;
    private javax.swing.JTextField Identifier;
    private JTextArea query_output;
    private JTextArea log_output;
    private BufferedReader ac;
    private BufferedReader br;

    private static Duct IDserver;

    /* Global Variable to hold program name. */
    public static String glob;


    /**
     *
     * This method is called from within the constructor to initialize
     * the form.
     *
     * This code should not be modified if the Form Editor is used.
     * We are currently abandoning this in favor of EMACS...
     */

    private void initComponents() {

        IDtype = new javax.swing.JTextField();
        IDname = new javax.swing.JTextField();
	Identifier = new javax.swing.JTextField();
        jButton1 = new javax.swing.JButton();

        jLabel1 = new javax.swing.JLabel();
	jLabel2 = new javax.swing.JLabel();
	jLabel3 = new javax.swing.JLabel();


	query_output = new JTextArea();
 	query_output.setEditable(false);
 	query_output.setColumns(50);
 	query_output.setRows(50);
	query_output.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 14));

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Identity Generator Client");

        jButton1.setText("Generate Identity");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
		public void actionPerformed(java.awt.event.ActionEvent evt) {
		    jButton1ActionPerformed(evt);
		}
	    });

        jLabel1.setText("Type:");
	jLabel2.setText("Name:");
	jLabel3.setText("Identifier:");

        IDname.addActionListener(new java.awt.event.ActionListener() {
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
			      .addComponent(IDtype, javax.swing.GroupLayout.PREFERRED_SIZE, 136, javax.swing.GroupLayout.PREFERRED_SIZE)
			      .addGap(37, 37, 37)
			      .addComponent(jLabel2)
			      .addGap(11, 11, 11)
			      .addComponent(IDname, javax.swing.GroupLayout.PREFERRED_SIZE, 151, javax.swing.GroupLayout.PREFERRED_SIZE)
			      .addGap(37, 37, 37)
			      .addComponent(jLabel3)
			      .addGap(11, 11, 11)
			      .addComponent(Identifier, javax.swing.GroupLayout.PREFERRED_SIZE, 151, javax.swing.GroupLayout.PREFERRED_SIZE)
			      .addContainerGap())

		      .addGroup(layout.createSequentialGroup()
				.addGroup(layout.createSequentialGroup()
					  .addGap(250, 250, 250)
					  .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 211, javax.swing.GroupLayout.PREFERRED_SIZE)))
		      .addGroup(layout.createSequentialGroup()
				.addGroup(layout.createSequentialGroup()
					  .addComponent(query_output))))));

        layout.setVerticalGroup(
				layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(layout.createSequentialGroup()
					  .addContainerGap()
					  .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
						    .addComponent(IDtype, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						    .addComponent(jLabel1)
						    .addComponent(jLabel2)
						    .addComponent(IDname, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						    .addComponent(jLabel3)
						    .addComponent(Identifier, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
					  .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
					  .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
					  .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
					  .addComponent(query_output)));

        pack();
    }


    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {

	IDserver = new Duct();
	if ( !IDserver.connect("192.168.2.1", 10988) ) {
 	    query_output.append("Cannot open query server connection.\n");
 	    return;
 	}

	query_output.setText(null);
	query_output.append("Identity generation/reciprocation output\n\n");
	query_output.append("Type: " + IDtype.getText() + "\n");
	query_output.append("Name: " + IDname.getText() + "\n");
	query_output.append("Identifier: " + Identifier.getText() + "\n\n");
	
	System.out.println("Sending:" + IDtype.getText() + "IDname.getText()"
			   + IDname.getText());
	IDserver.send(IDtype.getText() + ":" + IDname.getText() + ":"
		      + Identifier.getText());

	IDserver.receive();
	query_output.append(IDserver.toString());
	query_output.append("\n");
	IDserver.close();
    }


    private void ssnTextFieldActionPerformed(java.awt.event.ActionEvent evt) {
        // TODO add your handling code here:
    }


    /** Creates new form mainJFrame */
    public idclient() {
        initComponents();
    }


    /**
    * @param args the command line arguments
    */
    public static void main(String args[]) {

	/* Set the keystore name. */
	System.setProperty("javax.net.ssl.trustStore", "idclient.jks");


	/*Set our global variable to program name*/
        java.awt.EventQueue.invokeLater(new Runnable() {
		public void run() {
		    new idclient().setVisible(true);
		}
	    });
    }
}

