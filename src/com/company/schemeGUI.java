package com.company;

import com.company.newScheme.newSchemeV5text;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;

public class schemeGUI implements ActionListener {

    private JLabel statusLabel;
    private JLabel userLabel;
    private JPasswordField passwordText;
    private JTextField userText;

    private JLabel passwordLabel;
    private JButton submitButton;

    private JLabel wildLabel;
    private JTextField wildText;
    ButtonGroup group;

    static String birdString = "Login";
    static String catString = "Register";
    static String dogString = "Change Username";
    static String rabbitString = "Change Password";
    static String pigString = "Delete user";

    final static int minXlbl = 150;
    final static int minXField = 120;
    static newSchemeV5text NS;
    public static void main(String[] args) {
        NS = new newSchemeV5text();
        JFrame frame = new JFrame("New Scheme");
        frame.setSize(500, 200);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JPanel panel = new JPanel();
        frame.add(panel);
        new schemeGUI(panel);

        frame.setVisible(true);
    }

    JRadioButton birdButton;
    JRadioButton catButton;
    JRadioButton dogButton;
    JRadioButton rabbitButton;
    JRadioButton pigButton;
    public schemeGUI(JPanel panel) {

        panel.setLayout(null);

        userLabel = new JLabel("Username");
        userLabel.setBounds(minXlbl, 10, 80, 25);
        panel.add(userLabel);

        userText = new JTextField(20);
        userText.setBounds(minXlbl + minXField, 10, 160, 25);
        panel.add(userText);

        passwordLabel = new JLabel("Password");
        passwordLabel.setBounds(minXlbl, 40, 80, 25);
        panel.add(passwordLabel);

        passwordText  = new JPasswordField(20);
        passwordText.setBounds(minXlbl + minXField, 40, 160, 25);
        panel.add(passwordText);

        wildLabel = new JLabel("Wild Label");
        wildLabel.setBounds(minXlbl, 70, 100, 25);

        wildText  = new JPasswordField(20);
        wildText.setBounds(minXlbl + minXField, 70, 160, 25);

        submitButton = new JButton("submit");
        submitButton.setBounds(minXlbl + minXField+50, 120, 80, 25);
        panel.add(submitButton);

        statusLabel = new JLabel("");
        statusLabel.setBounds(minXlbl, 120, 180, 25);
        panel.add(statusLabel);

        submitButton.addActionListener( this);


        birdButton = new JRadioButton(birdString);
        birdButton.setMnemonic(KeyEvent.VK_B);
        birdButton.setActionCommand(birdString);
        birdButton.setSelected(true);

        catButton = new JRadioButton(catString);
        catButton.setMnemonic(KeyEvent.VK_C);
        catButton.setActionCommand(catString);

        dogButton = new JRadioButton(dogString);
        dogButton.setMnemonic(KeyEvent.VK_D);
        dogButton.setActionCommand(dogString);

        rabbitButton = new JRadioButton(rabbitString);
        rabbitButton.setMnemonic(KeyEvent.VK_R);
        rabbitButton.setActionCommand(rabbitString);

        pigButton = new JRadioButton(pigString);
        pigButton.setMnemonic(KeyEvent.VK_P);
        pigButton.setActionCommand(pigString);

        birdButton.setBounds(0, 10, minXlbl, 25);
        catButton.setBounds(0, 30, minXlbl, 25);
        dogButton.setBounds(0, 50, minXlbl, 25);
        rabbitButton.setBounds(0, 70, minXlbl, 25);
        pigButton.setBounds(0, 90, minXlbl, 25);

        //Group the radio buttons.
        group = new ButtonGroup();
        group.add(birdButton);
        group.add(catButton);
        group.add(dogButton);
        group.add(rabbitButton);
        group.add(pigButton);

        panel.add(birdButton);
        panel.add(catButton);
        panel.add(dogButton);
        panel.add(rabbitButton);
        panel.add(pigButton);

        birdButton.addActionListener(this);
        catButton.addActionListener(this);
        dogButton.addActionListener(this);
        rabbitButton.addActionListener(this);
        pigButton.addActionListener(this);
        panel.add(wildLabel);
        panel.add(wildText);
        wildLabel.setVisible(false);
        wildText.setVisible(false);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String command = e.getActionCommand();
        switch(command){
            case("submit"):
                System.out.println(e.getActionCommand());
                String username = new String(userText.getText());
                String password = new String(passwordText.getPassword());
                String wild = new String(wildText.getText());

                boolean a = true;

                if(birdButton.isSelected()) a = NS.login(username, password);
                if(catButton.isSelected()) a = NS.register(username, password);
                if(dogButton.isSelected()) a = NS.changeUsername(username, wild, password);
                if(rabbitButton.isSelected()) a = NS.changePassword(username, password, wild);
                if(pigButton.isSelected())a = NS.deleteUser(username, password);

                System.out.println("Username - " + username);
                System.out.println("Password - " + password);

                if(a) {
                    statusLabel.setText("Operation Successful");
                    statusLabel.setForeground(Color.GREEN);
                }
                else {
                    statusLabel.setText("Operation NOT Successful");
                    statusLabel.setForeground(Color.RED);
                }
                break;
            case("Login"):
                wildLabel.setVisible(false);
                wildText.setVisible(false);
                break;
            case("Register"):
                wildLabel.setVisible(false);
                wildText.setVisible(false);
                break;
            case("Change Username"):
                wildLabel.setText("New Username");
                wildLabel.setVisible(true);
                wildText.setVisible(true);

                break;
            case("Change Password"):
                wildLabel.setText("New Password");
                wildLabel.setVisible(true);
                wildText.setVisible(true);

                break;
            case("Delete user"):
                wildLabel.setVisible(false);
                wildText.setVisible(false);

                break;

            default: System.out.println(command);
        }

    }
}
