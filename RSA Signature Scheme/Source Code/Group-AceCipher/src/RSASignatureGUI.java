/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author Group Ace Cipher
 * Members:
 * 1. Ong Yong Quan
 * 2. Goh Xin Ran
 * 3. Chee Jiong King
 */
package rsa_signature;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class RSASignatureGUI extends JFrame {
    private JTextArea outputArea;
    private JButton generateKeysButton, signButton, verifyButton, showReportButton;
    private BigInteger p, q, n, phi, e, d;
    private BigInteger signature;
    private byte[] messageDigest;
    private File signedFile;
    private final File reportFile = new File("Signature_Report.txt");

    //GUI Interface
    public RSASignatureGUI() {
        setTitle("RSA Signature Scheme");
        setSize(900, 700);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        outputArea = new JTextArea();
        outputArea.setEditable(false);
        outputArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        add(new JScrollPane(outputArea), BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel();
        generateKeysButton = new JButton("Generate Keys");
        signButton = new JButton("Sign File");
        verifyButton = new JButton("Verify Signature");
        showReportButton = new JButton("Show Report");

        buttonPanel.add(generateKeysButton);
        buttonPanel.add(signButton);
        buttonPanel.add(verifyButton);
        buttonPanel.add(showReportButton);
        add(buttonPanel, BorderLayout.SOUTH);

        generateKeysButton.addActionListener(this::generateKeys);
        signButton.addActionListener(this::signFile);
        verifyButton.addActionListener(this::verifySignature);
        showReportButton.addActionListener(this::showReport);

        signButton.setEnabled(false);
        verifyButton.setEnabled(false);
        showReportButton.setEnabled(false);
    }

    //Part 1: Key Generation
    private void generateKeys(ActionEvent evt) {
        SecureRandom rnd = new SecureRandom();
        e = BigInteger.valueOf(65537);
        int bitLength = 512;

        do {
            p = BigInteger.probablePrime(bitLength, rnd);
            q = BigInteger.probablePrime(bitLength, rnd);
            n = p.multiply(q);
            phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        } while (!e.gcd(phi).equals(BigInteger.ONE));

        d = e.modInverse(phi);

        outputArea.setText("[KEY INFO]\n");
        outputArea.append("Public Key (e):\n" + e + "\n\n");
        outputArea.append("Modulus (n) [First 32 digits]:\n" + n.toString().substring(0, 32) + "...\n\n");
        outputArea.append("Private Key (d) [First 32 digits]:\n" + d.toString().substring(0, 32) + "...\n\n");

        signButton.setEnabled(true);
    }

    //Part 2: Signing File
    private void signFile(ActionEvent e) {
        try {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
            signedFile = fileChooser.getSelectedFile();

            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] fileBytes = Files.readAllBytes(signedFile.toPath());
            messageDigest = md.digest(fileBytes);

            BigInteger m = new BigInteger(1, messageDigest);
            signature = m.modPow(d, n);

            String digestHex = new BigInteger(1, messageDigest).toString(16).toUpperCase();
            String sigHex = signature.toString(16).toUpperCase();

            StringBuilder sb = new StringBuilder();
            sb.append("[FILE SIGNED]\n");
            sb.append(signedFile.getName() + "\n\n");
            sb.append("[SHA-512 Digest]\n");
            sb.append("Hex: \n" + digestHex + "\n\n");
            sb.append("[Signature]\n");
            sb.append("Hex: \n" + sigHex + "\n\n");

            outputArea.setText(sb.toString());

            try (PrintWriter writer = new PrintWriter(reportFile)) {
                writer.println(sb.toString());
            }

            verifyButton.setEnabled(true);
            showReportButton.setEnabled(true);
        } catch (Exception ex) {
            outputArea.setText("Signing error: " + ex.getMessage());
        }
    }

    //Part 2 Verification Signature
    private void verifySignature(ActionEvent e) {
        try {
            if (signedFile == null || !signedFile.exists()) {
                outputArea.setText("Verification error: No signed file selected.");
                return;
            }

            // Recalculate digest from current file content
            byte[] fileBytes = Files.readAllBytes(signedFile.toPath());
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] newDigest = md.digest(fileBytes);
            BigInteger currentHash = new BigInteger(1, newDigest);

            // Decrypt the signature with public key
            BigInteger mCheck = signature.modPow(this.e, n);

            boolean valid = mCheck.equals(currentHash);

            String result = "[Verification]\n" +
                    "Recovered hash from signature:\n" + mCheck.toString(16).toUpperCase() + "\n" +
                    "Current file SHA-512 hash:\n" + currentHash.toString(16).toUpperCase() + "\n" +
                    "Signature Valid?\n" + valid + "\n";

            outputArea.append(result);

            try (FileWriter writer = new FileWriter(reportFile, true)) {
                writer.write(result);
            }
        } catch (Exception ex) {
            outputArea.setText("Verification error: " + ex.getMessage());
        }
    }

    //Extra...
    private void showReport(ActionEvent e) {
        try {
            JTextArea area = new JTextArea();
            area.read(new FileReader(reportFile), null);
            area.setEditable(false);
            area.setFont(new Font("Monospaced", Font.PLAIN, 12));

            JScrollPane scrollPane = new JScrollPane(area);
            scrollPane.setPreferredSize(new Dimension(800, 500));

            JOptionPane.showMessageDialog(this, scrollPane, "Signature Report", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException ex) {
            outputArea.setText("Error reading report: " + ex.getMessage());
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new RSASignatureGUI().setVisible(true));
    }
}