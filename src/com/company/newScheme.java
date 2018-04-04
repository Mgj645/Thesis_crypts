package com.company;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Formatter;
import java.util.HashMap;
import java.util.HashSet;


public class newScheme implements SchemeInterface {

    HashSet<String> users;
    HashSet<String> usernames;
    HashMap<String, String> plainUsers;

    final static String fileName = "newSchemeUsers.txt";
    final static String fileUserNames = "newSchemeUserNames.txt";

     static String sha1key = "CHUCK";
    final static String aeskey = "15TYZfKX037oEaAerQL5ODcSrK6Ggfou";

    int count;
    final static int finalcount = 299;

    public newScheme() {
        count = 0;
        users = (HashSet<String>) readData(fileName);
        usernames = (HashSet<String>) readData(fileUserNames);
        plainUsers = new HashMap<String, String>();
    }

    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

    public boolean login(String username, String password) {
       // String trueuser = SHA_224.applyFunction(username);
        String user = applyFunction(username+"|%%|", password);
        return users.contains(user);
    }

    public boolean register(String username, String password) {
        String trueuser = SHA_224.applyFunction(username);

        if (usernames.contains(trueuser))
            return false;
        else {
            String user = applyFunction(username+"|%%|", password);
            usernames.add(trueuser);
            users.add(user);

            if(++count % finalcount == 0) {
                writeData(users, fileName);
                writeData(usernames, fileUserNames);
            }
            return true;
        }
    }

    public boolean changePassword(String username, String password1, String password2) {
        String trueuser = SHA_224.applyFunction(username);
        String user = applyFunction(trueuser, password1);

        if (!users.contains(user))
            return false;
        else {
            users.remove(user);
            String trueuser2 = applyFunction(username+"|%%|", password2);
            users.add(trueuser2);

            writeData(users, fileName);
            return true;
        }
    }

    public boolean changeUsername(String username1, String username2, String password) {
        String trueusername1 = SHA_224.applyFunction(username1);
        String trueuser1 = applyFunction(username1+"|%%|", password);
        if (!users.contains(trueuser1))
            return false;
        else {
            String trueusername2 = SHA_224.applyFunction(username2);
            String trueuser2 = applyFunction(username2+"|%%|", password);

            users.remove(trueuser1);
            users.add(trueuser2);

            usernames.remove(trueusername1);
            usernames.add(trueusername2);

            writeData(users, fileName);
            writeData(usernames, fileUserNames);

            return true;
        }
    }

    public boolean deleteUser(String username, String password) {
        String trueusername = SHA_224.applyFunction(username);
        String trueuser = applyFunction(username+"|%%|", password);
        if (!users.contains(trueuser))
            return false;
        else {
            users.remove(trueuser);
            usernames.remove(trueusername);

            writeData(users, fileName);
            writeData(usernames, fileUserNames);
            return true;
        }
    }
    
    public String applyFunction(String username, String password) {
        String user = null;
        try {
            user = calculateRFC2104HMAC(username + password, sha1key);
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return user;
    }

    private static String toHexString(byte[] bytes) {
        Formatter formatter = new Formatter();

        for (byte b : bytes) {
            formatter.format("%02x", b);
        }

        return formatter.toString();
    }

    public static String calculateRFC2104HMAC(String data, String key)
            throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);
        Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
        mac.init(signingKey);
        return toHexString(mac.doFinal(data.getBytes()));
    }
    
    OutputStream ops = null;
    ObjectOutputStream objOps = null;

    void writeData(Object users, String fileName) {
        try {
            ops = new FileOutputStream(fileName);
            objOps = new ObjectOutputStream(ops);
            objOps.writeObject(users);
            objOps.flush();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (objOps != null) objOps.close();
            } catch (Exception ex) {

            }
        }
    }

    Object readData(String fileName) {
        InputStream fileIs = null;
        ObjectInputStream objIs = null;
        Object users;
        try {
            fileIs = new FileInputStream(fileName);
            objIs = new ObjectInputStream(fileIs);
            users = objIs.readObject();
            //System.out.println("");
            //System.out.println(Collections.singletonList(users)); // method 2
            return users;
        } catch (FileNotFoundException e) {
            users = new HashSet<String>();

            return users;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } finally {
            try {
                if (objIs != null) objIs.close();
            } catch (Exception ex) {

            }
        }
        return null;
    }

    private void changeKey(){
        String oldkey = sha1key;

        sha1key = "DXeBGoKOLzydaiHtIG7qCdVkLo5cd7se";
    }

    private static Key generateKeyFromString(final String secKey) throws Exception {

        byte[] decodedKey = Base64.getDecoder().decode(secKey);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        return originalKey;
    }
}
