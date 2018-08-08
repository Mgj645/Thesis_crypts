package com.company.newScheme;

import com.company.SchemeInterface;
import samples.sample;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.util.HashSet;
import java.util.Random;

public class newSchemeV5keys implements SchemeInterface {

    private HashSet<String> users;
    private HashSet<String> usernames;

    private static byte[] sha1key;

    private static String sep = "|%|";

    private final static String fileName = "V5newSchemeUsers.txt";
    private final static String fileUserNames = "V5newSchemeUserNames.txt";
    private final static String SKEYfile = "V5sKEY.txt";

    int entries = 100000/100;
    int finalcount = entries;

    sample tpm;
    public newSchemeV5keys() {
        users = (HashSet<String>) readData(fileName);
        usernames = (HashSet<String>) readData(fileUserNames);

        tpm = new sample() ;

        tpm.ek(getRandom(6));
    }

    int count = 0;
    int countL = 0;
    public boolean login(String username, String password) {
        //if(countL++ % entries==0)
          //  System.out.println((countL)/entries + "%");
        return users.contains(applyFunction(username, password));
    }

    public boolean register(String username, String password) {
       //if(count++ % entries ==0) {
        //  System.out.println(count / entries + "%");
          //  writeData(users, fileName);
           // writeData(usernames, fileUserNames);
            //writeData(sha1key, SKEYfile);
       //}

        if (!usernames.add(username))
            return false;
        else {
                if(users.add(applyFunction(username, password))) {
                    usernames.add(username);
                    return true;
            }
            else return false;
        }
    }

    public boolean changePassword(String username, String password1, String password2) {
        if (!users.remove(applyFunction(username, password1)))
            return false;
        else {
            return users.add(applyFunction(username, password2));
        }
    }

    public boolean changeUsername(String username1, String username2, String password) {
        if (!users.remove(applyFunction(username1, password)))
            return false;
        else {
            if( users.add(applyFunction(username2, password))) {
                usernames.remove(username1);
                usernames.add(username2);
                return true;
            }
            else return false;
        }
    }

    public boolean deleteUser(String username, String password) {
        if (!usernames.remove(username))
            return false;
        else {
            return users.remove(applyFunction(username, password));
        }
    }

    public String applyFunction(String username, String password) {

        String user = null;
        try {
            SecretKeySpec key = new SecretKeySpec((tpm.getKey()), "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(key);

            byte[] bytes = mac.doFinal((username + sep + password).getBytes("ASCII"));

            StringBuffer hash = new StringBuffer();
            for (int i = 0; i < bytes.length; i++) {
                String hex = Integer.toHexString(0xFF & bytes[i]);
                if (hex.length() == 1) {
                    hash.append('0');
                }
                hash.append(hex);
            }
            user = hash.toString();
        } catch (Exception e){
            e.printStackTrace();
        }

        return user;    }


    Random rand;

    public  byte[] getRandom(int numBytes)
    {
        if (rand==null)
            rand = new Random();

        byte[] res = new byte[numBytes];
        rand.nextBytes(res);
        return res;
    }

    public static String toHex(byte[] x)
    {
        StringBuilder sb = new StringBuilder(x.length * 2);
        for (byte b: x)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }


    private OutputStream ops = null;
    private ObjectOutputStream objOps = null;
    private void writeData(Object users, String fileName) {
        //txts no explorer
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
    private Object readData(String file) {
        InputStream fileIs = null;
        ObjectInputStream objIs = null;
        Object users;
        try {
            fileIs = new FileInputStream(file);
            objIs = new ObjectInputStream(fileIs);
            users = objIs.readObject();
            //System.out.println("");
            //System.out.println(Collections.singletonList(users)); // method 2
            return users;
        } catch (FileNotFoundException e) {

            if(file.equals(fileUserNames) || file.equals(fileName))
                return new HashSet<String>();
            else
                return null;

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

    private void printEverything(){
        System.out.println("SHA1 key: " + toHex(sha1key));
        System.out.println("Users: " ); users.forEach(System.out::println);
        System.out.println("Usernames: " ); usernames.forEach(System.out::println);

    }

}
