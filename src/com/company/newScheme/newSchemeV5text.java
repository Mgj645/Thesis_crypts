package com.company.newScheme;

import com.company.SHA_224;
import com.company.SHA_3;
import com.company.SchemeInterface;
import samples.sample;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.util.*;

public class newSchemeV5text implements SchemeInterface {

    private HashSet<String> users;
    private HashSet<String> usernames;

    private static byte[] sha1key;
    private static byte[] aeskey;

    private static String sep;

    private ArrayList<ArrayList<String>> log;

    private byte[] cipherdb;


    private final static String fileName = "V5newSchemeUsers.txt";
    private final static String fileUserNames = "V5newSchemeUserNames.txt";
    private final static String chipheredDB = "V5cipherdb.txt";
    private final static String SKEYfile = "V5sKEY.txt";
    private final static String AKEYfile = "V5aKEY.txt";
    private int choice;
    private final static boolean clearRedis = true;


    sample tpm;
    public newSchemeV5text() {
        cipherdb = null;
        cipherdb = null;
        users = (HashSet<String>) readData(fileName);
        usernames = (HashSet<String>) readData(fileUserNames);

        cipherdb = (byte[]) readData(chipheredDB);
        sha1key = (byte[]) readData(SKEYfile);
        aeskey = (byte[]) readData(AKEYfile);

        if(sha1key==null)
           sha1key = getRandom(16);

        if(aeskey==null)
           aeskey = getRandom(16);

        System.out.println(toHex(aeskey));
        System.out.println(toHex(sha1key));
        writeData(sha1key, SKEYfile);
        writeData(aeskey, AKEYfile);

        tpm = new sample();

        choice = 0;

        log = new ArrayList<>();
        new Thread(() -> {
            try {
                int count = 0;
                while(2+2==4) {
                    Thread.sleep(10000);
                    dumpLog();
                    if(count++ > 0) {
                        changeKey();
                        count=0;
                    }
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }).start();
    }


    public boolean login(String username, String password) {
        String user = applyFunction(username, password);
        return users.contains(user);
    }

    public boolean register(String username, String password) {

        if (!usernames.add(username))
            return false;
        else {
            usernames.add(username);
                if(users.add(applyFunction(username, password))) {
                log.add(new ArrayList<>() {{
                    add("add");
                    add(username);
                    add(password);
                }});

                return true;
            }
            else return false;
        }
    }

    public boolean changePassword(String username, String password1, String password2) {
        if (!users.remove(applyFunction(username, password1)))
            return false;
        else {
            if(users.add(applyFunction(username, password2))){
                log.add(new ArrayList<>() {{add("cp");add(username);add(password1);add(password2);}});
                return true;}
            else return false;
        }
    }

    public boolean changeUsername(String username1, String username2, String password) {
        if (!users.remove(applyFunction(username1, password)))
            return false;
        else {
            if( users.add(applyFunction(username2, password))) {
                usernames.remove(username1);
                usernames.add(username2);
                log.add(new ArrayList<>() {{add("cu");add(username1);add(username2);add(password);}});
                return true;
            }
            else return false;
        }
    }

    public boolean deleteUser(String username, String password) {
        if (!usernames.remove(username))
            return false;
        else {
            if( users.remove(applyFunction(username, password))) {
                log.add(new ArrayList<>() {{
                    add("del");
                    add(username);
                    add(password);
                }});
                return true;
            }
            else return false;
        }
    }

    public String applyFunction(String username, String password) {
        String user;
        switch(choice){
            case 0: user = applyHMAC(username, password, "HmacSHA1"); break;
            case 1: user = applyHMAC(username, password, "HmacMD5"); break;
            case 2: user = applyHMAC(username, password, "HmacSHA256"); break;
            case 3: user = SHA_224.applyFunction(username+sep+password); break;
            case 4: user = SHA_3.applyFunction(username+sep+password); break;
            default: return null;
        }
        return user;
    }

    private String applyHMAC(String username, String password, String HMAC){
        String user = null;
        try {
            SecretKeySpec key = new SecretKeySpec(sha1key, HMAC);
            Mac mac = Mac.getInstance(HMAC);
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
        return user;
    }
    private void dumpLog(){
        try {
            HashMap<String, String> dbpw;
            if (cipherdb != null) {
                dbpw = byte2map(tpm.decrypt(cipherdb, aeskey, 0));
            }
            else
                dbpw = new HashMap<>();

            //update the hashmap according to the log
            for(ArrayList<String> entry : log){
                switch(entry.get(0)){
                    case "add":
                        dbpw.put(entry.get(1), entry.get(2));
                        break;
                    case "cp":
                           dbpw.replace(entry.get(1), entry.get(3));
                        break;
                    case "cu":
                     dbpw.remove(entry.get(1));
                        dbpw.put(entry.get(2), entry.get(3));
                        break;
                    case "del":
                        dbpw.remove(entry.get(1));
                        break;
                    default: System.out.println("Something went terribly wrong");
                }
            }

            log = new ArrayList<>();

            //encrypt that bitch back
            aeskey =  getRandom(16);

            cipherdb = tpm.encrypt(dbpw.toString().getBytes(), aeskey,0);
            writeData(cipherdb, chipheredDB);
            writeData(aeskey, AKEYfile);
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("dumped");
    }

    private void changeKey(){
        if (cipherdb != null) {

            sha1key =  getRandom(16);
            sep = new String(getRandom(4));
            writeData(sha1key, SKEYfile);

            long startTime = System.nanoTime();

            users = new HashSet<>();
            try {
                HashMap<String, String> db = byte2map(tpm.decrypt(cipherdb, aeskey, 0));
                Iterator it = db.entrySet().iterator();
                while (it.hasNext()) {
                    Map.Entry pair = (Map.Entry) it.next();
                      String user = applyFunction((String) pair.getKey(), (String) pair.getValue());
                    users.add(user);
                    it.remove();
                }

            } catch (Exception e) {
                e.printStackTrace();
            }

            long endTime = System.nanoTime();

            System.out.println("Changed hash set with key " + toHex(sha1key)+ " and it took " + (int) ((endTime - startTime) / (1000000)) + " ms!" +
                    " choice " + choice);

            writeData(users, fileName);
            writeData(usernames, fileUserNames);

        }
    }

    private static HashMap<String, String> byte2map(byte[] dbB){
        Properties props = new Properties();
        String db = new String(dbB);
        try {
            props.load(new StringReader(db.substring(1, db.length() - 1).replace(", ", "\n")));
        } catch (IOException e) {
            e.printStackTrace();
        }
        HashMap<String, String> dbpw = new HashMap<>();
        for (Map.Entry<Object, Object> e : props.entrySet()) {
            dbpw.put((String)e.getKey(), (String)e.getValue());
        }

        return dbpw;
    }
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
        {
            sb.append(String.format("%02x", b));

        }
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

}
