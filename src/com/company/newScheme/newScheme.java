package com.company.newScheme;

//import redis.clients.jedis.Jedis;

import com.company.AES256;
import com.company.SHA_224;
import com.company.SchemeInterface;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.*;

public class newScheme implements SchemeInterface {

    private HashSet<String> users;
    private HashSet<String> usernames;

    private final static String fileName = "newSchemeUsers.txt";
    private final static String fileUserNames = "newSchemeUserNames.txt";
    private final static String chipheredDB = "cipherdb.txt";
    private final static String KEYfile = "KEY.txt";


    private static String sha1key;
    private final static String sep = "|%";
    private final static String aeskey = "15TYZfKX037oEaAerQL5ODcSrK6Ggfou";

    private int count;
    private final static int finalcount = 1000000;

    private ArrayList<ArrayList<String>> log;
    private AES256 aes;
    private byte[] cipherdb;
    //private Jedis jedis;
    public newScheme() {
        count = 0;
       // jedis = new Jedis();
        /*String tmpk = jedis.get("key");
        if(tmpk == null || tmpk.equals(""))
            sha1key = "chuck";
        else
            sha1key = tmpk;*/
        users = (HashSet<String>) readData(fileName);
        usernames = (HashSet<String>) readData(fileUserNames);
        cipherdb = (byte[]) readData(chipheredDB);
        sha1key = (String) readData(KEYfile);
        if(sha1key == null)
            sha1key = "a";

        //readRedis();
        log = new ArrayList<ArrayList<String>>();
        aes = new AES256();

      /*  new Thread(() -> {
            try {
                while(2+2==4) {
                    Thread.sleep(20000);
                    dumpLog();
                    changeKey();
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }).start();
*/
    }


    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

    public boolean login(String username, String password) {
       // String trueuser = SHA_224.applyFunction(username);
        String user = applyFunction(username, password);
        return users.contains(user);
    }

    public boolean register(String username, String password) {
       // String trueuser = SHA_224.applyFunction(username);

        if (usernames.contains(username))
            return false;
        else {
            String user = applyFunction(username, password);
            usernames.add(username);
            users.add(user);

            if(++count % finalcount == 0) {
                writeData(users, fileName);
                writeData(usernames, fileUserNames);
                writeData(cipherdb, chipheredDB);
                writeData(sha1key, KEYfile);
            }

            ArrayList<String> entry = new ArrayList<>() {{add("add");add(username);add(password);}};
            log.add(entry);

            return true;
        }
    }

    public boolean changePassword(String username, String password1, String password2) {
        //String trueuser = SHA_224.applyFunction(username);
        String user = applyFunction(username, password1);

        if (!users.contains(user))
            return false;
        else {
            users.remove(user);
            String trueuser2 = applyFunction(username, password2);
            users.add(trueuser2);

            writeData(users, fileName);

            ArrayList<String> entry = new ArrayList<>() {{add("cp");add(username);add(password1);add(password2);}};
            log.add(entry);

            return true;
        }
    }

    public boolean changeUsername(String username1, String username2, String password) {
        //String trueusername1 = SHA_224.applyFunction(username1);
        String trueuser1 = applyFunction(username1, password);
        if (!users.contains(trueuser1))
            return false;
        else {
            String trueusername2 = SHA_224.applyFunction(username2);
            String trueuser2 = applyFunction(username2, password);

            users.remove(trueuser1);
            users.add(trueuser2);

            usernames.remove(username1);
            usernames.add(trueusername2);

            writeData(users, fileName);
            writeData(usernames, fileUserNames);

            ArrayList<String> entry = new ArrayList<>() {{add("cu");add(username1);add(username2);add(password);}};
            log.add(entry);

            return true;
        }
    }

    public boolean deleteUser(String username, String password) {
        //String trueusername = SHA_224.applyFunction(username);
        String trueuser = applyFunction(username, password);
        if (!users.contains(trueuser))
            return false;
        else {
            users.remove(trueuser);
            usernames.remove(username);

            writeData(users, fileName);
            writeData(usernames, fileUserNames);

            ArrayList<String> entry = new ArrayList<>() {{add("del");add(username);add(password);}};
            log.add(entry);

            return true;
        }
    }
    
    public String applyFunction(String username, String password) {
        String user = null;
        try {
            user = calculateRFC2104HMAC(username + sep + password, sha1key);
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

    private static String calculateRFC2104HMAC(String data, String key)
            throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);
        Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
        mac.init(signingKey);
        return toHexString(mac.doFinal(data.getBytes()));
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

    private void dumpLog(){
        try {
            HashMap<String, String> dbpw;
            if (cipherdb != null) {
                //decipher old ciphered db and put it in String

                //String to Map
                dbpw = aes.decipher(cipherdb, aeskey);
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
            cipherdb = aes.cipher(dbpw, aeskey);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void changeKey(){
        long startTime = System.nanoTime();

        sha1key = UUID.randomUUID().toString();
        users = new HashSet<>();
        try {
                HashMap<String, String> db = aes.decipher(cipherdb, aeskey);
                Iterator it = db.entrySet().iterator();
                while (it.hasNext()) {
                    Map.Entry pair = (Map.Entry)it.next();
                    String user = applyFunction(  (String) pair.getKey(), (String) pair.getValue());
                    users.add(user);
                    it.remove();
                }

        } catch (Exception e) {
            e.printStackTrace(); 
        }

        long endTime = System.nanoTime();
        System.out.println("Changed hash set with key " + sha1key + " and it took " + (int) ((endTime - startTime)/(1000000)) + " ms!");

       writeData(users, fileName);
       writeData(usernames, fileUserNames);
        writeData(cipherdb, chipheredDB);
        writeData(sha1key, KEYfile);
        //jedis.set("key", sha1key);
        //writeRedis();
    }

    private static Key generateKeyFromString(final String secKey) throws Exception {

        byte[] decodedKey = Base64.getDecoder().decode(secKey);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        return originalKey;
    }

    private HashMap<String, String> string2map(String db){
        Properties props = new Properties();
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

    private HashSet<String> string2set(String db){
        HashSet<String> myHashSet = new HashSet();  // Or a more realistic size
        StringTokenizer st = new StringTokenizer(db, ",");
        while(st.hasMoreTokens())
            myHashSet.add(st.nextToken());
        return myHashSet;
    }

    private void writeRedis(){
        //jedis.set("users", users.toString());
        //jedis.set("usernames", usernames.toString());
        //jedis.set("ciphered", cipherdb.toString());
    }

    /*private void readRedis(){
        String userstmp = jedis.get("users");
        if(userstmp == null || userstmp.equals("")) {
            users = new HashSet<>();
            usernames = new HashSet<>();
            cipherdb = null;
        }
        else {
            users = string2set(userstmp);
            //usernames = string2set(jedis.get("usernames"));
           // cipherdb = jedis.get("ciphered").getBytes();
        }

    }*/

    private void delRedis(){
       // jedis.del("users");
       // jedis.del("usernames");
       // jedis.del("ciphered");
       // jedis.del("key");
    }
}
