package com.company;

import redis.clients.jedis.Jedis;
import samples.sample;
import tss.tpm.TPM_ALG_ID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

import static tss.Helpers.getRandom;

public class SSPM implements SchemeInterface {
    private boolean version_username;
    private boolean version_redis;

    private boolean version_newkey;
    private boolean version_tpmkey;
    private boolean version_tpmop;
    private HashSet<String> users;
    private HashSet<String> usernames;

    private static byte[] sha1key;
    private final static String sep = "|%";

    private ArrayList<ArrayList<String>> log;
    private final static String aeskey = "q4t7w!z%C*F-JaNd";

    private byte[] cipherdb;

    private final static String usersFiles = "sspm_Users";
    private final static String usernamesFiles = "sspm_UserNames";
    private final static String chipheredDB = "sspm_cipherdb";
    private final static String KEYfile = "KEY";

    private final static boolean clearRedis = true;
    Jedis jedis;
    sample tpm;

    public SSPM(boolean username_, boolean redis_, boolean newkey_, boolean tpmkey_, boolean tpmop_) {
        version_username = username_;
        version_redis = redis_;
        version_newkey = newkey_;
        version_tpmkey = tpmkey_;
        version_tpmop = tpmop_;

        users = (HashSet<String>) readData(usersFiles);
        usernames = (HashSet<String>) readData(usernamesFiles);
        sha1key = (byte[]) readData(KEYfile);


        if (sha1key == null)
            sha1key = getRandom(6);


        if (version_tpmkey || version_tpmop)
            tpm = new sample();

        if (version_redis)
            goJedis();

        if(version_newkey)
            cipherdb = (byte[]) readData(chipheredDB);

        log = new ArrayList<>();
        new Thread(() -> {
            try {
                int count = 0;
                while(2+2==4) {
                    Thread.sleep(10000);
                    dumpJedis();
                    if(count++ > 3) {
                      //  changeKey();
                        count=0;
                    }
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }).start();
    }

    private void goJedis() {
        jedis = new Jedis();

        if(clearRedis){
            jedis.del(usersFiles);
            jedis.del(usernamesFiles);
            jedis.del(chipheredDB);
            jedis.del(KEYfile);
            jedis.del("users");
            jedis.del("usernames");
        }

        cipherdb = jedis.get(chipheredDB.getBytes());

        users = new HashSet<>(); usernames = new HashSet<>();
        users.addAll(jedis.smembers(usersFiles));
        usernames.addAll(jedis.smembers(usernamesFiles));
        cipherdb = jedis.get(chipheredDB.getBytes());

        sha1key = jedis.get(KEYfile).getBytes();
        if(sha1key == null)
            sha1key = "a".getBytes();
    }

    @Override
    public boolean login(String username, String password) throws Exception {
        return users.contains(applyFunction(username, password));
    }

    @Override
    public boolean register(String username, String password) throws Exception {
        if (version_username) {
            if (!usernames.add(username))
                return false;
            else {
                if (users.add(applyFunction(username, password))) {
                    usernames.add(username);
                    if(version_redis || version_newkey)
                        log.add(new ArrayList<>() {{
                            add("add");
                            add(username);
                            add(password);
                        }});

                    return true;
                } else return false;
            }
        } else return users.add(applyFunction(username, password));
    }

    @Override
    public boolean changePassword(String username, String password1, String password2) {
        if (!users.remove(applyFunction(username, password1)))
            return false;
        else {
            if(users.add(applyFunction(username, password2))) {
                if (version_redis || version_newkey)
                    log.add(new ArrayList<>() {{
                        add("cp");
                        add(username);
                        add(password1);
                        add(password2);
                    }});
                return true;
            }
            else return false;
        }
    }

    @Override
    public boolean changeUsername(String username1, String username2, String password) {
        if (!users.remove(applyFunction(username1, password)))
            return false;
        else {
            if (users.add(applyFunction(username2, password))) {
                if (version_username) {
                    usernames.remove(username1);
                    usernames.add(username2);
                }
                if (version_redis || version_newkey)
                log.add(new ArrayList<>() {{add("cu");add(username1);add(username2);add(password);}});

                return true;
            } else return false;
        }
    }

    @Override
    public boolean deleteUser(String username, String password) {
        if (version_username) {
            if (!usernames.remove(username))
                return false;
            else {
                if (users.remove(applyFunction(username, password))) {
                    usernames.remove(username);
                    if (version_redis || version_newkey)
                        log.add(new ArrayList<>() {{
                            add("del");
                            add(username);
                            add(password);
                        }});

                    return true;
                } else return false;
            }
        } else return users.remove(applyFunction(username, password));
    }

    @Override
    public Object getDB() {
        return users;
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

            if (file.equals(usersFiles) || file.equals(usernamesFiles))
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

    public String applyFunction(String username, String password) {
        if (version_tpmop == false) {
            String user = null;
            try {
                SecretKeySpec key;
                if (version_tpmkey)
                    key = new SecretKeySpec(tpm.getKey(), "HmacSHA1");
                else
                    key = new SecretKeySpec(sha1key, "HmacSHA1");

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
            } catch (Exception e) {
                e.printStackTrace();
            }
            return user;
        } else {
            String user;
            final String name = username + sep + password;
            user = tpm.hmac(TPM_ALG_ID.SHA1, name.getBytes(), sha1key);
            return user;
        }
    }


    private void dumpJedis(){
        try {
            HashMap<String, String> dbpw;
            if (cipherdb != null) {
                dbpw = AES.decipher(cipherdb, aeskey);
            }
            else
                dbpw = new HashMap<>();

            //update the hashmap according to the log
            for(ArrayList<String> entry : log){
                switch(entry.get(0)){
                    case "add":
                        jedis.sadd(usersFiles, applyFunction(entry.get(1), entry.get(2)));
                        jedis.sadd(usernamesFiles, entry.get(1));
                        dbpw.put(entry.get(1), entry.get(2));
                        break;
                    case "cp":
                        jedis.sdiff(usersFiles, applyFunction(entry.get(1), entry.get(2)));
                        jedis.sadd(usersFiles, applyFunction(entry.get(1), entry.get(3)));
                        dbpw.replace(entry.get(1), entry.get(3));
                        break;
                    case "cu":
                        jedis.sdiff(usersFiles, applyFunction(entry.get(1), entry.get(3)));
                        jedis.sadd(usersFiles, applyFunction(entry.get(2), entry.get(3)));

                        jedis.sdiff(usernamesFiles, entry.get(1));
                        jedis.sadd(usernamesFiles, entry.get(2));

                        dbpw.remove(entry.get(1));
                        dbpw.put(entry.get(2), entry.get(3));
                        break;
                    case "del":
                        jedis.sdiff(usersFiles, applyFunction(entry.get(1), entry.get(2)));
                        jedis.sdiff(usernamesFiles, entry.get(1));

                        dbpw.remove(entry.get(1));
                        break;
                    default: System.out.println("Something went terribly wrong");
                }
            }

            log = new ArrayList<>();

            //encrypt that bitch back
            cipherdb = AES.cipher(dbpw, aeskey);
            jedis.set(chipheredDB.getBytes(), cipherdb);
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("dumped");
    }
}
