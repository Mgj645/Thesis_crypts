package com.company.newScheme;

import com.company.SHA_224;
import com.company.SHA_3;
import com.company.SchemeInterface;
import redis.clients.jedis.Jedis;
import samples.sample;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.StringReader;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

public class newSchemeV5 implements SchemeInterface {
    public Object getDB() {
        return users;
    }
    private HashSet<String> users;
    private HashSet<String> usernames;

    private static byte[] sha1key;
    private static byte[] aeskey;

    private static String sep;

    private ArrayList<ArrayList<String>> log;

    private byte[] cipherdb;

    private final static String usersRedis = "newSchemeUsers";
    private final static String userNamesRedis = "newSchemeUserNames";
    private final static String chipheredDB = "cipherdb";

    private int choice;
    private final static boolean clearRedis = true;
    Jedis jedis;

    sample tpm;
    public newSchemeV5() {
        cipherdb = null;
        jedis = new Jedis();

        if(clearRedis){
            jedis.del(usersRedis);
            jedis.del(userNamesRedis);
            jedis.del(chipheredDB);
            jedis.del("AESkey");
            jedis.del("SHA1key");
        }

        users = new HashSet<>(); usernames = new HashSet<>();
        users.addAll(jedis.smembers(usersRedis));
        usernames.addAll(jedis.smembers(userNamesRedis));
        cipherdb = jedis.get(chipheredDB.getBytes());

        String a = jedis.get("SHA1key");
        sha1key = (a==null) ? getRandom(16) : a.getBytes();

        a = jedis.get("AESkey");
        aeskey = (a==null) ? getRandom(16) : a.getBytes();

        System.out.println(toHex(aeskey));
        System.out.println(toHex(sha1key));

        sep = "|%|";
        tpm = new sample();

        if(jedis.exists("choice"))
            choice = Integer.parseInt(jedis.get("choice"));
        else {
            choice = ThreadLocalRandom.current().nextInt(0, 5);
            jedis.set("choice", String.valueOf(choice));
        }

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
                dbpw = byte2map(tpm.decrypt(cipherdb, aeskey));
            }
            else
                dbpw = new HashMap<>();

            //update the hashmap according to the log
            for(ArrayList<String> entry : log){
                switch(entry.get(0)){
                    case "add":
                        jedis.sadd(usersRedis, applyFunction(entry.get(1), entry.get(2)));
                        jedis.sadd(userNamesRedis, entry.get(1));
                        dbpw.put(entry.get(1), entry.get(2));
                        break;
                    case "cp":
                        jedis.sdiff(usersRedis, applyFunction(entry.get(1), entry.get(2)));
                        jedis.sadd(usersRedis, applyFunction(entry.get(1), entry.get(3)));
                        dbpw.replace(entry.get(1), entry.get(3));
                        break;
                    case "cu":
                        jedis.sdiff(usersRedis, applyFunction(entry.get(1), entry.get(3)));
                        jedis.sadd(usersRedis, applyFunction(entry.get(2), entry.get(3)));

                        jedis.sdiff(userNamesRedis, entry.get(1));
                        jedis.sadd(userNamesRedis, entry.get(2));

                        dbpw.remove(entry.get(1));
                        dbpw.put(entry.get(2), entry.get(3));
                        break;
                    case "del":
                        jedis.sdiff(usersRedis, applyFunction(entry.get(1), entry.get(2)));
                        jedis.sdiff(userNamesRedis, entry.get(1));

                        dbpw.remove(entry.get(1));
                        break;
                    default: System.out.println("Something went terribly wrong");
                }
            }

            log = new ArrayList<>();

            //encrypt that bitch back
            aeskey =  getRandom(16);

            cipherdb = tpm.encrypt(dbpw.toString().getBytes(), aeskey);
            jedis.set(chipheredDB.getBytes(), cipherdb);
            jedis.set("AESkey", new String(aeskey));
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("dumped");
    }

    private void changeKey(){
        if (cipherdb != null) {

            choice = ThreadLocalRandom.current().nextInt(0, 5);
            jedis.set("choice", String.valueOf(choice));

            sha1key =  getRandom(16);

            jedis.set("SHA1key", new String(sha1key));

            long startTime = System.nanoTime();

            users = new HashSet<>();
            try {
                HashMap<String, String> db = byte2map(tpm.decrypt(cipherdb, aeskey));
                Iterator it = db.entrySet().iterator();
                while (it.hasNext()) {
                    Map.Entry pair = (Map.Entry) it.next();
                    jedis.del(usersRedis);
                    jedis.sadd(usersRedis, applyFunction((String) pair.getKey(),(String) pair.getValue()));
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
}
