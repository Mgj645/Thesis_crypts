package com.company.newScheme;

import com.company.AES;
import com.company.SHA_224;
import com.company.SHA_3;
import com.company.SchemeInterface;
import redis.clients.jedis.Jedis;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

public class newSchemeV4 implements SchemeInterface {

    private HashSet<String> users;
    private HashSet<String> usernames;

    private static String sha1key;
    private final static String sep = "|%";

    private ArrayList<ArrayList<String>> log;
    private final static String aeskey = "q4t7w!z%C*F-JaNd";

    private byte[] cipherdb;

    private final static String usersRedis = "newSchemeUsers";
    private final static String userNamesRedis = "newSchemeUserNames";
    private final static String chipheredDB = "cipherdb";
    private final static String KEYfile = "KEY";


    private int choice;
    private final static boolean clearRedis = true;
    Jedis jedis;
    public newSchemeV4() {
        cipherdb = null;
        jedis = new Jedis();

        if(clearRedis){
            jedis.del(usersRedis);
            jedis.del(userNamesRedis);
            jedis.del(chipheredDB);
            jedis.del(KEYfile);
            jedis.del("users");
            jedis.del("usernames");
        }

        users = new HashSet<>(); usernames = new HashSet<>();
        users.addAll(jedis.smembers(usersRedis));
        usernames.addAll(jedis.smembers(userNamesRedis));
        cipherdb = jedis.get(chipheredDB.getBytes());

        sha1key = jedis.get(KEYfile);
        if(sha1key == null)
            sha1key = "a";

        jedis.del(usersRedis);
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
                    if(count++ > 3) {
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
            SecretKeySpec key = new SecretKeySpec((sha1key).getBytes("UTF-8"), HMAC);
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
                dbpw = AES.decipher(cipherdb, aeskey);
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
            cipherdb = AES.cipher(dbpw, aeskey);
            jedis.set(chipheredDB.getBytes(), cipherdb);
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("dumped");
    }

    private void changeKey(){
        if (cipherdb != null) {

            choice = ThreadLocalRandom.current().nextInt(0, 5);
            jedis.set("choice", String.valueOf(choice));

            sha1key = UUID.randomUUID().toString();
            jedis.set(KEYfile, sha1key);
            long startTime = System.nanoTime();

            users = new HashSet<>();
            try {
                HashMap<String, String> db = AES.decipher(cipherdb, aeskey);
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

            System.out.println("Changed hash set with key " + sha1key + " and it took " + (int) ((endTime - startTime) / (1000000)) + " ms!" +
                    "choice " + choice);
        }
    }
}
