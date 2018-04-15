package com.company.newScheme;

//import redis.clients.jedis.Jedis;

import com.company.SchemeInterface;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.HashSet;

public class newSchemeV1 implements SchemeInterface {

    private HashSet<String> users;
    private HashSet<String> usernames;

    private static String sha1key;
    private final static String sep = "|%";

    private int count;
    private final static int finalcount = 10000;

    //private Jedis jedis;
    public newSchemeV1() {
        count = 0;
       // jedis = new Jedis();
        /*String tmpk = jedis.get("key");
        if(tmpk == null || tmpk.equals(""))
            sha1key = "chuck";
        else
            sha1key = tmpk;*/
        users = new HashSet<String>();
        usernames =  new HashSet<String>();
        if(sha1key == null)
            sha1key = "a";
    }


    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

    public boolean login(String username, String password) {
        String user = applyFunction(username, password);
        return users.contains(user);
    }

    public boolean register(String username, String password) {

        if (!usernames.add(username))
            return false;
        else {
            return users.add(applyFunction(username, password));
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
            users.add(applyFunction(username2, password));
            usernames.remove(username1);
            usernames.add(username2);
            return true;
        }
    }

    public boolean deleteUser(String username, String password) {
        if (!usernames.remove(username))
            return false;
        else {
            users.remove(applyFunction(username, password));
            return true;
        }
    }
    
    public String applyFunction(String username, String password) {
        String user = null;
        try {
            SecretKeySpec key = new SecretKeySpec((sha1key).getBytes("UTF-8"), HMAC_SHA1_ALGORITHM);
            Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
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


}
