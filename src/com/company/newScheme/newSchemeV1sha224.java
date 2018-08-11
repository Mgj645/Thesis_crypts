package com.company.newScheme;

//import redis.clients.jedis.Jedis;

import com.company.SchemeInterface;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;

public class newSchemeV1sha224 implements SchemeInterface {
    public Object getDB() {
        return users;
    }
    private HashSet<String> users;
    private HashSet<String> usernames;

    private static String sha1key;
    private final static String sep = "|%";


    public newSchemeV1sha224() {

        users = new HashSet<String>();
        usernames = new HashSet<String>();

        sha1key = "a";
    }


    public boolean login(String username, String password) {
        return users.contains(applyFunction(username, password));
    }

    public boolean register(String username, String password) {
        if (!usernames.add(username))
            return false;
        else {
            usernames.add(username);
            return users.add(applyFunction(username, password));}
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
            usernames.remove(username1);
            usernames.add(username2);
            return users.add(applyFunction(username2, password));
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
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-224");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        StringBuffer hexString = new StringBuffer();
        md.update((username+sep+password).getBytes());
        byte[] digest = md.digest();


        for (int i = 0; i < digest.length; i++) {
            if ((0xff & digest[i]) < 0x10) {
                hexString.append("0"
                        + Integer.toHexString((0xFF & digest[i])));
            } else {
                hexString.append(Integer.toHexString(0xFF & digest[i]));
            }
        }

        return hexString.toString();
    }


}
