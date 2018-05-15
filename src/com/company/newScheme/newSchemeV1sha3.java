package com.company.newScheme;

//import redis.clients.jedis.Jedis;

import com.company.SchemeInterface;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.util.encoders.Hex;

import java.util.HashSet;

public class newSchemeV1sha3 implements SchemeInterface {

    private HashSet<String> users;
    private HashSet<String> usernames;

    private final static String sep = "|%";

    public newSchemeV1sha3() {

        users = new HashSet<String>();
        usernames = new HashSet<String>();
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

        SHA3.DigestSHA3 digestSHA3 = new SHA3.Digest512();

        byte[] digest = digestSHA3.digest((username+sep+password).getBytes());

        //System.out.println("SHA3-512 = " + Hex.toHexString(digest));
        return Hex.toHexString(digest).toString();
    }



}
