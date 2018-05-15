package com.company.newScheme;

import com.company.SchemeInterface;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.HashSet;

public class newSchemeV0 implements SchemeInterface {

    private HashSet<String> users;

    private static String sha1key;
    private final static String sep = "|%";

    public newSchemeV0() {
        users = new HashSet<String>();
        sha1key = "a";
    }


    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

    public boolean login(String username, String password) {
        return users.contains(applyFunction(username, password));
    }

    public boolean register(String username, String password) {

        return users.add(applyFunction(username, password));
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
            return users.add(applyFunction(username2, password));
        }
    }

    public boolean deleteUser(String username, String password) {
        return users.remove(applyFunction(username, password));
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
