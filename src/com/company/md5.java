package com.company;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

public class md5 extends Scheme implements SchemeInterface{
    Map<String, String> users;
    final static String fileName = "users_md5.txt";

    public md5(){
        users = (Map<String, String>) readData(fileName);
    }

    public boolean login(String username, String password){
        username = applyFunction(username);
        if(!users.containsKey(username))
            return false;
        else
            return (applyFunction(password).equals(users.get(username)));
    }

    public boolean register(String username, String password){
        username = applyFunction(username);
        if(users.containsKey(username))
            return false;
        else {
            users.put(username, applyFunction(password));
            writeData(users, fileName);
            return true;
        }
    }

    @Override
    public boolean changePassword(String username, String password1, String password2) {
        if(!users.containsKey(username))
            return false;
        else
        if(!applyFunction(password1).equals(users.get(username)))
            return false;
        {
            users.put(username, applyFunction(password2));
            writeData(users, fileName);
            return true;
        }
    }

    @Override
    public boolean changeUsername(String username1, String username2, String password) {

        if(!users.containsKey(username1))
            return false;
        else
        if(!applyFunction(password).equals(users.get(username1)))
            return false;
        {
            users.remove(username1);
            users.put(username2, applyFunction(password));
            writeData(users, fileName);
            return true;
        }
    }

    @Override
    public boolean deleteUser(String username, String password) {
        if(!users.containsKey(username))
            return false;
        else
        if(!applyFunction(password).equals(users.get(username)))
            return false;
        {
            users.remove(username);
            writeData(users, fileName);
            return true;
        }
    }

    public static String applyFunction(String a){
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        StringBuffer hexString = new StringBuffer();
        md.update(a.getBytes());
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
