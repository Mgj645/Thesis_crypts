package com.company;

import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.util.encoders.Hex;

import java.util.Map;

public class SHA_3 extends Scheme implements SchemeInterface{
    Map<String, String> users;
    final static String fileName = "users_sha3.txt";

    public SHA_3(){
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

        SHA3.DigestSHA3 digestSHA3 = new SHA3.Digest512();

        byte[] digest = digestSHA3.digest(a.getBytes());

        //System.out.println("SHA3-512 = " + Hex.toHexString(digest));
        return Hex.toHexString(digest).toString();
    }
}
