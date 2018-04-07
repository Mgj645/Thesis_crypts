package com.company;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.StringReader;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

//import android.util.Base64;
public class AES256 extends Scheme implements SchemeInterface {
    final static String fileName = "AES256.txt";
    final static String key1 = "DXeBGoKOLzydaiHtIG7qCdVkLo5cd7se";
    private byte[] cipheredUsers;


    public AES256(){
        try {
            cipheredUsers = cipher((HashMap<String, String>) readData(fileName),generateKeyFromString(key1));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public boolean login(String username, String password) {
        try {
            HashMap<String, String> users = string2map(decipher(cipheredUsers, generateKeyFromString(key1)));
            if(!users.containsKey(username))
                return false;
            else
                return password.equals(users.get(username));
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public boolean register(String username, String password) {
        try {
            HashMap<String, String> users = string2map(decipher(cipheredUsers, generateKeyFromString(key1)));
            if(users.containsKey(username))
                return false;
            else
            {
                users.put(username, password);
                cipheredUsers = cipher(users, generateKeyFromString(key1));
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public boolean changePassword(String username, String password1, String password2) {
        try {
            HashMap<String, String> users = string2map(decipher(cipheredUsers, generateKeyFromString(key1)));
            if(!users.containsKey(username))
                return false;
            else
            {
                users.replace(username, password1, password2);
                cipheredUsers = cipher(users, generateKeyFromString(key1));
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

    }

    @Override
    public boolean changeUsername(String username1, String username2, String password) {
        try {
            HashMap<String, String> users = string2map(decipher(cipheredUsers, generateKeyFromString(key1)));
            if(!users.containsKey(username1))
                return false;
            else
            {
                users.remove(username1, password);
                users.put(username2, password);
                cipheredUsers = cipher(users, generateKeyFromString(key1));
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }


    }

    @Override
    public boolean deleteUser(String username, String password) {
        try {
            HashMap<String, String> users = string2map(decipher(cipheredUsers, generateKeyFromString(key1)));
            if(!users.containsKey(username))
                return false;
            else
            {
                users.remove(username, password);
                cipheredUsers = cipher(users, generateKeyFromString(key1));
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

    }

    static byte[] iv;
    public static byte[] cipher(HashMap<String, String> a, Key key)  {
        Cipher cipher;


        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        cipher.init(Cipher.ENCRYPT_MODE, key);
        AlgorithmParameters params = cipher.getParameters();
        iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] ciphertext = cipher.doFinal(a.toString().getBytes("UTF-8"));

            return ciphertext;


        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    public static String decipher(byte[] ciphertext, Key key)  {
        String plaintext = "null";
        Cipher cipher = null;


        try {

            /* Decrypt the message, given derived key and initialization vector. */
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            plaintext = new String(cipher.doFinal(ciphertext), "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return plaintext;
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

}
