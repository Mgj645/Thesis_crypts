package com.company;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.util.Map;

//import android.util.Base64;
public class AES256 extends Scheme implements SchemeInterface {
    Map<String, String> users;
    final static String fileName = "AES256.txt";
    final static String key1 = "DXeBGoKOLzydaiHtIG7qCdVkLo5cd7se";

    public AES256(){users = (Map<String, String>) readData(fileName);}

    @Override
    public boolean login(String username, String password) {
        return true;
    }

    @Override
    public boolean register(String username, String password) {
        return false;
    }

    @Override
    public boolean changePassword(String username, String password1, String password2) {
        return false;
    }

    @Override
    public boolean changeUsername(String username1, String username2, String password) {
        return false;
    }

    @Override
    public boolean deleteUser(String username, String password) {
        return false;
    }

    static byte[] iv;
    public static byte[] cipher(String a, Key key)  {
        Cipher cipher;


        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        cipher.init(Cipher.ENCRYPT_MODE, key);
        AlgorithmParameters params = cipher.getParameters();
        iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] ciphertext = cipher.doFinal(a.getBytes("UTF-8"));

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


}
