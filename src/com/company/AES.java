package com.company;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.StringReader;
import java.security.Key;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

//import android.util.Base64;
public class AES extends Scheme implements SchemeInterface {
    public Object getDB() {
        return cipheredUsers;
    }
    final static String fileName = "AES.txt";
    final static String key1 = "DXeBGoKOLzydaiHtIG7qCdVkLo5cd7se";
    private byte[] cipheredUsers;


    public AES(){
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            cipheredUsers = null;

    }

    @Override
    public boolean login(String username, String password) {
        try {
            HashMap<String, String> users = decipher(cipheredUsers, key1);
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
            HashMap<String, String> users = decipher(cipheredUsers, key1);
            if(users.containsKey(username))
                return false;
            else
            {
                users.put(username, password);
                cipheredUsers = cipher(users, key1);
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
            HashMap<String, String> users = decipher(cipheredUsers, key1);
            if(!users.containsKey(username))
                return false;
            else
            {
                users.replace(username, password1, password2);
                cipheredUsers = cipher(users, key1);
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
            HashMap<String, String> users = decipher(cipheredUsers, key1);
            if(!users.containsKey(username1))
                return false;
            else
            {
                users.remove(username1, password);
                users.put(username2, password);
                cipheredUsers = cipher(users, key1);
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
            HashMap<String, String> users = decipher(cipheredUsers, key1);
            if(!users.containsKey(username))
                return false;
            else
            {
                users.remove(username, password);
                cipheredUsers = cipher(users, key1);
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

    }

    static IvParameterSpec ivSpec;

    static int ctLength;
    public static byte[] cipher(HashMap<String, String> a, String k)  {
        try {
            byte[] keyBytes = k.getBytes();
            Key key = new SecretKeySpec(keyBytes, "AES");
            Cipher c = Cipher.getInstance("AES");
            c.init(Cipher.ENCRYPT_MODE, key);
            return c.doFinal(a.toString().getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static HashMap<String, String>  decipher(byte[] ciphertext, String k)  {
        if(ciphertext==null)
            return new HashMap<>();
        try {
            byte[] keyBytes = k.getBytes();
            Key key = new SecretKeySpec(keyBytes, "AES");
            Cipher c = Cipher.getInstance("AES");
            c.init(Cipher.DECRYPT_MODE, key);
            byte[] decValue = c.doFinal(ciphertext);
            String decryptedValue = new String(decValue);
            return string2map(decryptedValue);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static HashMap<String, String> string2map(String db){
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

    public static String toHex(byte[] data, int length)
    {
        StringBuffer	buf = new StringBuffer();

        for (int i = 0; i != length; i++)
        {
            int	v = data[i] & 0xff;

            buf.append("0123456789abcdef".charAt(v >> 4));
            buf.append("0123456789abcdef".charAt(v & 0xf));
        }

        return buf.toString();
    }
}
