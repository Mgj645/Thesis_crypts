package com.company;

import java.io.*;
import java.util.HashMap;

public class Scheme {
    OutputStream ops = null;
    ObjectOutputStream objOps = null;
    int count;
    final static int finalcount = 299;

    void writeData(Object users, String fileName) {
        if(++count % finalcount == 0) {
            try {
                ops = new FileOutputStream(fileName);
                objOps = new ObjectOutputStream(ops);
                objOps.writeObject(users);
                objOps.flush();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    if (objOps != null) objOps.close();
                } catch (Exception ex) {

                }
            }
        }
    }

    Object readData(String fileName) {
        InputStream fileIs = null;
        ObjectInputStream objIs = null;
        Object users;
        try {
            fileIs = new FileInputStream(fileName);
            objIs = new ObjectInputStream(fileIs);
            users = objIs.readObject();
          // System.out.println("");
          // System.out.println(Collections.singletonList(users)); // method 2
            return users;
        } catch (FileNotFoundException e) {
                users = new HashMap<String, String>();

            return users;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } finally {
            try {
                if (objIs != null) objIs.close();
            } catch (Exception ex) {

            }
        }
        return null;
    }

}
