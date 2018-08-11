package com.company;

import edu.nyu.poly.pph.PolyPasswordHasher;
import edu.nyu.poly.pph.model.PPHAccount;

import java.io.IOException;
import java.util.List;

public class PolyFace implements SchemeInterface{
    public Object getDB() {
        return null;
    }
    private PolyPasswordHasher pph;
    private final int shares = 0;

    public PolyFace( ){
        try {
            pph = new PolyPasswordHasher("pph.properties");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public boolean login(String username, String password) throws Exception {
        return pph.isValidLogin(username,password);
    }

    @Override
    public boolean register(String username, String password) throws Exception {
            return pph.createAccount(username, password, shares);
    }

    @Override
    public boolean changePassword(String username, String password1, String password2) {
        boolean result = false;
        List<PPHAccount> users = pph.getUsers();

        PPHAccount p = getUser(users, username);
       if(p != null){
           PPHAccount pa = p;
           if(p.getPassword().equals(password1)) {
               p.setPassword(password2);
               users.remove(pa);
               users.add(p);
               pph.setUsers(users);
               result = true;
           }
           }
        return result;
    }


    @Override
    public boolean changeUsername(String username1, String username2, String password) {
        boolean result = false;
        List<PPHAccount> users = pph.getUsers();
        PPHAccount p = getUser(users, username1);


        if(p != null){
            PPHAccount pa = p;
            if(p.getPassword().equals(password)) {
                p.setUsername(username2);
                users.remove(pa);
                users.add(p);
                pph.setUsers(users);
                result = true;
            }
        }
        return result;
    }

    @Override
    public boolean deleteUser(String username, String password) {
        boolean result = false;
        List<PPHAccount> users = pph.getUsers();
        PPHAccount p = getUser(users, username);

        if(p != null){
            if(p.getPassword().equals(password)) {
                users.remove(p);
                pph.setUsers(users);
                result = true;
            }
        }
        return result;
    }

    private PPHAccount getUser(List<PPHAccount> l, String u){
        for(PPHAccount p: l){
            if(p.getUsername().equals(u))
                return p;
        }
        return null;
    }
}
