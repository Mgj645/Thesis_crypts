package com.company;

import java.util.Map;

public class plain_text extends Scheme implements SchemeInterface {

    Map<String, String> users;
    final static String fileName = "plaintext.txt";

    public plain_text(){
        users = (Map<String, String>) readData(fileName);
    }

    public boolean login(String username, String password){
        if(!users.containsKey(username))
            return false;
        else
            return (password.equals(users.get(username)));
    }

    public boolean register(String username, String password){
        if(users.containsKey(username))
            return false;
        else {
            users.put(username, password);
            writeData(users, fileName);
            return true;
        }
    }

    @Override
    public boolean changePassword(String username, String password1, String password2) {
        if(!users.containsKey(username))
            return false;
        else
            if(!password1.equals(users.get(username)))
                 return false;
        {
            users.put(username, password2);
            writeData(users, fileName);
            return true;
        }
    }

    @Override
    public boolean changeUsername(String username1, String username2, String password) {
        if(!users.containsKey(username1))
            return false;
        else
        if(!password.equals(users.get(username1)))
            return false;
        {
            users.remove(username1);
            users.put(username2, password);
            writeData(users, fileName);
            return true;
        }
    }

    @Override
    public boolean deleteUser(String username, String password) {
        if(!users.containsKey(username))
            return false;
        else
        if(!password.equals(users.get(username)))
            return false;
        {
            users.remove(username);
            writeData(users, fileName);
            return true;
        }
    }

}
