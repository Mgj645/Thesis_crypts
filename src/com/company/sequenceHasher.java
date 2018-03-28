package com.company;

import java.util.Map;

public class sequenceHasher extends Scheme implements SchemeInterface {
    Map<String, String> users;
    final static String fileName = "seq_hash.txt";

    final static String[] sequences = {"423", "322"};

    public sequenceHasher(){
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

    private String applyFunction(String pwd){
        String[] ss = sequences[1].split("");
        for(int i = 0; i < ss.length-1; i++)
            switch(Integer.parseInt(ss[i])){
                case 1: pwd = pwd; break;
                case 2:  pwd = md5.applyFunction(pwd); break;
                case 3:  pwd = SHA_3.applyFunction(pwd); break;
                case 4:  pwd = bcrypt.applyFunction(pwd); break;
                default: System.out.println("oops");
            }

        return pwd;
    }
}
