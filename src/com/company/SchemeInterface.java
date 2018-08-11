package com.company;

public interface SchemeInterface {


    boolean login(String username, String password) throws Exception;

    boolean register(String username, String password) throws Exception;

    boolean changePassword(String username, String password1, String password2);
    boolean changeUsername(String username1, String username2, String password);

    boolean deleteUser(String username, String password);

    Object getDB();
}
