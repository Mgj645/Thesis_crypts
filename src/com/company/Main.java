package com.company;

import java.io.*;

public class Main {
    static String[] passwords;
    static String[] usernames;

    final static boolean plain = false;
    final static boolean md5 = false;
    final static boolean sha_224 = false;
    final static boolean sha_3 = false;
    final static boolean b_crypt = false;

    final static boolean aes256 = true;

    final static boolean newScheme = false;

    final static boolean sequence_hash = false;

    final static int noUsers = 200;

    final static boolean register = false;
    final static boolean login = true;

    public static void main(String[] args) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Press 1 for auto mode. Press 2 for manual mode.");
        String command = br.readLine();

        if (command.equals("1")) {
            simulateUsers();

            if (plain) runScheme ("plaintext", new plain_text());
            if (md5) runScheme ("md5", new md5());

            if (sha_224) runScheme ("sha_224", new SHA_224());

            if (sha_3) runScheme ("sha_3", new SHA_3());
            if (b_crypt) runScheme ("B-CRYPT", new bcrypt());
            if (newScheme)  runScheme ("New Scheme", new newScheme());

            if(aes256)  runScheme("aes256", new AES256());

            //if (sequence_hash) seqHash();
        } else if (command.equals(("2"))) {
            newScheme NS = new newScheme();
            System.out.println("Welcome to the new scheme");
            while (true) {
                System.out.println("Choose your operation");
                String line = br.readLine();
                String[] words = line.split(" ");
                command = words[0];
                boolean res = false;
                switch (command) {
                    case "login":
                        if (words.length == 3)
                            res = NS.login(words[1], words[2]);
                        break;

                    case "register":
                        if (words.length == 3)
                            res = NS.register(words[1], words[2]);
                        break;

                    case "cp":
                        if (words.length == 4)
                            res = NS.changePassword(words[1], words[2], words[3]);
                        break;

                    case "cu":
                        if (words.length == 4)
                            res = NS.changeUsername(words[1], words[2], words[3]);
                        break;

                    case "delete":
                        if (words.length == 3)
                            res = NS.deleteUser(words[1], words[2]);
                        break;
                }

                if (res)
                    System.out.print(" - Operation Sucessful");
                else
                    System.out.print(" - Operation NOT Sucessful");
                System.out.println("");
            }
        } else {
            System.out.println("Command not recognized");

        }
    }

    private static void simulateUsers() throws IOException {
        BufferedReader lines = new BufferedReader(new FileReader("passwords.txt"));
        String line = lines.readLine();
        int i = 0;
        passwords = new String[noUsers];
        while (line != null && i < noUsers) {
            passwords[i++] = line;
            line = lines.readLine();
        }

        lines = new BufferedReader(new FileReader("usernames.txt"));
        line = lines.readLine();
        i = 0;
        usernames = new String[noUsers];
        while (line != null && i < noUsers) {
            usernames[i++] = line;
            line = lines.readLine();
        }

    }

    private static void runScheme(String name, SchemeInterface sc){
        System.out.print(name);
        if (register) {
            long startTime = System.nanoTime();
            for (int i = 0; i < noUsers; i++)
                sc.register(usernames[i], passwords[i]);
            System.out.print(" - Registration Completed");
            long endTime = System.nanoTime();
            long duration =  ((endTime - startTime)/(1000000));
            writeTime(name + " - register", duration);
        }

        if (login) {
            long startTime = System.nanoTime();
            for (int i = 0; i < noUsers; i++)
                System.out.print(" " + sc.login(usernames[i], passwords[i]));
            System.out.print(" - Login Completed");
            long endTime = System.nanoTime();
            long duration =  ((endTime - startTime)/(1000000));
            writeTime(name + " - login", duration);
        }
        System.out.println("");
    }

    static void writeTime(String name, long time) {
        try(FileWriter fw = new FileWriter("time.txt", true);
            BufferedWriter bw = new BufferedWriter(fw);
            PrintWriter out = new PrintWriter(bw))
        {
            out.println(name);
            out.println(time + " ms");
        } catch (IOException e) {
        }
    }
}
