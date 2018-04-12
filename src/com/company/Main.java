package com.company;

import com.company.newScheme.*;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.chart.BarChart;
import javafx.scene.chart.CategoryAxis;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;
import javafx.stage.Stage;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class Main extends Application  {


    static String[] passwords;
    static String[] usernames;

    final static boolean plain = true;
    final static boolean md5 = true;
    final static boolean sha_224 = true;
    final static boolean sha_3 = true;
    final static boolean b_crypt = false;
    final static boolean aes256 = false;
    final static boolean polyPassword = true;

    final static boolean newSchemeV0 = true;
    final static boolean newSchemeV1 = true;
    final static boolean newSchemeV2 = true;
    final static boolean newScheme = true;



    final static boolean sequence_hash = false;

    final static int noUsers = 10000;

    final static boolean register = true;
    final static boolean login = true;
    static private HashMap<String, double[]> time;
    public static void main(String[] args) throws Exception {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Press 1 for auto mode. Press 2 for manual mode.");
        String command = br.readLine();

        time = new HashMap<>();

        if (command.equals("1")) {
            simulateUsers();
            Thread.sleep(1500);

            if (plain) time.put("Plain Text", runScheme ("plaintext", new plain_text()));
            Thread.sleep(1500);

            if (md5) time.put("MD5", runScheme ("md5", new md5()));
            Thread.sleep(1500);

            if (sha_224) time.put("SHA 224", runScheme ("sha_224", new SHA_224()));
            Thread.sleep(1500);

            if (sha_3) time.put("SHA 3", runScheme ("sha_3", new SHA_3()));
            Thread.sleep(1500);

            if (b_crypt) time.put("BCRYPT", runScheme ("B-CRYPT", new bcrypt()));
            Thread.sleep(1500);

            if(aes256)  time.put("AES 256", runScheme("aes256", new AES256()));
            Thread.sleep(1500);

            if(polyPassword)  time.put("PolyPasswordHasher", runScheme("PolyHash", new PolyFace()));
            Thread.sleep(1500);


            if (newSchemeV0)  time.put("New Scheme V0", runScheme ("New Scheme V0", new newSchemeV0()));
            Thread.sleep(1500);

            if (newSchemeV1)  time.put("New Scheme V1", runScheme ("New Scheme V1", new newSchemeV1()));
            Thread.sleep(1500);

            if (newSchemeV2)  time.put("New Scheme V2", runScheme ("New Scheme V2", new newSchemeV2()));
            Thread.sleep(1500);

            if (newScheme)  time.put("New Scheme", runScheme ("New Scheme", new newScheme()));
            Thread.sleep(1500);
            launch(args);

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

    private static double[] runScheme(String name, SchemeInterface sc) throws Exception {
        System.out.print(name);
        double[] duration = new double[2];
        if (register) {
            long startTime = System.nanoTime();
            for (int i = 0; i < noUsers; i++)
                sc.register(usernames[i], passwords[i]);
            System.out.print(" - Registration Completed");
            long endTime = System.nanoTime();
            duration[0] = (double) ((endTime - startTime)/(1000000));
            writeTime(name + " - register", duration[0]);
        }
        Thread.sleep(1500);

        if (login) {
            long startTime = System.nanoTime();
            for (int i = 0; i < noUsers; i++)
               sc.login(usernames[i], passwords[i]);
            System.out.print(" - Login Completed");
            long endTime = System.nanoTime();
            duration[1] = (double) ((endTime - startTime)/(1000000));
            writeTime(name + " - login", duration[1]);
        }
        System.out.println("");
        return duration;
    }

    static void writeTime(String name, double time) {
       /* try(FileWriter fw = new FileWriter("time.txt", true);
            BufferedWriter bw = new BufferedWriter(fw);
            PrintWriter out = new PrintWriter(bw))
        {
            out.println(name);
            out.println(time + " ms");
        } catch (IOException e) {
        }*/

    }

    @Override public void start(Stage stage) {
        stage.setTitle("Bar Chart Sample");
        final NumberAxis xAxis = new NumberAxis();
        final CategoryAxis yAxis = new CategoryAxis();
        final BarChart<Number,String> bc =
                new BarChart<Number,String>(xAxis,yAxis);
        bc.setTitle(noUsers + " entradas");
        xAxis.setLabel("Tempo em ms");
        xAxis.setTickLabelRotation(90);
        yAxis.setLabel("Esquema");

        XYChart.Series series1 = new XYChart.Series();
        series1.setName("Register Operations");
        HashMap<String, double[]> time2 = new HashMap<>();
        time2.putAll(time);
        Iterator it = time.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry pair = (Map.Entry)it.next();
            series1.getData().add(new XYChart.Data(((double[]) pair.getValue())[0], pair.getKey()));
        }

        XYChart.Series series2 = new XYChart.Series();
        series2.setName("Login Operations");
        it = time2.entrySet().iterator();

        while (it.hasNext()) {
            Map.Entry pair = (Map.Entry)it.next();
            series2.getData().add(new XYChart.Data(((double[]) pair.getValue())[1], pair.getKey()));
        }
        ;

        Scene scene  = new Scene(bc,800,600);
        bc.getData().addAll(series1, series2);
        stage.setScene(scene);
        stage.show();
    }

}
