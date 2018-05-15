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
    final static boolean md5 = false;
    final static boolean sha_224 = false;
    final static boolean sha_3 = false;
    final static boolean b_crypt = false;
    final static boolean aes256 = false;
    final static boolean polyPassword = false;

    final static boolean newSchemeV0 = true;
    final static boolean newSchemeV1 = false;
    final static boolean newSchemeV2 = false;
    final static boolean newSchemeV3 = false;
    final static boolean newSchemeV4 = true;
    final static boolean newSchemeV4redis = false;

    final static boolean newSchemeV1shaMD5 = false;
    final static boolean newSchemeV1sha256 = false;
    final static boolean newSchemeV1sha3 = false;
    final static boolean newSchemeV1sha224 = false;

    final static boolean newScheme = true;
    final static boolean newSchemeDES = true;

    final static boolean sequence_hash = false;

    final static int noUsers = 800;

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
            Thread.sleep(2000);
            if (newSchemeV0)  time.put("V0", runScheme ("V0", new newSchemeV0()));

            if (newSchemeV1)  time.put("V1", runScheme ("V1", new newSchemeV1()));

            if (newSchemeV2)  time.put("V2", runScheme ("V2", new newSchemeV2()));

            if (newSchemeV3)  time.put("V3", runScheme ("V3", new newSchemeV3()));

            if (newSchemeV4)  time.put("V4", runScheme ("V4", new newSchemeV4()));

            if (newSchemeV4redis)  time.put("V4R", runScheme ("V4R", new newSchemeV4redis()));

            if (newSchemeV1shaMD5)  time.put("V1 HMAC md5", runScheme ("HMAC V1 md5", new newSchemeV1SHAMD5()));

            if (newSchemeV1sha256)  time.put("HMAC V1 sha 256", runScheme ("HMAC V1 sha256", new newSchemeV1sha256()));

            //if (newSchemeV1sha3)  time.put("V1 sha3 ", runScheme ("V1 sha3", new newSchemeV1sha3()));

            if (newSchemeV1sha224)  time.put("V1 sha224", runScheme ("V1 sha224", new newSchemeV1sha224()));

            if (plain) time.put("Plain Text", runScheme ("plaintext", new plain_text()));

            if (md5) time.put("MD5", runScheme ("md5", new md5()));

            if (sha_224) time.put("SHA 224", runScheme ("sha_224", new SHA_224()));

            if (sha_3) time.put("SHA 3", runScheme ("sha_3", new SHA_3()));

            if (b_crypt) time.put("BCRYPT", runScheme ("B-CRYPT", new bcrypt()));

            if(aes256)  time.put("AES 256", runScheme("aes256", new AES()));

            if(polyPassword)  time.put("PolyPasswordHasher", runScheme("PolyHash", new PolyFace()));

            launch(args);

            //if (sequence_hash) seqHash();
        } else if (command.equals(("2"))) {
            com.company.newScheme.newSchemeV4redis NS = new newSchemeV4redis();
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
        int wrong = 0; int right = 0;

        if (register) {
            long startTime = System.nanoTime();
            for (int i = 0; i < noUsers; i++)
                sc.register(usernames[i], passwords[i]);
            long endTime = System.nanoTime();
            System.out.print(" - Registration Completed");

            duration[0] = (double) ((endTime - startTime)/(1000000));
        }
        Thread.sleep(1500);

        if (login) {
            long startTime = System.nanoTime();
            for (int i = 0; i < noUsers; i++) {
                if(sc.login(usernames[i], passwords[i]))
                    right++;
                else
                    wrong++;
            }
            long endTime = System.nanoTime();
            System.out.print(" - Login Completed " + right + " sucessful, " + wrong + " not!" );

            duration[1] = (double) ((endTime - startTime)/(1000000));

        }
        System.out.println("");
        return duration;
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
