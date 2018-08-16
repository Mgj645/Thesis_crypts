import com.company.*;
import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import javafx.stage.Stage;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

public class GUI extends Application {

    static int noUsers;

    static String[] passwords;
    static String[] usernames;
    final int sndCol = 5;

    RadioButton plainBTN, md5BTN, sha3BTN, sha224, sspmBTN, sgxBTN;

    Button submitBTN, simBTN, schemeBTN;
    RadioButton loginBTN, registerBTN, cuBTN, cpBTN, delBTN;
    TextField simFIELD, userFIELD, passFIELD, wildFIELD;
    ListView myHashes, consoleView;

    Label col1, col2, col3, simLABEL, consoleLABEL;
    final ToggleGroup operationGroup = new ToggleGroup();
    final ToggleGroup schemeGroup = new ToggleGroup();
    SchemeInterface sc;

    boolean schemeSEL = false;

    boolean SSnewkey, SStpmkey, SStpmop, SSusernames, SSredis;
    guiSSPM SS;
    @Override
    public void start(Stage primaryStage) throws Exception {
        primaryStage.setTitle("Password Database Schemes");
        //StackPane layout = new StackPane();
        GridPane grid = new GridPane();
        grid.setPadding((new Insets(10, 10, 10, 10)));
        grid.setVgap(13);
        grid.setHgap(10);
        setElements();
        grid.add(myHashes, sndCol + 4, 2, 4, 9);
        grid.add(consoleView, sndCol, 8, 3, 3);
        grid.getChildren().addAll(col1, col2, col3,
                plainBTN, md5BTN, sha3BTN, sha224, sspmBTN, schemeBTN, sgxBTN, simLABEL, simFIELD, simBTN, consoleLABEL,
                submitBTN, loginBTN, registerBTN, cuBTN, cpBTN, delBTN, userFIELD, passFIELD, wildFIELD);
        Scene mainScene = new Scene(grid, 900, 500);
        primaryStage.setScene(mainScene);
        primaryStage.show();
        //grid.setStyle("-fx-background-color: #4286f4;");
        setActions();
    }

    private void setElements() {
        col1 = new Label("1. Choose a Scheme");
        col2 = new Label("2. Choose an Operation");
        col3 = new Label("Database View");

        //1st column
        simLABEL = new Label("Simulate Users");
        simFIELD = new TextField();
        simBTN = new Button("Simulate");
        simFIELD.setPromptText("Input number, max 1M");
        plainBTN = new RadioButton("plaintext");
        md5BTN = new RadioButton("MD5");
        sha3BTN = new RadioButton("SHA-3");
        sha224 = new RadioButton("SHA-224");
        sspmBTN = new RadioButton("SSPM");
        sgxBTN = new RadioButton("SSPM with Intel SGX");

        schemeBTN = new Button("Enter Scheme");

        plainBTN.setToggleGroup(schemeGroup);
        md5BTN.setToggleGroup(schemeGroup);
        sha3BTN.setToggleGroup(schemeGroup);
        sha224.setToggleGroup(schemeGroup);
        sspmBTN.setToggleGroup(schemeGroup);

        GridPane.setConstraints(plainBTN, 0, 2);
        GridPane.setConstraints(md5BTN, 0, 3);
        GridPane.setConstraints(sha3BTN, 0, 4);
        GridPane.setConstraints(sha224, 0, 5);
        GridPane.setConstraints(sspmBTN, 0, 6);
        GridPane.setConstraints(sgxBTN, 0, 7);

        GridPane.setConstraints(schemeBTN, 1, 7);

        GridPane.setConstraints(col1, 0, 1);
        GridPane.setConstraints(simLABEL, 0, 8);
        GridPane.setConstraints(simFIELD, 0, 9);
        GridPane.setConstraints(simBTN, 1, 9);

        //2nd column
        consoleLABEL = new Label("Console Log");
        submitBTN = new Button("Submit");

        userFIELD = new TextField();
        userFIELD.setPromptText("username");
        passFIELD = new TextField();
        passFIELD.setPromptText("password");

        wildFIELD = new TextField();
        wildFIELD.setVisible(false);

        loginBTN = new RadioButton("Login");
        registerBTN = new RadioButton("Register");
        cuBTN = new RadioButton("Change Username");
        cpBTN = new RadioButton("Change Password");
        delBTN = new RadioButton("Delete User");

        loginBTN.setToggleGroup(operationGroup);
        registerBTN.setToggleGroup(operationGroup);
        cuBTN.setToggleGroup(operationGroup);
        cpBTN.setToggleGroup(operationGroup);
        delBTN.setToggleGroup(operationGroup);

        GridPane.setConstraints(loginBTN, sndCol, 2);
        GridPane.setConstraints(registerBTN, sndCol, 3);
        GridPane.setConstraints(cuBTN, sndCol, 4);
        GridPane.setConstraints(cpBTN, sndCol, 5);
        GridPane.setConstraints(delBTN, sndCol, 6);

        GridPane.setConstraints(userFIELD, sndCol + 2, 2);
        GridPane.setConstraints(passFIELD, sndCol + 2, 3);
        GridPane.setConstraints(wildFIELD, sndCol + 2, 4);

        GridPane.setConstraints(submitBTN, sndCol + 2, 6);
        GridPane.setConstraints(col2, sndCol, 1);
        GridPane.setConstraints(consoleLABEL, sndCol, 7);

        //3rd  column & console
        myHashes = new ListView();
        consoleView = new ListView();
        consoleView.setStyle("-fx-control-inner-background: black; -fx-text-fill: yellow;");
        GridPane.setConstraints(col3, sndCol + 4, 1);
    }

    private void setActions() {
        sspmBTN.setOnAction(e-> SS = new guiSSPM("title", "message"));
        simBTN.setOnAction(e -> {
            try {
                //System.out.println(simFIELD.getText());
                noUsers = Integer.parseInt(simFIELD.getText());
                simulateUsers();
            } catch (Exception e1) {
                e1.printStackTrace();
            }
        });
        schemeBTN.setOnAction(e -> {
            schemeSEL = true;
            if (plainBTN.isSelected()) sc = new plain_text();
            else if (md5BTN.isSelected()) sc = new md5();
            else if (sha3BTN.isSelected()) sc = new SHA_3();
            else if (sha224.isSelected()) sc = new SHA_224();
            else if (sspmBTN.isSelected()){
                SSnewkey = SS.newkey;
                SSusernames = SS.usernames;
                SSredis = SS.redis;
                SStpmkey = SS.tpmkey;
                SStpmop = SS.tpmop;
                sc = new SSPM(SSusernames, SSredis, SSnewkey, SStpmkey, SStpmop);
                //sc = new newSchemeV1();
            }
            else
                schemeSEL = false;
        });

        submitBTN.setOnAction(e -> {
            try {
                if (registerBTN.isSelected()) {
                    boolean b = sc.register(userFIELD.getText(), passFIELD.getText());
                    updateConsoleView("Register", b);
                }

                if (loginBTN.isSelected()) {
                    boolean b = sc.login(userFIELD.getText(), passFIELD.getText());
                    updateConsoleView("Login", b);
                }

                if (cuBTN.isSelected()) {
                    boolean b = sc.changeUsername(userFIELD.getText(), passFIELD.getText(), wildFIELD.getText());
                    updateConsoleView("Change Username", b);
                }

                if (cpBTN.isSelected()) {
                    boolean b = sc.changePassword(userFIELD.getText(), passFIELD.getText(), wildFIELD.getText());
                    updateConsoleView("Change Password", b);
                }

                if (delBTN.isSelected()) {
                    boolean b = sc.deleteUser(userFIELD.getText(), passFIELD.getText());
                    updateConsoleView("Delete User", b);
                }

                if (!loginBTN.isSelected()) {
                    updateListView();
                }
            } catch (Exception e1) {
                e1.printStackTrace();
            }
        });

        loginBTN.setOnAction(e -> logRegDelforms());
        registerBTN.setOnAction(e -> logRegDelforms());
        delBTN.setOnAction(e -> logRegDelforms());
        cuBTN.setOnAction(e -> {
            cucpForms();
            userFIELD.setPromptText("old username");
            passFIELD.setPromptText("new username");
            wildFIELD.setPromptText("password");
        });

        cpBTN.setOnAction(e -> {
            cucpForms();
            userFIELD.setPromptText("username");
            passFIELD.setPromptText("old password");
            wildFIELD.setPromptText("new password");
        });
    }

    private void logRegDelforms() {
        userFIELD.setVisible(true);
        userFIELD.setText("");
        userFIELD.setPromptText("username");

        passFIELD.setVisible(true);
        passFIELD.setText("");
        passFIELD.setPromptText("password");

        wildFIELD.setVisible(false);
    }

    private void cucpForms() {
        userFIELD.setVisible(true);
        wildFIELD.setVisible(true);
        passFIELD.setVisible(true);
        passFIELD.setText("");
        userFIELD.setText("");
        wildFIELD.setText("");
    }

    boolean firstSim = false;

    private void simulateUsers() throws Exception {
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

        long startTime = System.nanoTime();

        for (int j = 0; j < noUsers; j++)
            sc.register(usernames[j], passwords[j]);
        long endTime = System.nanoTime();
        double duration = (double) ((endTime - startTime) / (1000000));


        consoleView.getItems().add("Simmed " + noUsers + " Users and it took " + duration + " ms.");

        updateListView();
    }

    private void updateListView() {
        myHashes.getItems().clear();
        if (sspmBTN.isSelected()) {
            HashSet users = (HashSet) sc.getDB();
            myHashes.getItems().addAll(users);
        } else {
            Map<String, String> users = (Map<String, String>) sc.getDB();
            List<String> users_ = new ArrayList();
            for (Map.Entry<String, String> entry : users.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();
                users_.add(key + ":" + value);
            }
            myHashes.getItems().addAll(users_);
        }
    }

    private void updateConsoleView(String op, boolean sta) {
        if (sta)
            consoleView.getItems().add(op + " sucessful!");
        else
            consoleView.getItems().add(op + " not sucessful!");
    }
}

