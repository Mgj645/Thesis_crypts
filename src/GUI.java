import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.Priority;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;

import javax.swing.*;

public class GUI extends Application {
    Button submitBTN;
    RadioButton loginBTN, registerBTN, cuBTN, cpBTN, delBTN;
    TextField userFIELD, passFIELD, wildFIELD;
    ListView myHashes;
    final ToggleGroup group = new ToggleGroup();
    @Override
    public void start(Stage primaryStage) throws Exception {
        primaryStage.setTitle("Password Database Schemes");
       //StackPane layout = new StackPane();
        GridPane grid = new GridPane();
        grid.setPadding((new Insets(10, 0 , 10, 10)));
        grid.setVgap(8);
        grid.setHgap(10);
        setButtons();

        grid.add(myHashes, 4, 1, 4, 6);
        grid.getChildren().addAll(submitBTN, loginBTN, registerBTN, cuBTN, cpBTN, delBTN, userFIELD, passFIELD, wildFIELD);
        Scene mainScene = new Scene(grid, 600, 500);
        primaryStage.setScene(mainScene);
        primaryStage.show();
        //grid.setStyle("-fx-background-color: #4286f4;");
        submitBTN.setOnAction(e -> {
                String user = userFIELD.getText() + ":" + passFIELD.getText();
                myHashes.getItems().add(user);
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

    private void setButtons(){
        myHashes = new ListView();
        submitBTN = new Button();
        submitBTN.setText("Submit");

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

        loginBTN.setToggleGroup(group); registerBTN.setToggleGroup(group);
        cuBTN.setToggleGroup(group); cpBTN.setToggleGroup(group);
        delBTN.setToggleGroup(group);

        GridPane.setConstraints(loginBTN, 0,1);
        GridPane.setConstraints(registerBTN, 0,2);
        GridPane.setConstraints(cuBTN, 0,3);
        GridPane.setConstraints(cpBTN, 0,4);
        GridPane.setConstraints(delBTN, 0,5);

        GridPane.setConstraints(userFIELD, 2,1);
        GridPane.setConstraints(passFIELD, 2,2);
        GridPane.setConstraints(wildFIELD, 2,3);

        GridPane.setConstraints(submitBTN, 2,5);

    }

    private void logRegDelforms(){
        userFIELD.setVisible(true);
        userFIELD.setText("");
        userFIELD.setPromptText("username");

        passFIELD.setVisible(true);
        passFIELD.setText("");
        passFIELD.setPromptText("password");

        wildFIELD.setVisible(false);

    }

    private void cucpForms(){
        userFIELD.setVisible(true);
        wildFIELD.setVisible(true);
        passFIELD.setVisible(true);
        passFIELD.setText("");
        userFIELD.setText("");
        wildFIELD.setText("");
    }
}
