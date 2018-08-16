import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;

public class guiSSPM{
    boolean newkey, tpmkey, tpmop, usernames, redis;
    public guiSSPM(String title, String message){
        CheckBox newkey_, tpmkey_, tpmop_, usernames_, redis_;

        Stage window = new Stage();
        window.initModality(Modality.APPLICATION_MODAL);
        window.setTitle(title);
        window.setMinWidth(250);
        Label label = new Label("Pick your SSPM settings");

        usernames_ = new CheckBox("Don't allow replicate usernames");
        newkey_ = new CheckBox("Generate new keys Periodically");
        tpmkey_ = new CheckBox("Use TPM to store the secret key");
        tpmop_ = new CheckBox("Use TPM for all hashing operations (may be very slow)");
        redis_ = new CheckBox("Use a Redis database to achive persistency (Redis service required)");

        Button closeBotton = new Button("Proceed");
        closeBotton.setOnAction(e -> {
            if(usernames_.isSelected())
                usernames = true;

            if(newkey_.isSelected())
                newkey = true;

            if(tpmkey_.isSelected())
                tpmkey = true;

            if(tpmop_.isSelected())
                tpmop = true;

            if(redis_.isSelected())
                redis = true;
        window.close();
        });

        VBox layout = new VBox(10);
        layout.getChildren().addAll(label, usernames_, newkey_, tpmkey_, tpmop_, redis_, closeBotton);
        layout.setAlignment(Pos.CENTER);

        Scene scene = new Scene(layout);
        window.setScene(scene);
        window.showAndWait();
    }


}
