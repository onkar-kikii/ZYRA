import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DBConnection {

    public static Connection getConnection(String password)
            throws SQLException {

        String url = System.getenv("DB_URL");
        String user = System.getenv("DB_USER");
        String dbPassword = System.getenv("DB_PASSWORD");

        if (url == null || url.isBlank()) {
            url = "jdbc:mysql://localhost:3306/drowsiness_db";
        }

        if (user == null || user.isBlank()) {
            user = "root";
        }

        if (dbPassword == null || dbPassword.isBlank()) {
            dbPassword = password;
        }

        if (dbPassword == null) {
            throw new SQLException(
                "Database password is not configured."
            );
        }

        return DriverManager.getConnection(
            url, user, dbPassword
        );
    }
}
