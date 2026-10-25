import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

import org.opencv.core.*;
import org.opencv.imgcodecs.Imgcodecs;
import org.opencv.imgproc.Imgproc;
import org.opencv.objdetect.CascadeClassifier;
import org.opencv.objdetect.FaceDetectorYN;

public class ZyraApiServer {

    private static String password;
    private static FaceDetectorYN faceDetector;
    private static CascadeClassifier eyeCascade;

    private static final Map<Integer, Long> lastSaved =
            new ConcurrentHashMap<>();

    private static final String FACE_MODEL =
            "models/face_detection_yunet_2023mar.onnx";

    private static final String EYE_MODEL =
            "models/haarcascade_eye_tree_eyeglasses.xml";

    public static void main(String[] args) throws Exception {

        // Read database password from the hosting environment.
        password = System.getenv("DB_PASSWORD");

        if (password == null) {
            password = "";
        }

        // Verify database connectivity before starting the API.
        try (Connection c = DBConnection.getConnection(password)) {
            System.out.println("MySQL connected successfully.");
        }

        // Initialize OpenCV and detection models.
        nu.pattern.OpenCV.loadLocally();

        faceDetector = FaceDetectorYN.create(
                FACE_MODEL,
                "",
                new Size(320, 320),
                0.60f,
                0.30f,
                5000
        );

        eyeCascade = new CascadeClassifier(EYE_MODEL);

        if (eyeCascade.empty()) {
            throw new IllegalStateException(
                    "Could not load eye model: " + EYE_MODEL
            );
        }

        // Use the hosting platform's assigned port.
        int port = Integer.parseInt(
                System.getenv().getOrDefault("PORT", "8080")
        );

        // Listen on all interfaces for cloud hosting.
        HttpServer server = HttpServer.create(
                new InetSocketAddress("0.0.0.0", port),
                0
        );

        // Health endpoint.
        server.createContext("/api/health", ex -> {
            if (!method(ex, "GET")) {
                return;
            }

            send(ex,
                    "{\"status\":\"online\","
                    + "\"database\":\"connected\","
                    + "\"detector\":\"ready\"}"
            );
        });

        // Register ordinary user accounts. Role is always user.
        server.createContext("/api/auth/register", ex -> {
            if (!method(ex, "POST")) return;

            try {
                String body = readBody(ex);
                String username = stringField(body, "username").trim();
                String userPassword = stringField(body, "password");

                if (!username.matches("[A-Za-z0-9_.-]{3,50}")
                        || userPassword.length() < 12
                        || userPassword.length() > 200) {
                    send(ex, "{\"error\":\"Username must be 3-50 valid characters and password at least 12 characters\"}", 400);
                    return;
                }

                String passwordHash = AuthUtil.hashPassword(userPassword);

                try (Connection c = DBConnection.getConnection(password);
                     PreparedStatement p = c.prepareStatement(
                         "INSERT INTO users (username,password_hash,role) VALUES (?,?,'user')")) {
                    p.setString(1, username);
                    p.setString(2, passwordHash);
                    p.executeUpdate();
                }

                send(ex, "{\"registered\":true,\"message\":\"Account created. Please log in.\"}", 201);
            } catch (SQLIntegrityConstraintViolationException e) {
                send(ex, "{\"error\":\"Username already exists\"}", 409);
            } catch (Exception e) {
                send(ex, "{\"error\":\"Registration failed. Check your details.\"}", 400);
            }
        });

        // Log in and issue a random bearer token.
        server.createContext("/api/auth/login", ex -> {
            if (!method(ex, "POST")) return;

            try {
                String body = readBody(ex);
                String username = stringField(body, "username").trim();
                String userPassword = stringField(body, "password");

                int userId;
                String storedHash;
                String role;

                try (Connection c = DBConnection.getConnection(password);
                     PreparedStatement p = c.prepareStatement(
                         "SELECT user_id,password_hash,role FROM users WHERE username=?")) {
                    p.setString(1, username);

                    try (ResultSet r = p.executeQuery()) {
                        if (!r.next()) {
                            send(ex, "{\"error\":\"Invalid username or password\"}", 401);
                            return;
                        }
                        userId = r.getInt("user_id");
                        storedHash = r.getString("password_hash");
                        role = r.getString("role");
                    }
                }

                if (!AuthUtil.verifyPassword(userPassword, storedHash)) {
                    send(ex, "{\"error\":\"Invalid username or password\"}", 401);
                    return;
                }

                byte[] randomBytes = new byte[32];
                new java.security.SecureRandom().nextBytes(randomBytes);
                String token = java.util.Base64.getUrlEncoder()
                    .withoutPadding().encodeToString(randomBytes);

                String tokenHash = tokenHash(token);

                try (Connection c = DBConnection.getConnection(password);
                     PreparedStatement p = c.prepareStatement(
                         "INSERT INTO auth_tokens (user_id,token_hash,expires_at) "
                         + "VALUES (?, ?, DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 12 HOUR))")) {
                    p.setInt(1, userId);
                    p.setString(2, tokenHash);
                    p.executeUpdate();
                }

                send(ex, "{\"token\":" + quote(token)
                    + ",\"userId\":" + userId
                    + ",\"username\":" + quote(username)
                    + ",\"role\":" + quote(role)
                    + ",\"expiresInSeconds\":43200}");
            } catch (Exception e) {
                e.printStackTrace();
                send(ex, "{\"error\":\"Login failed\"}", 500);
            }
        });
        // Dashboard statistics.
        server.createContext("/api/dashboard", ex -> {

            if (!method(ex, "GET")) {
                return;
            }

            AuthenticatedUser currentUser = authenticate(ex);
            if (currentUser == null) {
                send(ex, "{\"error\":\"Authentication required\"}", 401);
                return;
            }

            String sql =
                    "SELECT "
                    + "(SELECT COUNT(*) FROM drivers) drivers,"
                    + "(SELECT COUNT(*) FROM monitoring_sessions) sessions,"
                    + "(SELECT COUNT(*) FROM observations) observations,"
                    + "(SELECT COUNT(*) FROM fatigue_assessments) assessments,"
                    + "(SELECT COUNT(*) FROM alerts) alerts,"
                    + "(SELECT COUNT(*) FROM monitoring_sessions "
                    + "WHERE session_status='active') active_sessions";

            // DASHBOARD_OWNER_FILTER_ADDED
            if (!currentUser.isAdmin()) {
                int uid = currentUser.userId;
                sql = "SELECT "
                    + "(SELECT COUNT(*) FROM drivers WHERE owner_user_id=" + uid + ") drivers,"
                    + "(SELECT COUNT(*) FROM monitoring_sessions s JOIN drivers d ON d.driver_id=s.driver_id WHERE d.owner_user_id=" + uid + ") sessions,"
                    + "(SELECT COUNT(*) FROM observations o JOIN monitoring_sessions s ON s.session_id=o.session_id JOIN drivers d ON d.driver_id=s.driver_id WHERE d.owner_user_id=" + uid + ") observations,"
                    + "(SELECT COUNT(*) FROM fatigue_assessments a JOIN monitoring_sessions s ON s.session_id=a.session_id JOIN drivers d ON d.driver_id=s.driver_id WHERE d.owner_user_id=" + uid + ") assessments,"
                    + "(SELECT COUNT(*) FROM alerts a JOIN monitoring_sessions s ON s.session_id=a.session_id JOIN drivers d ON d.driver_id=s.driver_id WHERE d.owner_user_id=" + uid + ") alerts,"
                    + "(SELECT COUNT(*) FROM monitoring_sessions s JOIN drivers d ON d.driver_id=s.driver_id WHERE d.owner_user_id=" + uid + " AND s.session_status='active') active_sessions";
            }
            try (
                    Connection c = DBConnection.getConnection(password);
                    Statement s = c.createStatement();
                    ResultSet r = s.executeQuery(sql)
            ) {
                r.next();

                send(ex,
                        "{\"drivers\":" + r.getLong("drivers")
                        + ",\"sessions\":" + r.getLong("sessions")
                        + ",\"observations\":" + r.getLong("observations")
                        + ",\"assessments\":" + r.getLong("assessments")
                        + ",\"alerts\":" + r.getLong("alerts")
                        + ",\"activeSessions\":"
                        + r.getLong("active_sessions") + "}"
                );

            } catch (Exception e) {
                e.printStackTrace();
                send(ex, "{\"error\":\"Database query failed\"}", 500);
            }
        });

        // Database records.
        server.createContext("/api/data/", ex -> {

            if (!method(ex, "GET")) {
                return;
            }

            AuthenticatedUser currentUser = authenticate(ex);
            if (currentUser == null) {
                send(ex, "{\"error\":\"Authentication required\"}", 401);
                return;
            }

            String category = ex.getRequestURI()
                    .getPath()
                    .substring("/api/data/".length());

            String sql;

            switch (category) {
                case "drivers":
                    sql = "SELECT * FROM drivers ORDER BY driver_id DESC LIMIT 200";
                    break;

                case "sessions":
                    sql = "SELECT * FROM monitoring_sessions ORDER BY session_id DESC LIMIT 200";
                    break;

                case "observations":
                    sql = "SELECT * FROM observations ORDER BY observation_id DESC LIMIT 200";
                    break;

                case "assessments":
                    sql = "SELECT * FROM fatigue_assessments ORDER BY assessment_id DESC LIMIT 200";
                    break;

                case "alerts":
                    sql = "SELECT * FROM alerts ORDER BY alert_id DESC LIMIT 200";
                    break;

                case "reports":
                    sql = "SELECT * FROM session_reports ORDER BY report_id DESC LIMIT 200";
                    break;

                case "events":
                    sql = "SELECT * FROM monitoring_events ORDER BY event_id DESC LIMIT 100";
                    break;

                default:
                    send(ex, "{\"error\":\"Unknown category\"}", 404);
                    return;
            }

            // OWNER_FILTERS_ADDED: restrict ordinary users to their own drivers.
            if (!currentUser.isAdmin()) {
                int uid = currentUser.userId;

                switch (category) {
                    case "drivers":
                        sql = "SELECT d.* FROM drivers d WHERE d.owner_user_id=" + uid
                            + " ORDER BY d.driver_id DESC LIMIT 200";
                        break;

                    case "sessions":
                        sql = "SELECT s.* FROM monitoring_sessions s JOIN drivers d "
                            + "ON d.driver_id=s.driver_id WHERE d.owner_user_id=" + uid
                            + " ORDER BY s.session_id DESC LIMIT 200";
                        break;

                    case "observations":
                        sql = "SELECT o.* FROM observations o JOIN monitoring_sessions s "
                            + "ON s.session_id=o.session_id JOIN drivers d "
                            + "ON d.driver_id=s.driver_id WHERE d.owner_user_id=" + uid
                            + " ORDER BY o.observation_id DESC LIMIT 200";
                        break;

                    case "assessments":
                        sql = "SELECT a.* FROM fatigue_assessments a JOIN monitoring_sessions s "
                            + "ON s.session_id=a.session_id JOIN drivers d "
                            + "ON d.driver_id=s.driver_id WHERE d.owner_user_id=" + uid
                            + " ORDER BY a.assessment_id DESC LIMIT 200";
                        break;

                    case "alerts":
                        sql = "SELECT a.* FROM alerts a JOIN monitoring_sessions s "
                            + "ON s.session_id=a.session_id JOIN drivers d "
                            + "ON d.driver_id=s.driver_id WHERE d.owner_user_id=" + uid
                            + " ORDER BY a.alert_id DESC LIMIT 200";
                        break;

                    case "reports":
                        sql = "SELECT r.* FROM session_reports r JOIN monitoring_sessions s "
                            + "ON s.session_id=r.session_id JOIN drivers d "
                            + "ON d.driver_id=s.driver_id WHERE d.owner_user_id=" + uid
                            + " ORDER BY r.report_id DESC LIMIT 200";
                        break;

                    case "events":
                        sql = "SELECT e.* FROM monitoring_events e JOIN monitoring_sessions s "
                            + "ON s.session_id=e.session_id JOIN drivers d "
                            + "ON d.driver_id=s.driver_id WHERE d.owner_user_id=" + uid
                            + " ORDER BY e.event_id DESC LIMIT 100";
                        break;
                }
            }
            try (
                    Connection c = DBConnection.getConnection(password);
                    Statement st = c.createStatement();
                    ResultSet r = st.executeQuery(sql)
            ) {
                ResultSetMetaData md = r.getMetaData();
                StringBuilder b = new StringBuilder("[");
                int cols = md.getColumnCount();

                while (r.next()) {

                    if (b.length() > 1) {
                        b.append(',');
                    }

                    b.append('{');

                    for (int i = 1; i <= cols; i++) {

                        if (i > 1) {
                            b.append(',');
                        }

                        b.append(quote(md.getColumnLabel(i))).append(':');

                        Object v = r.getObject(i);

                        if (v == null) {
                            b.append("null");
                        } else if (v instanceof Number || v instanceof Boolean) {
                            b.append(v);
                        } else {
                            b.append(quote(v.toString()));
                        }
                    }

                    b.append('}');
                }

                b.append(']');
                send(ex, b.toString());

            } catch (Exception e) {
                e.printStackTrace();
                send(ex, "{\"error\":\"Database query failed\"}", 500);
            }
        });

        // Start a monitoring session.
        server.createContext("/api/session/start", ex -> {

            if (!method(ex, "POST")) {
                return;
            }

            AuthenticatedUser currentUser = authenticate(ex);
            if (currentUser == null) {
                send(ex, "{\"error\":\"Authentication required\"}", 401);
                return;
            }

            try {
                String body = readBody(ex);
                int driverId = intField(body, "driverId");

                if (!currentUser.isAdmin()) {
                    try (Connection check = DBConnection.getConnection(password);
                         PreparedStatement ownerCheck = check.prepareStatement(
                             "SELECT 1 FROM drivers WHERE driver_id=? AND owner_user_id=?")) {
                        ownerCheck.setInt(1, driverId);
                        ownerCheck.setInt(2, currentUser.userId);

                        try (ResultSet result = ownerCheck.executeQuery()) {
                            if (!result.next()) {
                                send(ex, "{\"error\":\"Driver not found or access denied\"}", 403);
                                return;
                            }
                        }
                    }
                }

                try (
                        Connection c = DBConnection.getConnection(password);
                        PreparedStatement p = c.prepareStatement(
                                "INSERT INTO monitoring_sessions "
                                + "(driver_id,session_status) "
                                + "VALUES (?, 'active')",
                                Statement.RETURN_GENERATED_KEYS
                        )
                ) {
                    p.setInt(1, driverId);
                    p.executeUpdate();

                    try (ResultSet k = p.getGeneratedKeys()) {
                        if (!k.next()) {
                            throw new SQLException("Could not create session");
                        }

                        int id = k.getInt(1);

                        send(ex,
                                "{\"sessionId\":" + id
                                + ",\"driverId\":" + driverId
                                + ",\"status\":\"active\"}"
                        );
                    }
                }

            } catch (Exception e) {
                send(ex,
                        "{\"error\":"
                        + quote(e.getMessage() == null
                                ? "Could not start session"
                                : e.getMessage())
                        + "}",
                        400
                );
            }
        });

        // Stop a monitoring session.
        server.createContext("/api/session/stop", ex -> {

            if (!method(ex, "POST")) {
                return;
            }

            // Session-stop ownership check
            AuthenticatedUser currentUser = authenticate(ex);
            if (currentUser == null) {
                send(ex, "{\"error\":\"Authentication required\"}", 401);
                return;
            }

            try {
                int id = intField(readBody(ex), "sessionId");

                if (!currentUser.isAdmin()) {
                    try (Connection check = DBConnection.getConnection(password);
                         PreparedStatement ownerCheck = check.prepareStatement(
                             "SELECT 1 FROM monitoring_sessions s "
                             + "JOIN drivers d ON d.driver_id=s.driver_id "
                             + "WHERE s.session_id=? AND d.owner_user_id=?")) {
                        ownerCheck.setInt(1, id);
                        ownerCheck.setInt(2, currentUser.userId);

                        try (ResultSet result = ownerCheck.executeQuery()) {
                            if (!result.next()) {
                                send(ex, "{\"error\":\"Session not found or access denied\"}", 403);
                                return;
                            }
                        }
                    }
                }

                try (
                        Connection c = DBConnection.getConnection(password);
                        PreparedStatement p = c.prepareStatement(
                                "UPDATE monitoring_sessions "
                                + "SET session_status='completed', "
                                + "end_time=CURRENT_TIMESTAMP "
                                + "WHERE session_id=? "
                                + "AND session_status='active'"
                        )
                ) {
                    p.setInt(1, id);

                    int n = p.executeUpdate();

                    if (n == 0) {
                        send(ex, "{\"error\":\"Active session not found\"}", 404);
                        return;
                    }

                    lastSaved.remove(id);

                    send(ex,
                            "{\"sessionId\":" + id
                            + ",\"status\":\"completed\"}"
                    );
                }

            } catch (Exception e) {
                send(ex, "{\"error\":\"Could not stop session\"}", 400);
            }
        });

        // Webcam frame and eye-detection endpoint.
        server.createContext("/api/detect", ex -> {

            if (!method(ex, "POST")) {
                return;
            }

            // Webcam ownership check
            AuthenticatedUser currentUser = authenticate(ex);
            if (currentUser == null) {
                send(ex, "{\"error\":\"Authentication required\"}", 401);
                return;
            }

            Mat image = null;
            Mat gray = null;
            Mat faces = null;
            Mat upper = null;
            MatOfByte imageBytes = null;
            MatOfRect eyeRects = null;

            try {
                String body = readBody(ex);

                int sessionId = intField(body, "sessionId");

                if (!currentUser.isAdmin()) {
                    try (Connection check = DBConnection.getConnection(password);
                         PreparedStatement ownerCheck = check.prepareStatement(
                             "SELECT 1 FROM monitoring_sessions s "
                             + "JOIN drivers d ON d.driver_id=s.driver_id "
                             + "WHERE s.session_id=? AND d.owner_user_id=? "
                             + "AND s.session_status='active'")) {
                        ownerCheck.setInt(1, sessionId);
                        ownerCheck.setInt(2, currentUser.userId);

                        try (ResultSet result = ownerCheck.executeQuery()) {
                            if (!result.next()) {
                                send(ex, "{\"error\":\"Active session not found or access denied\"}", 403);
                                return;
                            }
                        }
                    }
                }

                String encoded = stringField(body, "image");

                int comma = encoded.indexOf(',');

                byte[] bytes = Base64.getDecoder().decode(
                        encoded.substring(comma >= 0 ? comma + 1 : 0)
                );

                imageBytes = new MatOfByte(bytes);

                image = Imgcodecs.imdecode(
                        imageBytes,
                        Imgcodecs.IMREAD_COLOR
                );

                if (image.empty()) {
                    throw new IllegalArgumentException(
                            "Invalid webcam frame"
                    );
                }

                gray = new Mat();

                Imgproc.cvtColor(
                        image,
                        gray,
                        Imgproc.COLOR_BGR2GRAY
                );

                Imgproc.equalizeHist(gray, gray);

                faces = new Mat();

                faceDetector.setInputSize(
                        new Size(image.cols(), image.rows())
                );

                faceDetector.detect(image, faces);

                boolean face = faces.rows() > 0 && faces.cols() >= 15;
                boolean left = false;
                boolean right = false;

                String status = "NO FACE DETECTED";

                if (face) {

                    float[] f = new float[faces.cols()];
                    faces.get(0, 0, f);

                    int fx = clamp(
                            Math.round(f[0]),
                            0,
                            image.cols() - 1
                    );

                    int fy = clamp(
                            Math.round(f[1]),
                            0,
                            image.rows() - 1
                    );

                    int fw = clamp(
                            Math.round(f[2]),
                            1,
                            image.cols() - fx
                    );

                    int fh = clamp(
                            Math.round(f[3]),
                            1,
                            image.rows() - fy
                    );

                    int rh = Math.max(
                            1,
                            Math.min(fh, Math.round(fh * 0.62f))
                    );

                    upper = new Mat(gray, new Rect(fx, fy, fw, rh));
                    eyeRects = new MatOfRect();

                    eyeCascade.detectMultiScale(
                            upper,
                            eyeRects,
                            1.08,
                            3,
                            0,
                            new Size(18, 14),
                            new Size(
                                    Math.max(24, fw / 3),
                                    Math.max(18, fh / 4)
                            )
                    );

                    Rect[] eyes = eyeRects.toArray();

                    int[] lx = {
                            Math.round(f[4]),
                            Math.round(f[6])
                    };

                    int[] ly = {
                            Math.round(f[5]),
                            Math.round(f[7])
                    };

                    boolean[] detected = new boolean[2];

                    for (int i = 0; i < 2; i++) {
                        for (Rect e : eyes) {

                            double cx = fx + e.x + e.width / 2.0;
                            double cy = fy + e.y + e.height / 2.0;

                            double dx = (cx - lx[i]) / Math.max(1, fw * 0.18);
                            double dy = (cy - ly[i]) / Math.max(1, fh * 0.15);

                            if (dx * dx + dy * dy <= 1.0) {
                                detected[i] = true;
                                break;
                            }
                        }
                    }

                    left = detected[0];
                    right = detected[1];

                    status = (left || right)
                            ? "FACE DETECTED - EYE(S) DETECTED"
                            : "WARNING: EYES NOT DETECTED";
                }

                long now = System.currentTimeMillis();

                if (now - lastSaved.getOrDefault(sessionId, 0L) >= 2000) {

                    try (
                            Connection c = DBConnection.getConnection(password);
                            PreparedStatement p = c.prepareStatement(
                                    "INSERT INTO monitoring_events "
                                    + "(session_id,face_detected,left_eye_detected,"
                                    + "right_eye_detected,status_message) "
                                    + "SELECT ?,?,?,?,? "
                                    + "WHERE EXISTS ("
                                    + "SELECT 1 FROM monitoring_sessions "
                                    + "WHERE session_id=? AND session_status='active')"
                            )
                    ) {
                        p.setInt(1, sessionId);
                        p.setBoolean(2, face);
                        p.setBoolean(3, left);
                        p.setBoolean(4, right);
                        p.setString(5, status);
                        p.setInt(6, sessionId);

                        p.executeUpdate();
                        lastSaved.put(sessionId, now);
                    }
                }

                send(ex,
                        "{\"sessionId\":" + sessionId
                        + ",\"faceDetected\":" + face
                        + ",\"leftEyeDetected\":" + left
                        + ",\"rightEyeDetected\":" + right
                        + ",\"status\":" + quote(status)
                        + "}"
                );

            } catch (Exception e) {
                e.printStackTrace();

                send(ex,
                        "{\"error\":"
                        + quote(e.getMessage() == null
                                ? "Detection failed"
                                : e.getMessage())
                        + "}",
                        400
                );

            } finally {
                if (image != null) image.release();
                if (gray != null) gray.release();
                if (faces != null) faces.release();
                if (upper != null) upper.release();
                if (imageBytes != null) imageBytes.release();
                if (eyeRects != null) eyeRects.release();
            }
        });

        server.setExecutor(Executors.newFixedThreadPool(6));
        server.start();

        System.out.println("ZYRA API running on port " + port);
    }

    private static String tokenHash(String token) throws Exception {
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
            .digest(token.getBytes(StandardCharsets.UTF_8));
        StringBuilder result = new StringBuilder();
        for (byte b : digest) result.append(String.format("%02x", b & 0xff));
        return result.toString();
    }
    private static class AuthenticatedUser {
        final int userId;
        final String username;
        final String role;

        AuthenticatedUser(int userId, String username, String role) {
            this.userId = userId;
            this.username = username;
            this.role = role;
        }

        boolean isAdmin() {
            return "admin".equals(role);
        }
    }

    private static AuthenticatedUser authenticate(HttpExchange ex) {
        try {
            String header = ex.getRequestHeaders().getFirst("Authorization");

            if (header == null || !header.startsWith("Bearer ")) {
                return null;
            }

            String token = header.substring(7).trim();
            if (token.isEmpty() || token.length() > 200) return null;

            String hash = tokenHash(token);

            try (Connection c = DBConnection.getConnection(password);
                 PreparedStatement p = c.prepareStatement(
                     "SELECT u.user_id, u.username, u.role "
                     + "FROM auth_tokens t JOIN users u ON u.user_id=t.user_id "
                     + "WHERE t.token_hash=? AND t.expires_at>CURRENT_TIMESTAMP")) {

                p.setString(1, hash);

                try (ResultSet r = p.executeQuery()) {
                    if (!r.next()) return null;

                    return new AuthenticatedUser(
                        r.getInt("user_id"),
                        r.getString("username"),
                        r.getString("role")
                    );
                }
            }
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean requireAuth(HttpExchange ex) throws IOException {
        if (authenticate(ex) != null) return true;

        send(ex, "{\"error\":\"Authentication required. Please log in.\"}", 401);
        return false;
    }
    private static int clamp(int v, int lo, int hi) {
        return Math.max(lo, Math.min(v, hi));
    }

    private static int intField(String json, String key) {
        Matcher m = Pattern.compile(
                "\"" + Pattern.quote(key) + "\"\\s*:\\s*(\\d+)"
        ).matcher(json);

        if (!m.find()) {
            throw new IllegalArgumentException(
                    "Missing numeric field: " + key
            );
        }

        return Integer.parseInt(m.group(1));
    }

    private static String stringField(String json, String key) {
        Matcher m = Pattern.compile(
                "\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]*)\""
        ).matcher(json);

        if (!m.find()) {
            throw new IllegalArgumentException(
                    "Missing field: " + key
            );
        }

        return m.group(1);
    }

    private static String readBody(HttpExchange ex) throws IOException {
        return new String(
                ex.getRequestBody().readAllBytes(),
                StandardCharsets.UTF_8
        );
    }

    private static boolean method(
            HttpExchange ex,
            String wanted
    ) throws IOException {

        cors(ex);

        if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
            ex.getResponseHeaders().set(
                    "Access-Control-Allow-Methods",
                    "GET, POST, OPTIONS"
            );

            ex.getResponseHeaders().set(
                    "Access-Control-Allow-Headers",
                    "Content-Type, Authorization"
            );

            ex.sendResponseHeaders(204, -1);
            ex.close();

            return false;
        }

        if (!wanted.equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, "{\"error\":\"Method not allowed\"}", 405);
            return false;
        }

        return true;
    }

    private static void cors(HttpExchange ex) {
        ex.getResponseHeaders().set(
                "Access-Control-Allow-Origin",
                "https://hilarious-douhua-91d05d.netlify.app"
        );

        ex.getResponseHeaders().set(
                "Access-Control-Allow-Headers",
                "Content-Type, Authorization"
        );

        ex.getResponseHeaders().set(
                "Access-Control-Allow-Methods",
                "GET, POST, OPTIONS"
        );
    }

    private static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");

        for (char c : s.toCharArray()) {
            switch (c) {
                case '"':
                    b.append("\\\"");
                    break;

                case '\\':
                    b.append("\\\\");
                    break;

                case '\n':
                    b.append("\\n");
                    break;

                case '\r':
                    b.append("\\r");
                    break;

                case '\t':
                    b.append("\\t");
                    break;

                default:
                    if (c < 32) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }

        return b.append('"').toString();
    }

    private static void send(
            HttpExchange ex,
            String body
    ) throws IOException {
        send(ex, body, 200);
    }

    private static void send(
            HttpExchange ex,
            String body,
            int code
    ) throws IOException {

        cors(ex);

        ex.getResponseHeaders().set(
                "Content-Type",
                "application/json; charset=UTF-8"
        );

        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);

        ex.sendResponseHeaders(code, bytes.length);

        try (OutputStream out = ex.getResponseBody()) {
            out.write(bytes);
        }
    }
}
