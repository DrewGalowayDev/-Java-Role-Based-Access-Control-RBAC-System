import org.mindrot.jbcrypt.BCrypt;
import java.sql.*;
import java.util.*;
import java.time.LocalDateTime;

public class RBACSystem {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/rbac_db";
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "SecurePass123!";

    private static User currentUser = null;
    private static Connection connection;

    public static void main(String[] args) {
        try {
            // Initialize database connection
            connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            initializeDatabase();

            Scanner scanner = new Scanner(System.in);

            while (true) {
                if (currentUser == null) {
                    System.out.println("\n=== RBAC System ===");
                    System.out.println("1. Login");
                    System.out.println("2. Exit");
                    System.out.print("Select option: ");

                    int choice = scanner.nextInt();
                    scanner.nextLine(); // Consume newline

                    switch (choice) {
                        case 1:
                            login(scanner);
                            break;
                        case 2:
                            System.out.println("Exiting system...");
                            connection.close();
                            return;
                        default:
                            System.out.println("Invalid option!");
                    }
                } else {
                    showRoleBasedMenu(scanner);
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static void initializeDatabase() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            // Create tables
            stmt.execute("CREATE TABLE IF NOT EXISTS users (" +
                    "id INT AUTO_INCREMENT PRIMARY KEY, " +
                    "username VARCHAR(50) UNIQUE NOT NULL, " +
                    "password VARCHAR(100) NOT NULL, " +
                    "full_name VARCHAR(100) NOT NULL)");

            stmt.execute("CREATE TABLE IF NOT EXISTS roles (" +
                    "id INT AUTO_INCREMENT PRIMARY KEY, " +
                    "name VARCHAR(50) UNIQUE NOT NULL)");

            stmt.execute("CREATE TABLE IF NOT EXISTS permissions (" +
                    "id INT AUTO_INCREMENT PRIMARY KEY, " +
                    "name VARCHAR(50) UNIQUE NOT NULL)");

            stmt.execute("CREATE TABLE IF NOT EXISTS user_roles (" +
                    "user_id INT NOT NULL, " +
                    "role_id INT NOT NULL, " +
                    "PRIMARY KEY (user_id, role_id), " +
                    "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, " +
                    "FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE)");

            stmt.execute("CREATE TABLE IF NOT EXISTS role_permissions (" +
                    "role_id INT NOT NULL, " +
                    "permission_id INT NOT NULL, " +
                    "PRIMARY KEY (role_id, permission_id), " +
                    "FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE, " +
                    "FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE)");

            stmt.execute("CREATE TABLE IF NOT EXISTS audit_logs (" +
                    "id INT AUTO_INCREMENT PRIMARY KEY, " +
                    "user_id INT NOT NULL, " +
                    "action VARCHAR(255) NOT NULL, " +
                    "timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                    "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)");

            // Insert default roles and permissions if not exist
            insertDefaultData();
        }
    }

    private static void insertDefaultData() throws SQLException {
        // Create default roles
        createRoleIfNotExists("Admin", Arrays.asList(
                "USER_CREATE", "USER_READ", "USER_UPDATE", "USER_DELETE",
                "ROLE_CREATE", "ROLE_READ", "ROLE_UPDATE", "ROLE_DELETE",
                "DASHBOARD_VIEW", "DATA_EDIT"));

        createRoleIfNotExists("Editor", Arrays.asList(
                "DASHBOARD_VIEW", "DATA_EDIT", "USER_READ"));

        createRoleIfNotExists("Viewer", Arrays.asList(
                "DASHBOARD_VIEW"));

        // Create admin user if not exists
        if (!userExists("admin")) {
            createUser("admin", "admin123", "System Administrator", "Admin");
        }
    }

    private static void createRoleIfNotExists(String roleName, List<String> permissions) throws SQLException {
        if (!roleExists(roleName)) {
            try (PreparedStatement pstmt = connection.prepareStatement(
                    "INSERT INTO roles (name) VALUES (?)", Statement.RETURN_GENERATED_KEYS)) {
                pstmt.setString(1, roleName);
                pstmt.executeUpdate();

                try (ResultSet rs = pstmt.getGeneratedKeys()) {
                    if (rs.next()) {
                        int roleId = rs.getInt(1);
                        for (String permission : permissions) {
                            int permId = getOrCreatePermission(permission);
                            assignPermissionToRole(roleId, permId);
                        }
                    }
                }
            }
        }
    }

    private static int getOrCreatePermission(String permissionName) throws SQLException {
        try (PreparedStatement pstmt = connection.prepareStatement(
                "SELECT id FROM permissions WHERE name = ?")) {
            pstmt.setString(1, permissionName);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt("id");
                }
            }
        }

        try (PreparedStatement pstmt = connection.prepareStatement(
                "INSERT INTO permissions (name) VALUES (?)", Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, permissionName);
            pstmt.executeUpdate();

            try (ResultSet rs = pstmt.getGeneratedKeys()) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
        }
        return -1;
    }

    private static void assignPermissionToRole(int roleId, int permissionId) throws SQLException {
        try (PreparedStatement pstmt = connection.prepareStatement(
                "INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)")) {
            pstmt.setInt(1, roleId);
            pstmt.setInt(2, permissionId);
            pstmt.executeUpdate();
        }
    }

    private static boolean roleExists(String roleName) throws SQLException {
        try (PreparedStatement pstmt = connection.prepareStatement(
                "SELECT id FROM roles WHERE name = ?")) {
            pstmt.setString(1, roleName);
            try (ResultSet rs = pstmt.executeQuery()) {
                return rs.next();
            }
        }
    }

    private static boolean userExists(String username) throws SQLException {
        try (PreparedStatement pstmt = connection.prepareStatement(
                "SELECT id FROM users WHERE username = ?")) {
            pstmt.setString(1, username);
            try (ResultSet rs = pstmt.executeQuery()) {
                return rs.next();
            }
        }
    }

    private static void login(Scanner scanner) throws SQLException {
        System.out.print("\nUsername: ");
        String username = scanner.nextLine();
        System.out.print("Password: ");
        String password = scanner.nextLine();

        try (PreparedStatement pstmt = connection.prepareStatement(
                "SELECT id, username, password, full_name FROM users WHERE username = ?")) {
            pstmt.setString(1, username);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    String hashedPassword = rs.getString("password");
                    if (BCrypt.checkpw(password, hashedPassword)) {
                        currentUser = new User(
                                rs.getInt("id"),
                                rs.getString("username"),
                                rs.getString("full_name"));
                        logAction(currentUser.getId(), "LOGIN_SUCCESS");
                        System.out.println("\nLogin successful! Welcome " + currentUser.getFullName());
                    } else {
                        System.out.println("Invalid credentials!");
                        logAction(null, "LOGIN_FAILURE: " + username);
                    }
                } else {
                    System.out.println("User not found!");
                }
            }
        }
    }

    private static void showRoleBasedMenu(Scanner scanner) throws SQLException {
        Set<String> permissions = getUserPermissions(currentUser.getId());

        System.out.println("\n=== Dashboard ===");
        System.out.println("User: " + currentUser.getFullName() + " | Permissions: " + permissions);

        // Build menu based on permissions
        List<MenuOption> options = new ArrayList<>();

        if (permissions.contains("DASHBOARD_VIEW")) {
            options.add(new MenuOption("View Dashboard", "DASHBOARD_VIEW"));
        }
        if (permissions.contains("USER_READ")) {
            options.add(new MenuOption("View Users", "USER_READ"));
        }
        if (permissions.contains("USER_CREATE")) {
            options.add(new MenuOption("Create User", "USER_CREATE"));
        }
        if (permissions.contains("ROLE_READ")) {
            options.add(new MenuOption("View Roles", "ROLE_READ"));
        }
        if (permissions.contains("DATA_EDIT")) {
            options.add(new MenuOption("Edit Data", "DATA_EDIT"));
        }
        options.add(new MenuOption("Logout", "LOGOUT"));

        // Display menu
        for (int i = 0; i < options.size(); i++) {
            System.out.println((i + 1) + ". " + options.get(i).getName());
        }
        System.out.print("Select option: ");

        int choice = scanner.nextInt();
        scanner.nextLine(); // Consume newline

        if (choice > 0 && choice <= options.size()) {
            MenuOption selected = options.get(choice - 1);
            if (selected.getPermission().equals("LOGOUT")) {
                logAction(currentUser.getId(), "LOGOUT");
                currentUser = null;
            } else {
                executeMenuAction(selected.getPermission(), scanner);
            }
        } else {
            System.out.println("Invalid option!");
        }
    }

    private static void executeMenuAction(String permission, Scanner scanner) throws SQLException {
        switch (permission) {
            case "DASHBOARD_VIEW":
                System.out.println("\n=== Dashboard ===");
                System.out.println("Welcome to your personalized dashboard!");
                System.out.println("Current time: " + LocalDateTime.now());
                break;

            case "USER_READ":
                viewUsers();
                break;

            case "USER_CREATE":
                createUser(scanner);
                break;

            case "ROLE_READ":
                viewRoles();
                break;

            case "DATA_EDIT":
                System.out.println("\nEditing data... (Simulated action)");
                logAction(currentUser.getId(), "DATA_EDIT");
                System.out.println("Data edited successfully!");
                break;

            default:
                System.out.println("Action not implemented!");
        }
    }

    private static void viewUsers() throws SQLException {
        System.out.println("\n=== User List ===");
        try (PreparedStatement pstmt = connection.prepareStatement(
                "SELECT id, username, full_name FROM users")) {
            try (ResultSet rs = pstmt.executeQuery()) {
                System.out.printf("%-5s %-15s %-20s%n", "ID", "Username", "Full Name");
                System.out.println("---------------------------------");
                while (rs.next()) {
                    System.out.printf("%-5d %-15s %-20s%n",
                            rs.getInt("id"),
                            rs.getString("username"),
                            rs.getString("full_name"));
                }
            }
        }
    }

    private static void createUser(Scanner scanner) throws SQLException {
        System.out.println("\n=== Create New User ===");
        System.out.print("Username: ");
        String username = scanner.nextLine();
        System.out.print("Password: ");
        String password = scanner.nextLine();
        System.out.print("Full Name: ");
        String fullName = scanner.nextLine();
        System.out.print("Role (Admin/Editor/Viewer): ");
        String roleName = scanner.nextLine();

        if (!roleExists(roleName)) {
            System.out.println("Invalid role!");
            return;
        }

        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());

        try (PreparedStatement pstmt = connection.prepareStatement(
                "INSERT INTO users (username, password, full_name) VALUES (?, ?, ?)",
                Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, username);
            pstmt.setString(2, hashedPassword);
            pstmt.setString(3, fullName);
            pstmt.executeUpdate();

            try (ResultSet rs = pstmt.getGeneratedKeys()) {
                if (rs.next()) {
                    int userId = rs.getInt(1);
                    int roleId = getRoleId(roleName);
                    assignRoleToUser(userId, roleId);

                    logAction(currentUser.getId(), "USER_CREATE: " + username);
                    System.out.println("User created successfully!");
                }
            }
        }
    }

    private static void viewRoles() throws SQLException {
        System.out.println("\n=== Role List ===");
        try (PreparedStatement pstmt = connection.prepareStatement(
                "SELECT r.id, r.name, GROUP_CONCAT(p.name SEPARATOR ', ') AS permissions " +
                        "FROM roles r " +
                        "JOIN role_permissions rp ON r.id = rp.role_id " +
                        "JOIN permissions p ON rp.permission_id = p.id " +
                        "GROUP BY r.id")) {
            try (ResultSet rs = pstmt.executeQuery()) {
                System.out.printf("%-5s %-15s %-50s%n", "ID", "Name", "Permissions");
                System.out.println("------------------------------------------------------------");
                while (rs.next()) {
                    System.out.printf("%-5d %-15s %-50s%n",
                            rs.getInt("id"),
                            rs.getString("name"),
                            rs.getString("permissions"));
                }
            }
        }
    }

    private static Set<String> getUserPermissions(int userId) throws SQLException {
        Set<String> permissions = new HashSet<>();
        try (PreparedStatement pstmt = connection.prepareStatement(
                "SELECT p.name " +
                        "FROM permissions p " +
                        "JOIN role_permissions rp ON p.id = rp.permission_id " +
                        "JOIN roles r ON rp.role_id = r.id " +
                        "JOIN user_roles ur ON r.id = ur.role_id " +
                        "WHERE ur.user_id = ?")) {
            pstmt.setInt(1, userId);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    permissions.add(rs.getString("name"));
                }
            }
        }
        return permissions;
    }

    private static int getRoleId(String roleName) throws SQLException {
        try (PreparedStatement pstmt = connection.prepareStatement(
                "SELECT id FROM roles WHERE name = ?")) {
            pstmt.setString(1, roleName);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt("id");
                }
            }
        }
        return -1;
    }

    private static void assignRoleToUser(int userId, int roleId) throws SQLException {
        try (PreparedStatement pstmt = connection.prepareStatement(
                "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)")) {
            pstmt.setInt(1, userId);
            pstmt.setInt(2, roleId);
            pstmt.executeUpdate();
        }
    }

    private static void logAction(Integer userId, String action) throws SQLException {
        String sql = "INSERT INTO audit_logs (user_id, action) VALUES (?, ?)";
        if (userId == null) {
            sql = "INSERT INTO audit_logs (action) VALUES (?)";
        }

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            if (userId != null) {
                pstmt.setInt(1, userId);
                pstmt.setString(2, action);
            } else {
                pstmt.setString(1, action);
            }
            pstmt.executeUpdate();
        }
    }

    // Helper classes
    static class User {
        private int id;
        private String username;
        private String fullName;

        public User(int id, String username, String fullName) {
            this.id = id;
            this.username = username;
            this.fullName = fullName;
        }

        public int getId() {
            return id;
        }

        public String getUsername() {
            return username;
        }

        public String getFullName() {
            return fullName;
        }
    }

    static class MenuOption {
        private String name;
        private String permission;

        public MenuOption(String name, String permission) {
            this.name = name;
            this.permission = permission;
        }

        public String getName() {
            return name;
        }

        public String getPermission() {
            return permission;
        }
    }
}