CREATE DATABASE IF NOT EXISTS rbac_db;
USE rbac_db;

-- Create admin user with necessary privileges
CREATE USER 'admin'@'localhost' IDENTIFIED BY 'SecurePass123!';
GRANT ALL PRIVILEGES ON rbac_db.* TO 'admin'@'localhost';
FLUSH PRIVILEGES;