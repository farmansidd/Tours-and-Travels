-- SQL command to remove the unnecessary column from otp_store table
ALTER TABLE otp_store DROP COLUMN otp_store;

-- SQL command to create the otp_store table if it does not exist
CREATE TABLE otp_store (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(100) NOT NULL UNIQUE,
    otp VARCHAR(15) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
