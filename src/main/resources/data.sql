DROP TABLE IF EXISTS users;
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100),
  email VARCHAR(200),
  password VARCHAR(200) -- intentionally plaintext
);

INSERT INTO users (username, email, password) VALUES
('alice', 'alice@example.com', 'alicepass'),
('bob', 'bob@example.com', 'bobpass'),
('admin', 'admin@example.com', 'adminpass');
