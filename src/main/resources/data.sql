DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id INT AUTO_INCREMENT  PRIMARY KEY,
  username VARCHAR(250) NOT NULL,
  password VARCHAR(250) NOT NULL,
  status VARCHAR(20) DEFAULT NULL
);

INSERT INTO users (username, password, status) VALUES
  ('admin', '$2y$12$C8wZoGmWD2aO1GpBL4P9sOFVIvcshQ6jneleYlJJ3Cfo81nE9aKi2', 'ACTIVE'),
  ('test_01', '$2y$12$C8wZoGmWD2aO1GpBL4P9sOFVIvcshQ6jneleYlJJ3Cfo81nE9aKi2', 'ACTIVE'),
  ('test_02', '$2y$12$C8wZoGmWD2aO1GpBL4P9sOFVIvcshQ6jneleYlJJ3Cfo81nE9aKi2', 'INACTIVE');