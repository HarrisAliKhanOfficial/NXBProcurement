--DROP TABLE IF EXISTS superuser;
DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS request;
DROP TABLE IF EXISTS quotes;
DROP TABLE IF EXISTS items;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS image;
DROP TABLE IF EXISTS forgotpasswords;
DROP TABLE IF EXISTS images;


CREATE TABLE request(
    _id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) ,
    staff_id VARCHAR(255) ,
    created_at TIMESTAMP WITHOUT TIMEZONE_,
    updated_at TIMESTAMP WITHOUT TIMEZONE_,
    status VARCHAR(255),
    order_created BOOLEAN

);

CREATE TABLE user(
    id VARCHAR(255) PRIMARY KEY,
    name TEXT NOT NULL,
    email EMAIL UNIQUE NOT NULL,
    email_verified_at TIMESTAMP WITHOUT TIMEZONE_,
    password TEXT NOT NULL,
    phone VARCHAR(255),
    role_id INT,
    remember_token VARCHAR(255),
    created_at TIMESTAMP WITHOUT TIMEZONE_,
    updated_at TIMESTAMP WITHOUT TIMEZONE_,
    status BOOLEAN,
    is_terminated BOOLEAN,
    is_verified BOOLEAN,
    verification_code VARCHAR(255)

);


CREATE TABLE quotes(
    id VARCHAR(255) PRIMARY KEY,
    path VARCHAR(255),
    status VARCHAR(255),
    request_id VARCHAR(255) ,
    created_at TIMESTAMP WITHOUT TIMEZONE_,
    updated_at TIMESTAMP WITHOUT TIMEZONE_,
    is_pdf VARCHAR(255),
    FOREIGN KEY (request_id) REFERENCES request(_id)

);

CREATE TABLE items(
    id VARCHAR(255) PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    price VARCHAR(255),
    request_id VARCHAR(255) ,
    created_at TIMESTAMP WITHOUT TIMEZONE_,
    updated_at TIMESTAMP WITHOUT TIMEZONE_,
    quantity INTEGER,

    FOREIGN KEY (request_id) REFERENCES request (_id)

);

CREATE TABLE orders(
    id VARCHAR(255) PRIMARY KEY,
    items TEXT,
    total INTEGER,
    path VARCHAR(255),
    request_id VARCHAR(255) ,
    staff_id VARCHAR(255),
    is_sign BOOLEAN,
    created_at TIMESTAMP WITHOUT TIMEZONE_,
    updated_at TIMESTAMP WITHOUT TIMEZONE_,
    is_cash BOOLEAN,
    is_read BOOLEAN,
    comment TEXT,
    FOREIGN KEY (request_id) REFERENCES request (_id)
    FOREIGN KEY (items) REFERENCES items (id)
    FOREIGN KEY (staff_id) REFERENCES user(id)

);



CREATE TABLE roles(
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255),
    created_at TIMESTAMP WITHOUT TIMEZONE_,
    updated_at TIMESTAMP WITHOUT TIMEZONE_
);


CREATE TABLE notifications(
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255),
    type VARCHAR(255),
    notifiable_type VARCHAR(255),
    notifiable_id INTEGER,
    data TEXT,
    read_at TIMESTAMP WITHOUT TIMEZONE_,
    created_at TIMESTAMP WITHOUT TIMEZONE_,
    updated_at TIMESTAMP WITHOUT TIMEZONE_

);


CREATE TABLE images(
    id VARCHAR(255) PRIMARY KEY,
    url VARCHAR(255),
    type VARCHAR(255),
    user_id VARCHAR(255),
    is_pdf VARCHAR(255),
    created_at TIMESTAMP WITHOUT TIMEZONE_,
    updated_at TIMESTAMP WITHOUT TIMEZONE_,
    FOREIGN KEY (user_id) REFERENCES user(id)

);



CREATE TABLE forgotpasswords(
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255),
    email EMAIL UNIQUE NOT NULL,
    email_token VARCHAR(255),
    created_at  TIMESTAMP WITHOUT TIME ZONE,
    updated_at  TIMESTAMP WITHOUT TIME ZONE
);