const express = require("express");
const crypt = require("crypto")
const mysql = require("mysql2")

const app = express();

// Allows the server to read data submitted by HTML forms
app.use(express.urlencoded({ extended: true }));
// Allows users to access HTML files inside the public folder
app.use(express.static("public"));

// Gets the MySQL root password from the environment
const pass = process.env.ROOTPASS
// Connects to the paws database
const conn = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: pass,
    database: "paws",
    port: 3306
})

// Sets the password hashing settings
const hashRounds = 100;
const hashLength=64;
const salt = "salt";

// Connects to MySQL
conn.connect(function(err) {
    if(err)
		console.log("Couldnt connect to MySQL",err);
	else
		console.log("Database connection established");
});

// Registration form
app.post("/register", function(req, res) {
    // Gets the values submitted by the form
    let username = req.body.username;
    let email = req.body.email;
    let plainPass = req.body.password;

    // Hashes the password before saving it
    let hashedPass = crypt.pbkdf2Sync(
        plainPass,salt, hashRounds, hashLength, 'sha512'
    ).toString(`hex`);

    // Creates a query to insert the new user into the database
    let sql = "INSERT INTO `user` (username, email, password) VALUES (?, ?, ?)";

    // Executes the query using the submitted values
    conn.query(sql, [username, email, hashedPass], function(err, result) {
        if (err) {
            console.log("Error registering user", err);
            res.send("Registration failed");
        } else {
            res.send(
                'You have successfully registered. <a href="login.html">Login here</a>'
            );
        }
    });
});

// Login form
app.post("/login", function(req, res) {
    // Gets the values submitted by the form
    let username = req.body.username;
    let plainPass = req.body.password;

    // Hashes the submitted password using the same settings
    let hashedPass = crypt.pbkdf2Sync(
        plainPass,salt, hashRounds, hashLength, 'sha512'
    ).toString(`hex`);

    // Searches for a user with the matching username and password
    let sql = "SELECT * FROM `user` WHERE username = ? AND password = ?";

    // Executes the query
    conn.query(sql, [username, hashedPass], function(err, result) {
        if (err) {
            console.log("Error checking login", err);
            res.send("Login failed");
        } else if (result.length === 0) {
            // Displays an error if no matching account is found
            res.send(
                'The login credentials were incorrect. <a href="login.html">Try again</a>'
            );
        } else {
            res.send("You have logged in successfully");
        }
    });
});

app.listen(3000, function() {
    console.log("Server running at http://localhost:3000");
});