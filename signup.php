<?php
echo "Signup page loaded!";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Database connection
    $conn = new mysqli("localhost", "root", "", "login");

    if ($conn->connect_error) {
        die("❌ Database connection failed: " . $conn->connect_error);
    }

    // Get form data
    $username = $_POST['username'];
    $email = $_POST['email'];
    $contact = $_POST['number'];
    $password = $_POST['password'];

    // Validate email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        die("❌ Invalid email format!");
    }

    // Check if username or email already exists in `info` table
    $check_stmt = $conn->prepare("SELECT * FROM info WHERE Username = ? OR Email = ?");
    $check_stmt->bind_param("ss", $username, $email);
    $check_stmt->execute();
    $check_stmt->store_result();

    if ($check_stmt->num_rows > 0) {
        die("❌ Username or email already exists!");
    }
    $check_stmt->close();

    // Hash the password
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    // Insert into `info` table
    $insert_stmt = $conn->prepare("INSERT INTO info (Username, Email, Contact, Password) VALUES (?, ?, ?, ?)");
    $insert_stmt->bind_param("ssss", $username, $email, $contact, $hashedPassword);

    if ($insert_stmt->execute()) {
        echo "✅ Signup successful!";

        // header"(Location: landing-page.html");
        exit();
    } else {
        echo "❌ Error inserting data: " . $insert_stmt->error;
    }

    $insert_stmt->close();
    $conn->close();
}
?>
