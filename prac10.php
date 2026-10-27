
<?php
session_start();

$conn = new mysqli("localhost", "root", "", "studenthub");

if ($conn->connect_error) {
    die("Database connection failed.");
}

$conn->set_charset("utf8mb4");

$error = "";
$timeout = 1800; // 30 minutes

// Check session timeout
if (isset($_SESSION["user_id"])) {
    if (isset($_SESSION["last_activity"]) &&
        time() - $_SESSION["last_activity"] > $timeout) {

        session_unset();
        session_destroy();

        header("Location: prac10.php?timeout=1");
        exit;
    }

    $_SESSION["last_activity"] = time();
}

// Remember-me authentication
if (!isset($_SESSION["user_id"]) &&
    isset($_COOKIE["remember_token"])) {

    $token = $_COOKIE["remember_token"];

    if (preg_match('/^[a-f0-9]{64}$/', $token)) {
        $tokenHash = hash("sha256", $token);

        $stmt = $conn->prepare(
            "SELECT user_id, username, role
             FROM users
             WHERE remember_token_hash = ?
             AND remember_token_expiry > NOW()"
        );

        $stmt->bind_param("s", $tokenHash);
        $stmt->execute();
        $stmt->bind_result($id, $name, $role);

        if ($stmt->fetch()) {
            session_regenerate_id(true);

            $_SESSION["user_id"] = $id;
            $_SESSION["username"] = $name;
            $_SESSION["role"] = $role;
            $_SESSION["last_activity"] = time();
        }

        $stmt->close();
    }
}

// Login processing
if ($_SERVER["REQUEST_METHOD"] === "POST" &&
    isset($_POST["login"])) {

    $email = trim($_POST["email"] ?? "");
    $password = $_POST["password"] ?? "";

    $stmt = $conn->prepare(
        "SELECT user_id, username, password_hash, role
         FROM users WHERE email = ?"
    );

    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->bind_result($id, $name, $passwordHash, $role);

    if ($stmt->fetch() &&
        password_verify($password, $passwordHash)) {

        $stmt->close();

        session_regenerate_id(true);

        $_SESSION["user_id"] = $id;
        $_SESSION["username"] = $name;
        $_SESSION["role"] = $role;
        $_SESSION["last_activity"] = time();

        // Remember me for 7 days
        if (isset($_POST["remember"])) {
            $token = bin2hex(random_bytes(32));
            $tokenHash = hash("sha256", $token);

            $expiry = date(
                "Y-m-d H:i:s",
                time() + (7 * 24 * 60 * 60)
            );

            $save = $conn->prepare(
                "UPDATE users
                 SET remember_token_hash = ?,
                     remember_token_expiry = ?
                 WHERE user_id = ?"
            );

            $save->bind_param("ssi", $tokenHash, $expiry, $id);
            $save->execute();
            $save->close();

            setcookie("remember_token", $token, [
                "expires" => time() + (7 * 24 * 60 * 60),
                "path" => "/php_practicals/",
                "httponly" => true,
                "samesite" => "Lax"
            ]);
        }

        header("Location: prac10.php");
        exit;

    } else {
        $stmt->close();
        $error = "Invalid email or password.";
    }
}

// Logout processing
if (isset($_GET["logout"])) {

    if (isset($_SESSION["user_id"])) {
        $id = $_SESSION["user_id"];

        $stmt = $conn->prepare(
            "UPDATE users
             SET remember_token_hash = NULL,
                 remember_token_expiry = NULL
             WHERE user_id = ?"
        );

        $stmt->bind_param("i", $id);
        $stmt->execute();
        $stmt->close();
    }

    setcookie("remember_token", "", [
        "expires" => time() - 3600,
        "path" => "/php_practicals/",
        "httponly" => true,
        "samesite" => "Lax"
    ]);

    $_SESSION = [];
    session_destroy();

    header("Location: prac10.php?loggedout=1");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>Practical 10 - Secure Login</title>

    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f2f4f8;
            padding: 30px 15px;
        }

        .container {
            max-width: 430px;
            margin: auto;
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px #ccc;
        }

        h2 {
            text-align: center;
            color: #243b55;
        }

        label {
            display: block;
            margin-top: 15px;
            font-weight: bold;
        }

        input[type="email"],
        input[type="password"] {
            box-sizing: border-box;
            width: 100%;
            padding: 10px;
            margin-top: 6px;
        }

        button, .logout {
            display: inline-block;
            box-sizing: border-box;
            width: 100%;
            padding: 12px;
            margin-top: 20px;
            background: #2457a7;
            color: white;
            border: none;
            text-align: center;
            text-decoration: none;
            cursor: pointer;
        }

        .message {
            padding: 12px;
            background: #ffe0e0;
            color: #a00000;
            margin-bottom: 15px;
        }

        .success {
            padding: 12px;
            background: #d8f3dc;
            color: #176b35;
        }
    </style>
</head>

<body>
<div class="container">

<?php if (isset($_SESSION["user_id"])): ?>

    <h2>Dashboard</h2>

    <p>
        Welcome,
        <strong><?php echo htmlspecialchars($_SESSION["username"]); ?></strong>
    </p>

    <p>
        Your role:
        <strong><?php echo htmlspecialchars($_SESSION["role"]); ?></strong>
    </p>

    <?php if ($_SESSION["role"] === "admin"): ?>

        <h3>Admin Panel</h3>
        <p>You have administrator access.</p>
        <p>You can manage administrative functions.</p>

    <?php elseif ($_SESSION["role"] === "student"): ?>

        <h3>Student Dashboard</h3>
        <p>You have student access.</p>
        <p>You can view student dashboard information.</p>

    <?php else: ?>

        <p>Access denied: Unknown user role.</p>

    <?php endif; ?>

    <p>Inactive sessions expire after 30 minutes.</p>

    <a class="logout" href="prac10.php?logout=1">
        Logout
    </a>

<?php else: ?>

    <h2>User Login</h2>

    <?php if ($error !== ""): ?>
        <div class="message">
            <?php echo htmlspecialchars($error); ?>
        </div>
    <?php endif; ?>

    <?php if (isset($_GET["timeout"])): ?>
        <div class="message">
            Session expired. Please log in again.
        </div>
    <?php endif; ?>

    <?php if (isset($_GET["loggedout"])): ?>
        <div class="success">
            You have logged out successfully.
        </div>
    <?php endif; ?>

    <form method="POST" action="prac10.php">

        <label for="email">Email</label>
        <input type="email" id="email" name="email" required>

        <label for="password">Password</label>
        <input type="password" id="password"
               name="password" required>

        <p>
            <label>
                <input type="checkbox" name="remember" value="1">
                Remember Me for 7 days
            </label>
        </p>

        <button type="submit" name="login">Login</button>

    </form>

<?php endif; ?>

</div>
</body>
</html>

<?php
$conn->close();
?>
