<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Self-Hosted Calendar App</title>
    <link rel="stylesheet" href="assets/styles.css">
    <script src="assets/app.js" defer></script>
</head>

<body>
    <h1>Self-Hosted Calendar App</h1>

    <div id="auth-container">
        <h2>Login / Register</h2>
        <form id="register-form">
            <input type="text" id="username" placeholder="Username" required>
            <button type="button" id="register-button">Register with Passkey</button>
        </form>
        <form id="login-form">
            <input type="text" id="username-login" placeholder="Username" required>
            <button type="button" id="login-button">Login with Passkey</button>
        </form>
    </div>

    <div id="calendar-container" style="display: none;">
        <h2>My Calendar</h2>
        <div id="calendar"></div>
        <button id="logout-button">Logout</button>
    </div>
</body>

</html>