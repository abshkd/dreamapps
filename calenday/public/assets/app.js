document.addEventListener('DOMContentLoaded', () => {
    const registerButton = document.getElementById('register-button');
    const loginButton = document.getElementById('login-button');
    const logoutButton = document.getElementById('logout-button');

    registerButton.addEventListener('click', async () => {
        const username = document.getElementById('username').value;
        if (!username) return alert('Please enter a username.');

        // Step 1: Initiate registration
        const response = await fetch('/api/register/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        const options = await response.json();

        // Step 2: Create credentials with WebAuthn
        const credential = await navigator.credentials.create({ publicKey: options });

        // Step 3: Send credentials to server for verification
        await fetch('/api/register/finish', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, credential: credential.toJSON() })
        });
        alert('Registration successful!');
    });

    loginButton.addEventListener('click', async () => {
        const username = document.getElementById('username-login').value;
        if (!username) return alert('Please enter a username.');

        // Step 1: Initiate login
        const response = await fetch('/api/login/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        const options = await response.json();

        // Step 2: Get assertion with WebAuthn
        const assertion = await navigator.credentials.get({ publicKey: options });

        // Step 3: Send assertion to server for verification
        const loginResponse = await fetch('/api/login/finish', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, assertion: assertion.toJSON() })
        });

        if (loginResponse.ok) {
            alert('Login successful!');
            document.getElementById('auth-container').style.display = 'none';
            document.getElementById('calendar-container').style.display = 'block';
        } else {
            alert('Login failed!');
        }
    });

    logoutButton.addEventListener('click', () => {
        document.getElementById('auth-container').style.display = 'block';
        document.getElementById('calendar-container').style.display = 'none';
    });
});
