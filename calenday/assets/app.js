document.addEventListener('DOMContentLoaded', () => {
    const registerButton = document.getElementById('register-button');
    const loginButton = document.getElementById('login-button');
    const logoutButton = document.getElementById('logout-button');

    // Function to handle both registration and login
    const handleAuth = async (action) => {
        const username = document.getElementById('username').value;
        if (!username) return alert('Please enter a username.');

        try {
            // Step 1: Start authentication (registration or login)
            const startUrl = `/auth.php?action=${action}&step=start`;
            const response = await fetch(startUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username }) // Send data as JSON
            });

            if (!response.ok) {
                const errorData = await response.json();
                console.error(`Server error during ${action}:`, errorData);
                alert(`An error occurred during ${action}.`);
                return;
            }

            const options = await response.json(); // Parse the response as JSON
            console.log(`${action.charAt(0).toUpperCase() + action.slice(1)} options:`, options); // Debugging log

            // Step 2: Create or get credentials with WebAuthn
            let credential;
            if (action === 'register') {
                credential = await navigator.credentials.create({ publicKey: options });
            } else {
                credential = await navigator.credentials.get({ publicKey: options });
            }

            // Step 3: Send credentials to the server for verification
            const finishUrl = `/auth.php?action=${action}&step=finish`;
            const verifyResponse = await fetch(finishUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, credential: credential.toJSON() })
            });

            if (verifyResponse.ok) {
                alert(`${action.charAt(0).toUpperCase() + action.slice(1)} successful!`);
                if (action === 'login') {
                    document.getElementById('auth-container').style.display = 'none';
                    document.getElementById('calendar-container').style.display = 'block';
                }
            } else {
                alert(`Error verifying ${action} credentials.`);
            }
        } catch (error) {
            console.error(`Error during ${action}:`, error); // Debugging log
        }
    };

    // Event listeners for register and login buttons
    registerButton.addEventListener('click', () => handleAuth('register'));
    loginButton.addEventListener('click', () => handleAuth('login'));

    // Logout button to toggle UI
    logoutButton.addEventListener('click', () => {
        document.getElementById('auth-container').style.display = 'block';
        document.getElementById('calendar-container').style.display = 'none';
    });
});
