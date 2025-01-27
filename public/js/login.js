let csrfToken = null;

// Fetch CSRF token when page loads
async function fetchCsrfToken() {
    try {
        const response = await fetch('/csrf-token');
        if (!response.ok) {
            throw new Error('Failed to fetch security token');
        }
        const data = await response.json();
        csrfToken = data.csrfToken;
    } catch (error) {
        console.error('Error fetching CSRF token:', error);
        alert('Error loading page security. Please refresh and try again.');
    }
}

// Fetch token when page loads
document.addEventListener('DOMContentLoaded', fetchCsrfToken);

document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    if (!csrfToken) {
        alert('Page security not ready. Please refresh and try again.');
        return;
    }

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'CSRF-Token': csrfToken
            },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            window.location.href = '/protected/index.html';
        } else {
            throw new Error(data.error || 'Login failed');
        }
    } catch (error) {
        alert(error.message || 'Login failed. Please try again.');
    }
});