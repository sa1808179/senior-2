// static\JS\script.js
setTimeout(() => {
    const alerts = document.getElementsByClassName('message');
    
    for (let i = 0; i < alerts.length; i++) {
        alerts[i].innerHTML = ''; // Clear the content of the alert
    }
    console.log('Flash messages cleared');
}, 10000);

async function logout() {
    const url = '/logout'; // The logout API endpoint
    try {
        const response = await fetch(url, { method: 'GET', credentials: 'include' });

        if (response.redirected) {
            // If the server redirects, follow the redirect
            window.location.href = response.url;
        } else {
            console.error("Unexpected response during logout:", response);
        }
    } catch (error) {
        console.error("Error during logout:", error);
        alert("Failed to log out. Please try again.");
    }
}
