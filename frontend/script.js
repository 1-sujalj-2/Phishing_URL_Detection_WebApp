// Get the HTML elements we need
const urlForm = document.getElementById('url-form');
const urlInput = document.getElementById('url-input');
const resultDisplay = document.getElementById('result-display');

// Listen for when the user submits the form
urlForm.addEventListener('submit', async (event) => {
    // Stop the form from causing a page reload
    event.preventDefault();

    const url = urlInput.value;
    
    // Show a "loading" message
    resultDisplay.innerHTML = '<div class="alert alert-info">Analyzing...</div>';

    try {
        // Send the URL to your FastAPI backend
        const response = await fetch('http://127.0.0.1:8000/url/detect', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url }),
        });

        const data = await response.json();
        const result = data.Output; // "Phishing" or "Legitimate"

        // Create a styled alert based on the result
        if (result === 'Phishing') {
            resultDisplay.innerHTML = '<div class="alert alert-danger"><strong>Result:</strong> Phishing ⚠️</div>';
        } else {
            resultDisplay.innerHTML = '<div class="alert alert-success"><strong>Result:</strong> Legitimate ✅</div>';
        }

    } catch (error) {
        // Show an error message if the connection fails
        resultDisplay.innerHTML = '<div class="alert alert-danger">Error: Could not connect to the server.</div>';
        console.error('Fetch Error:', error);
    }
});