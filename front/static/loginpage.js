// Login form submission
function validateLoginForm(event) {
    event.preventDefault();

    const usernameOrEmail = document.getElementById("usernameOrEmail").value.trim();
    const password = document.getElementById("password").value.trim();
    let isValid = true;

    // Reset error messages
    document.getElementById("username-error").innerText = "";
    document.getElementById("password-error").innerText = "";

    // Validate inputs
    if (!usernameOrEmail) {
        document.getElementById("username-error").innerText = "پر کردن این فیلد اجباری است";
        isValid = false;
    }
    if (!password) {
        document.getElementById("password-error").innerText = "پر کردن این فیلد اجباری است";
        isValid = false;
    }

    if (isValid) {
        // Extract query parameters from the URL
        const urlParams = new URLSearchParams(window.location.search);
        const clientId = urlParams.get("client_id");
        const redirectUri = urlParams.get("redirect_uri");
        const responseType = urlParams.get("response_type");

        // Simulate server request and response
        fetch("http://localhost:8080/api/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                username: /^[a-zA-Z0-9_.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(usernameOrEmail) ? "" : usernameOrEmail,
                email: /^[a-zA-Z0-9_.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(usernameOrEmail) ? usernameOrEmail : "",
                password: password,
                client_id: clientId,
                redirect_uri: redirectUri,
                response_type: responseType,
            }),
        })
            .then(response => response.json())
            .then(data => {
                if (data.login_token) {
                    // Store the LoginToken
                    localStorage.setItem("loginToken", data.login_token);

                    // Hide the login form and show the verification form
                    document.getElementById("login-form").style.display = "none";
                    document.getElementById("verify-form").style.display = "block";
                } else {
                    // If there's an error in the response, display the error message
                    document.getElementById("response-message").innerText = data.error || "Invalid credentials.";
                }
            })
            .catch(err => {
                document.getElementById("response-message").innerText = "Error: " + err.message;
            });
    }
}


// Verification code submission
function validateVerificationCode(event) {
    event.preventDefault();
    const inputs = document.querySelectorAll("#code-inputs input");
    let totp = "";
    inputs.forEach(input => totp += input.value.trim());

    let loginToken = localStorage.getItem("loginToken");
    console.log(loginToken)

    // Extract query parameters from the URL
    const urlParams = new URLSearchParams(window.location.search);
    const clientId = urlParams.get("client_id");
    const redirectUri = urlParams.get("redirect_uri");
    const responseType = urlParams.get("response_type");

    if (totp.length === 6) {
        fetch("http://localhost:8080/api/totp-approve", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                login_token: loginToken,
                totp: totp,
                client_id: clientId,
                redirect_uri: redirectUri,
                response_type: responseType}),
        })
            .then(response => response.json())
            .then(data => {
                debugger;
                if (data) {
                    document.getElementById("verify-response-message").innerText = "Code verified successfully!";
                    window.location.href = data.redirect_url;
                } else {
                    document.getElementById("verify-response-message").innerText = data.error || "Invalid code.";
                }
            })
            .catch(err => {
                document.getElementById("verify-response-message").innerText = "Error: " + err.message;
            });
    } else {
        document.getElementById("verify-response-message").innerText = "Please enter all 6 digits.";
    }
}

// Move focus to the next input box
function moveFocus(currentInput, nextIndex) {
    if (currentInput.value.length === 1 && nextIndex <= 6) {
        const nextInput = document.querySelector(`#code-inputs input:nth-child(${nextIndex})`);
        if (nextInput) nextInput.focus();
    }
}

// Handle the alternative method selection
function showAlternativeMethod(event) {
    event.preventDefault();  // Prevent default link behavior

    // Hide the verification form and show the alternative method
    document.getElementById('verify-form').style.display = 'none';
    document.getElementById('alternative-method').style.display = 'block';

    // Extract query parameters from the URL
    const urlParams = new URLSearchParams(window.location.search);
    const clientId = urlParams.get("client_id");
    const redirectUri = urlParams.get("redirect_uri");
    const responseType = urlParams.get("response_type");

    // Open a WebSocket connection to the server
    const socket = new WebSocket('wss://localhost:8080/api/notif-approve');

    // Create the object to send to the server (with the SignupToken)
    const loginToken = localStorage.getItem('loginToken'); // Retrieve the signup token
    const requestPayload = {
        login_token: loginToken,  // Send the loginToken as loginToken
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: responseType
    };

    socket.onopen = function() {
        // Send the login request to the server
        socket.send(JSON.stringify(requestPayload));
    };

    socket.onmessage = function(event) {
        const response = JSON.parse(event.data);

        if (response.code) {
            // Display the alternative code received from the server
            document.getElementById('alternative-code').textContent = response.code;
        } else if (response.error) {
            // Display any error message if there's an issue
            document.getElementById('alternative-code').textContent = 'Error: ' + response.error;
        }

        // Check for approval status from the server
        if (response.approved !== undefined) {
            if (response.approved === 1) {
                // Success: Code is approved
                document.getElementById('alternative-code').textContent = 'Code Approved! You can now log in.';
            } else if (response.approved === 2) {
                // Failure: Code is rejected or login failed
                document.getElementById('alternative-code').textContent = 'Login failed. Please try again.';
            }
        }
    };

    socket.onerror = function(event) {
        console.error('WebSocket error:', event);
        document.getElementById('alternative-code').textContent = 'WebSocket error occurred.';
    };

    socket.onclose = function() {
        console.log('WebSocket connection closed');
    };
}

// Go back to the original verification form
function goBackToVerification() {
    document.getElementById('alternative-method').style.display = 'none';
    document.getElementById('verify-form').style.display = 'block';
}