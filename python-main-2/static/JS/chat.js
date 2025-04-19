// static\JS\chat.js
function sendMessage() {
    const userInput = document.getElementById('user-input').value.trim();
    const chatDisplay = document.getElementById('chat-display');

    if (userInput) {
        // Display user message
        const userMessage = document.createElement('p');
        userMessage.innerHTML = `<strong><span style="color:rgb(0, 107, 130)">You:</span></strong> ${userInput}`;
        chatDisplay.appendChild(userMessage);

        document.getElementById('user-input').value = '';

        // Show typing simulation while waiting for the API response
        simulateBotResponse(chatDisplay, "Typing...");

        // Send the message to the API
        fetch('/api/ask', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ question: userInput, chat_id: window.currentChatId }),
        })
            .then((response) => response.json())
            .then((data) => {
                // Remove the "Typing..." message
                const lastMessage = chatDisplay.lastChild;
                window.currentChatId = data.chat_id;
                if (lastMessage && lastMessage.querySelector('.typing')) {
                    chatDisplay.removeChild(lastMessage);
                }

                if (data.answer) {
                    // Use the simulateBotResponse method to display the bot's response
                    simulateBotResponse(chatDisplay, data.answer);
                    loadChatSessions();
                } else {
                    // Handle cases where the API response doesn't include an answer
                    simulateBotResponse(chatDisplay, "Sorry, I couldn't process your message.");
                    loadChatSessions();
                }
            })
            .catch((error) => {
                // Handle API errors
                console.error("Error:", error);

                // Remove the "Typing..." message
                const lastMessage = chatDisplay.lastChild;
                if (lastMessage && lastMessage.querySelector('.typing')) {
                    chatDisplay.removeChild(lastMessage);
                }

                // Show an error message using simulateBotResponse
                simulateBotResponse(chatDisplay, "Oops! Something went wrong. Please try again later.");
                loadChatSessions();
            });
    }
}

function simulateBotResponse(chatDisplay, message) {
    const botMessage = document.createElement('p');
    botMessage.innerHTML = `<strong><span style="color:rgb(138, 0, 69)">Bot:</span></strong> <span class="typing"></span>`;
    chatDisplay.appendChild(botMessage);

    const typingSpan = botMessage.querySelector('.typing');
    let charIndex = 0;

    const typingInterval = setInterval(() => {
        if (charIndex < message.length) {
            typingSpan.textContent += message.charAt(charIndex);
            charIndex++;
            chatDisplay.scrollTop = chatDisplay.scrollHeight;
        } else {
            clearInterval(typingInterval);
        }
    }, 10);
}

function handleEnter(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        sendMessage();
    }
}

function loadChatSessions() {
    fetch('/api/chat_sessions')
        .then((response) => response.json())
        .then((data) => {
            const chatSessions = document.getElementById('chat-sessions');
            chatSessions.innerHTML = '';

            data.forEach(session => {
                const li = document.createElement('li');
                li.textContent = `${session.created_at}`;
                li.classList.add('chat-session-item');
                li.onclick = () => loadChat(session.id);
                chatSessions.appendChild(li);
            });
        })
        .catch((error) => {
            console.error("Error loading chat sessions:", error);
            alert("Failed to load chat sessions. Please try again.");
        });
}

function loadChat(chatId) {
    fetch(`/api/chat/${chatId}`)
        .then((response) => response.json())
        .then((data) => {
            const chatDisplay = document.getElementById('chat-display');
            chatDisplay.innerHTML = ''; // Clear previous chats

            data.forEach(chat => {
                // User message
                const userMessage = document.createElement('p');
                userMessage.innerHTML = `<strong><span style="color:rgb(0, 107, 130)">You:</span></strong> ${chat.user_message}`;
                chatDisplay.appendChild(userMessage);

                // Bot response
                const botMessage = document.createElement('p');
                botMessage.innerHTML = `<strong><span style="color:rgb(138, 0, 69)">Bot:</span></strong> ${chat.bot_response}`;
                chatDisplay.appendChild(botMessage);
            });

            // Set the current chat ID globally for sending messages
            window.currentChatId = chatId;
        })
        .catch((error) => {
            console.error("Error loading chat:", error);
            alert("Failed to load the chat. Please try again.");
        });
}

document.addEventListener('DOMContentLoaded', loadChatSessions);

function startNewChat() {
    window.currentChatId = 0; // Set the new chat ID
    const chatDisplay = document.getElementById('chat-display');
    chatDisplay.innerHTML = ''; // Clear the chat display for a fresh start
    const welcomeMessage = document.createElement('p');
    welcomeMessage.innerHTML = `<strong><span style="color:rgb(138, 0, 69)">Bot:</span></strong> Hi there! How can I assist you today?`;
    chatDisplay.appendChild(welcomeMessage);
    loadChatSessions(); // Refresh the chat sessions in the sidebar
}
