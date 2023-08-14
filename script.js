let encryptedData = null;
let decryptedData = null;

function generatePassword() {
    const password = generateRandomPassword();
    document.getElementById('passwordInput').value = password;
}

function generateRandomPassword() {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_";
    const passwordLength = 16;
    let password = "";
    
    for (let i = 0; i < passwordLength; i++) {
        const randomIndex = Math.floor(Math.random() * charset.length);
        password += charset[randomIndex];
    }
    
    return password;
}
function encryptData(data, password) {
    const salt = CryptoJS.lib.WordArray.random(128 / 8); // Random salt
    const key = CryptoJS.PBKDF2(password, salt, { keySize: 256 / 32, iterations: 1000 });

    const iv = CryptoJS.lib.WordArray.random(128 / 8); // Random IV
    const encrypted = CryptoJS.AES.encrypt(data, key, { iv: iv });

    // Create a combined message of salt + iv + ciphertext for decryption later
    const combined = salt.toString() + iv.toString() + encrypted.toString();
    return combined;
}

function decryptData(data, password) {
    const salt = CryptoJS.enc.Hex.parse(data.substr(0, 32));
    const iv = CryptoJS.enc.Hex.parse(data.substr(32, 32));
    const encrypted = data.substring(64);

    const key = CryptoJS.PBKDF2(password, salt, { keySize: 256 / 32, iterations: 1000 });
    const decrypted = CryptoJS.AES.decrypt(encrypted, key, { iv: iv });

    return decrypted.toString(CryptoJS.enc.Utf8);
}

function encryptFile() {
    const fileInput = document.getElementById('fileInput');
    const selectedFile = fileInput.files[0];
    const password = document.getElementById('passwordInput').value;

    if (selectedFile && password) {
        const reader = new FileReader();

        reader.onload = function(event) {
            const fileData = event.target.result.split(",")[1]; // Split off the data URL prefix
            // const fileData = event.target.result.split(",")[1];
            encryptedData = selectedFile.type + "," + encryptData(fileData, password);
            // encryptedData = encryptData(fileData, password);
            alert('File encrypted successfully.');

            const downloadEncryptedLink = document.getElementById('downloadEncryptedLink');
            downloadEncryptedLink.href = URL.createObjectURL(new Blob([encryptedData], { type: 'application/octet-stream' }));
            downloadEncryptedLink.download = 'encrypted_file.aes';
            downloadEncryptedLink.style.display = 'inline';
        }

        reader.readAsDataURL(selectedFile);
    } else {
        alert('Please select a file and enter a password.');
    }
}

function decryptFile() {
    const password = document.getElementById('passwordInput').value;

    if (password && encryptedData) {
        const mimeType = encryptedData.split(",")[0];  // Extract MIME type
        const encryptedContent = encryptedData.split(",")[1];  // Extract encrypted content
        
        const decryptedContent = decryptData(encryptedContent, password);
        
        // Combine MIME type with decrypted data to form a valid data URL
        const dataUrl = "data:" + mimeType + ";base64," + decryptedContent;

        // Display and prepare download link
        const downloadDecryptedLink = document.getElementById('downloadDecryptedLink');
        downloadDecryptedLink.href = dataUrl;
        downloadDecryptedLink.download = 'decrypted_file.' + (mimeType.split('/')[1] || 'txt');  // uses MIME subtype as extension, defaults to .txt
        downloadDecryptedLink.style.display = 'inline';

        // Checking if the mimeType suggests it's an image
        if (mimeType.startsWith('image/')) {
            const outputImage = document.getElementById('outputImage');
            outputImage.src = dataUrl;
            outputImage.style.display = 'block';
            downloadDecryptedLink.innerText = "Download Decrypted Image";
        } else {
            // If not an image, just adjust the download link text
            downloadDecryptedLink.innerText = "Download Decrypted File";
        }
    } else {
        alert('Password or encrypted data is missing.');
    }
}




function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return window.btoa(binary);
}