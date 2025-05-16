// Firebase configuration with obfuscation
(function() {
    // Basic obfuscation technique - not completely secure but better than plain text
    const _0x2c7e=['AIzaSyCwJ6gKE7NhEjrVUU6WV-Fl7G9nPJU80fw','manage-2fa.firebaseapp.com','manage-2fa','manage-2fa.firebasestorage.app','634856988727','1:634856988727:web:24b95066a740b08026dfb2','G-V7EG0PGXHE'];
    
    // Domain validation to prevent unauthorized access
    const allowedDomains = [
        'localhost',
        '127.0.0.1',
        'manage-2fa.firebaseapp.com',
        '2fa-manager.vercel.app'
    ];
    
    // This method makes it harder for automated scraping tools to find API keys
    window.getFirebaseConfig = function() {
        // Simple domain check - this adds an additional layer of security
        const currentDomain = window.location.hostname;
        const isAllowedDomain = allowedDomains.includes(currentDomain);
        
        if (!isAllowedDomain) {
            console.error('Unauthorized domain access attempt');
            return { unauthorized: true }; // Return dummy object that will fail initialization
        }
        
        return {
            apiKey: _0x2c7e[0],
            authDomain: _0x2c7e[1],
            projectId: _0x2c7e[2],
            storageBucket: _0x2c7e[3],
            messagingSenderId: _0x2c7e[4],
            appId: _0x2c7e[5],
            measurementId: _0x2c7e[6]
        };
    };
})(); 