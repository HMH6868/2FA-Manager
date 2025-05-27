// Firebase configuration with obfuscation
// This configuration is directly exported for use in React components.
// For production, consider using environment variables for sensitive keys.

const _0x2c7e = ['AIzaSyCwJ6gKE7NhEjrVUU6WV-Fl7G9nPJU80fw', 'manage-2fa.firebaseapp.com', 'manage-2fa', 'manage-2fa.firebasestorage.app', '634856988727', '1:634856988727:web:24b95066a740b08026dfb2', 'G-V7EG0PGXHE'];


// Domain validation to prevent unauthorized access
const allowedDomains = [
    'localhost',
    '127.0.0.1',
    'manage-2fa.firebaseapp.com',
    '2fa-manager.vercel.app',
    '2fa.hmh6868.id.vn'
];

export const getFirebaseConfig = () => {
    const currentDomain = window.location.hostname;
    const isAllowedDomain = allowedDomains.includes(currentDomain);

    if (!isAllowedDomain) {
        console.error('Unauthorized domain access attempt');
        return { unauthorized: true };
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
