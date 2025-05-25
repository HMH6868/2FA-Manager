import React, { useState } from 'react';
import { RegisterModal } from './RegisterModal'; // Assuming RegisterModal is in a separate file now

const LoginRegisterPage = ({ onLogin, onRegister, onInstallPWA, showInstallPWAButton, showAlert }) => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [showRegisterModal, setShowRegisterModal] = useState(false);

    const handleSubmit = (e) => {
        e.preventDefault();
        onLogin(email, password);
    };

    return (
        <div className="login-section" id="loginSection">
            <h2 className="card-title"><i className="fas fa-shield-alt"></i>2FA Code Manager</h2>
            <p className="text-muted mb-4">Sign in to access your 2FA codes across devices</p>

            <form onSubmit={handleSubmit}>
                <div className="mb-3">
                    <label htmlFor="email" className="form-label">Email</label>
                    <input type="email" className="form-control" id="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
                </div>
                <div className="mb-3">
                    <label htmlFor="password" className="form-label">Password</label>
                    <input type="password" className="form-control" id="password" required value={password} onChange={(e) => setPassword(e.target.value)} />
                </div>
                <div className="d-grid gap-2">
                    <button type="submit" className="btn btn-primary" id="loginBtn">Sign In</button>
                    <button type="button" className="btn btn-outline-secondary" id="registerBtn" onClick={() => setShowRegisterModal(true)}>Create Account</button>
                </div>
            </form>

            {showInstallPWAButton && (
                <button id="installPWA" className="btn btn-info w-100" onClick={onInstallPWA}>
                    <i className="fas fa-download me-2"></i>Install App
                </button>
            )}

            <RegisterModal
                show={showRegisterModal}
                onClose={() => setShowRegisterModal(false)}
                onRegister={onRegister}
                showAlert={showAlert}
            />
        </div>
    );
};

export default LoginRegisterPage;
