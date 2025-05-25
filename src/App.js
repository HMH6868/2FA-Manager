import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import './App.css'; // Default App.css
import './index.css'; // Combined 2fa.css and sidebar.css
import 'bootstrap/dist/css/bootstrap.min.css';
import * as bootstrap from 'bootstrap';
import '@fortawesome/fontawesome-free/css/all.min.css';

// Import Firebase and Google API configs
import { getFirebaseConfig } from './config';

// Import components
import LoginRegisterPage from './components/LoginRegisterPage';
import MainAppContent from './components/MainAppContent';
import { AddAccountModal } from './components/AddAccountModal';
import { RegisterModal } from './components/RegisterModal'; // Although imported in LoginRegisterPage, keep here for clarity if needed elsewhere
import { AccountItem } from './components/AccountItem'; // Although imported in MainAppContent, keep here for clarity if needed elsewhere


// Global constants (from app.js)
const SERVICE_ICONS = {
    default: 'fa-shield-alt',
    google: 'fa-google',
    facebook: 'fa-facebook',
    github: 'fa-github',
    twitter: 'fa-twitter',
    microsoft: 'fa-microsoft',
    apple: 'fa-apple',
    amazon: 'fa-amazon',
    dropbox: 'fa-dropbox',
    slack: 'fa-slack',
    discord: 'fa-discord',
    linkedin: 'fa-linkedin',
    paypal: 'fa-paypal',
    steam: 'fa-steam',
    gitlab: 'fa-gitlab',
    wordpress: 'fa-wordpress',
    bitbucket: 'fa-bitbucket',
    protonmail: 'fa-envelope',
    binance: 'fa-coins',
    digitalocean: 'fa-cloud',
    other: 'fa-shield-alt'
};

function App() {
    const [isFirebaseReady, setIsFirebaseReady] = useState(false);
    const [isLoggedIn, setIsLoggedIn] = useState(false);
    const [userEmail, setUserEmail] = useState('');
    const [accounts, setAccounts] = useState([]);
    const [syncStatus, setSyncStatus] = useState({ status: 'synced', message: 'All codes synced', icon: 'fa-check-circle' });
    const [searchTerm, setSearchTerm] = useState('');
    const [viewMode, setViewMode] = useState(localStorage.getItem('2fa_view_preference') || 'standard');
    const [showAddAccountModal, setShowAddAccountModal] = useState(false);
    const [editingAccount, setEditingAccount] = useState(null);

    // Firebase references
    const auth = isFirebaseReady ? window.firebase.auth() : null;
    const db = isFirebaseReady ? window.firebase.firestore() : null;

    // Firebase Initialization
    useEffect(() => {
        const firebaseConfig = getFirebaseConfig();
        if (firebaseConfig.unauthorized) {
            console.error('Unauthorized access to Firebase configuration');
            // Display error message to user if needed
            return;
        }

        if (window.firebase && !window.firebaseApp) {
            window.firebaseApp = window.firebase.initializeApp(firebaseConfig);
            window.firebase.firestore().enablePersistence()
                .then(() => {
                    console.log("Firestore persistence enabled");
                    setIsFirebaseReady(true);
                })
                .catch((err) => {
                    if (err.code === 'failed-precondition') {
                        console.log("Persistence failed: Multiple tabs open");
                    } else if (err.code === 'unimplemented') {
                        console.log("Persistence not supported by browser");
                    }
                    setIsFirebaseReady(true); // Still set ready even if persistence fails
                });
        } else if (window.firebaseApp) {
            setIsFirebaseReady(true); // Firebase already initialized
        }
    }, []);

    // Load CryptoJS
    useEffect(() => {
        const loadCryptoJSScript = () => {
            if (!document.getElementById('crypto-js-script')) {
                const script = document.createElement('script');
                script.src = 'https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js';
                script.id = 'crypto-js-script';
                script.onload = () => {
                    window.CryptoJS = window.CryptoJS;
                };
                document.head.appendChild(script);
            } else if (window.CryptoJS) {
                window.CryptoJS = window.CryptoJS;
            }
        };
        loadCryptoJSScript();

        const handleOnlineStatusChange = () => {
            const online = window.navigator.onLine;
            if (online) {
                updateSyncStatus('syncing', 'Reconnected, syncing changes...');
            } else {
                updateSyncStatus('offline', 'You are offline. Changes will sync when connection is restored', 'fa-wifi-slash');
            }
        };

        window.addEventListener('online', handleOnlineStatusChange);
        window.addEventListener('offline', handleOnlineStatusChange);

        return () => {
            window.removeEventListener('online', handleOnlineStatusChange);
            window.removeEventListener('offline', handleOnlineStatusChange);
        };
    }, []);

    // Authentication state observer
    useEffect(() => {
        if (!auth) return; // Wait for auth to be defined

        const unsubscribe = auth.onAuthStateChanged(async (user) => {
            if (user) {
                setIsLoggedIn(true);
                setUserEmail(user.email);
                setupAccountsListener(user.uid);
                processPendingOperations(user.uid);
            } else {
                setIsLoggedIn(false);
                setUserEmail('');
                setAccounts([]);
                if (window.unsubscribeListener) {
                    window.unsubscribeListener();
                    window.unsubscribeListener = null;
                }
                if (window.updateInterval) {
                    clearInterval(window.updateInterval);
                    window.updateInterval = null;
                }
                setSyncStatus({ status: 'synced', message: 'All codes synced', icon: 'fa-check-circle' });
            }
        });
        return () => unsubscribe();
    }, [auth]); // Depend on auth

    // Account listener
    const setupAccountsListener = (userId) => {
        updateSyncStatus('syncing', 'Connecting to database...');

        if (window.unsubscribeListener) {
            window.unsubscribeListener();
        }

        if (window.updateInterval) {
            clearInterval(window.updateInterval);
        }

        window.unsubscribeListener = db.collection('users').doc(userId)
            .collection('accounts')
            .onSnapshot(
                (snapshot) => {
                    const fetchedAccounts = [];
                    snapshot.forEach((doc) => {
                        fetchedAccounts.push({
                            id: doc.id,
                            ...doc.data()
                        });
                    });

                    fetchedAccounts.sort((a, b) => {
                        if (a.pinned && !b.pinned) return -1;
                        if (!a.pinned && b.pinned) return 1;
                        return a.name.localeCompare(b.name);
                    });

                    setAccounts(fetchedAccounts);
                    if (navigator.onLine) {
                        updateSyncStatus('synced', 'All accounts synced');
                        processPendingOperations(userId);
                    } else {
                        updateSyncStatus('offline', 'Using offline data. Changes will sync when back online', 'fa-wifi-slash');
                    }
                },
                (error) => {
                    console.error(`Firestore listen error for user ${userId}:`, error);
                    updateSyncStatus('error', 'Sync error: ' + error.message);
                }
            );

        // Start token update interval
        if (!window.updateInterval) {
            window.updateInterval = setInterval(updateTokens, 1000); // 1 second
        }
    };

    const updateSyncStatus = (status, message, iconOverride = '') => {
        let icon = '';
        switch (status) {
            case 'synced': icon = 'fa-check-circle'; break;
            case 'syncing': icon = 'fa-sync fa-spin'; break;
            case 'error': icon = 'fa-exclamation-circle'; break;
            case 'offline': icon = 'fa-wifi-slash'; break;
            default: icon = iconOverride;
        }
        setSyncStatus({ status, message, icon });
    };

    const processPendingOperations = async (userId) => {
        if (!navigator.onLine || !userId) return;

        const pendingData = localStorage.getItem('offline_2fa_accounts');
        if (!pendingData) {
            updateSyncStatus('synced', 'All changes synced');
            return;
        }

        let pendingOperations = JSON.parse(pendingData);
        pendingOperations = pendingOperations.filter(op => !op.data.userId || op.data.userId === userId);

        if (pendingOperations.length === 0) {
            updateSyncStatus('synced', 'All changes synced');
            localStorage.removeItem('offline_2fa_accounts');
            return;
        }

        updateSyncStatus('syncing', `Syncing ${pendingOperations.length} pending changes...`);

        const originalPendingOperations = [...pendingOperations]; // Keep a copy for retry
        let successfulOperations = [];

        for (let i = 0; i < pendingOperations.length; i++) {
            const operation = pendingOperations[i];
            try {
                if (operation.type === 'add') {
                    await executeAddAccount(operation.data.name, operation.data.secret, operation.data.service, operation.data.id, operation.data.pinned);
                } else if (operation.type === 'update') {
                    await executeUpdateAccount(operation.data.id, operation.data.name, operation.data.secret, operation.data.service, operation.data.pinned);
                } else if (operation.type === 'delete') {
                    await executeDeleteAccount(operation.data.id);
                }
                successfulOperations.push(operation);
            } catch (error) {
                console.error(`Error executing pending operation (${operation.type}):`, error);
                // If an operation fails, it remains in pendingOperations for next retry
            }
        }

        // Filter out successful operations from pendingOperations
        const remainingPending = originalPendingOperations.filter(op =>
            !successfulOperations.some(successOp => successOp.timestamp === op.timestamp && successOp.type === op.type && successOp.data.id === op.data.id)
        );

        if (remainingPending.length > 0) {
            localStorage.setItem('offline_2fa_accounts', JSON.stringify(remainingPending));
            updateSyncStatus('error', `Failed to sync ${remainingPending.length} changes`);
        } else {
            localStorage.removeItem('offline_2fa_accounts');
            updateSyncStatus('synced', 'All changes synced');
        }
    };

    const addPendingOperation = (type, data) => {
        const pendingData = localStorage.getItem('offline_2fa_accounts');
        let pendingOperations = pendingData ? JSON.parse(pendingData) : [];
        pendingOperations.push({ type, data, timestamp: Date.now() });
        localStorage.setItem('offline_2fa_accounts', JSON.stringify(pendingOperations));
    };

    const showAlert = (message, type) => {
        const alertContainer = document.getElementById('alertContainer');
        if (!alertContainer) return;

        const alertDiv = document.createElement('div');
        alertDiv.className = `custom-alert ${type}`;
        alertDiv.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'warning' ? 'exclamation-triangle' : 'exclamation-circle'}"></i>
            <span>${message}</span>
        `;
        alertContainer.appendChild(alertDiv);

        setTimeout(() => {
            alertDiv.remove();
        }, 3000);
    };

    // Encryption/Decryption (from app.js)
    const encryptSecret = (secret) => {
        const currentUser = auth.currentUser;
        if (!currentUser || !window.CryptoJS) return secret;
        try {
            const key = window.CryptoJS.SHA256(currentUser.uid).toString();
            const encrypted = window.CryptoJS.AES.encrypt(secret, key).toString();
            return encrypted;
        } catch (error) {
            console.error("Encryption error:", error);
            return secret;
        }
    };

    const decryptSecret = (encryptedSecret) => {
        const currentUser = auth.currentUser;
        if (!currentUser || !window.CryptoJS) return encryptedSecret;
        try {
            const key = window.CryptoJS.SHA256(currentUser.uid).toString();
            const decrypted = window.CryptoJS.AES.decrypt(encryptedSecret, key).toString(window.CryptoJS.enc.Utf8);
            return decrypted;
        } catch (error) {
            console.error("Decryption error:", error);
            return encryptedSecret;
        }
    };

    // TOTP generation (from app.js)
    const base32ToHex = (base32) => {
        const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let bits = '';
        let hex = '';
        for (let i = 0; i < base32.length; i++) {
            const val = base32Chars.indexOf(base32.charAt(i).toUpperCase());
            if (val === -1) continue;
            bits += val.toString(2).padStart(5, '0');
        }
        for (let i = 0; i < bits.length - 3; i += 4) {
            const chunk = bits.substr(i, 4);
            hex += parseInt(chunk, 2).toString(16);
        }
        return hex;
    };

    const generateTOTP = (secret) => {
        try {
            const cleanSecret = secret.replace(/\s+/g, '').toUpperCase();
            const epoch = Math.floor(Date.now() / 1000);
            const timeWindow = Math.floor(epoch / 30);

            if (typeof window.CryptoJS !== 'undefined') {
                const timeBytes = new Uint8Array(8);
                let time = timeWindow;
                for (let i = 7; i >= 0; i--) {
                    timeBytes[i] = time & 0xff;
                    time = time >> 8;
                }
                const secretHex = base32ToHex(cleanSecret);
                const wordArray = window.CryptoJS.enc.Hex.parse(secretHex);
                const timeWordArray = window.CryptoJS.enc.Hex.parse(Array.from(timeBytes).map(b => b.toString(16).padStart(2, '0')).join(''));
                const hash = window.CryptoJS.HmacSHA1(timeWordArray, wordArray);
                const hashHex = hash.toString(window.CryptoJS.enc.Hex);
                const offset = parseInt(hashHex.substr(hashHex.length - 1), 16);
                let otp = parseInt(hashHex.substr(offset * 2, 8), 16) & 0x7fffffff;
                otp = otp % 1000000;
                return otp.toString().padStart(6, '0');
            }
            return fallbackTOTP(cleanSecret, timeWindow);
        } catch (error) {
            console.error("Error generating TOTP:", error);
            const epoch = Math.floor(Date.now() / 1000);
            const timeWindow = Math.floor(epoch / 30);
            return fallbackTOTP(secret, timeWindow);
        }
    };

    const fallbackTOTP = (secret, timeWindow) => {
        let hash = 0;
        const combined = secret + timeWindow;
        for (let i = 0; i < combined.length; i++) {
            hash = ((hash << 5) - hash) + combined.charCodeAt(i);
            hash |= 0;
        }
        const code = Math.abs(hash) % 1000000;
        return code.toString().padStart(6, '0');
    };

    const getTimeRemaining = () => {
        const epoch = Math.floor(Date.now() / 1000);
        return 30 - (epoch % 30);
    };

    let lastTokenUpdate = 0;
    const updateTokens = () => {
        const currentEpoch = Math.floor(Date.now() / 1000);
        const currentWindow = Math.floor(currentEpoch / 30);

        if (currentWindow > lastTokenUpdate) {
            lastTokenUpdate = currentWindow;
            // Force re-render of accounts to update tokens
            setAccounts(prevAccounts => [...prevAccounts]);
        }
    };

    // Firebase operations (from app.js)
    const executeAddAccount = async (name, secret, service = 'default', id = null, pinned = false) => {
        const currentUser = auth.currentUser;
        if (!currentUser) throw new Error("Not authenticated");

        const userId = currentUser.uid;
        const encryptedSecret = encryptSecret(secret);

        let accountRef;
        if (id) {
            accountRef = db.collection('users').doc(userId).collection('accounts').doc(id);
        } else {
            accountRef = db.collection('users').doc(userId).collection('accounts').doc();
        }

        return accountRef.set({
            name: name,
            secret: encryptedSecret,
            service: service,
            pinned: pinned,
            userId: userId,
            createdAt: window.firebase.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
    };

    const executeUpdateAccount = async (id, name, secret, service = 'default', pinned = false) => {
        const currentUser = auth.currentUser;
        if (!currentUser) throw new Error("Not authenticated");

        const userId = currentUser.uid;
        const encryptedSecret = encryptSecret(secret);

        return db.collection('users').doc(userId)
            .collection('accounts')
            .doc(id)
            .update({
                name: name,
                secret: encryptedSecret,
                service: service,
                pinned: pinned,
                userId: userId,
                updatedAt: window.firebase.firestore.FieldValue.serverTimestamp()
            });
    };

    const executeDeleteAccount = async (id) => {
        const currentUser = auth.currentUser;
        if (!currentUser) throw new Error("Not authenticated");

        const userId = currentUser.uid;
        return db.collection('users').doc(userId)
            .collection('accounts')
            .doc(id)
            .delete();
    };

    const handleAddAccount = async (name, secret, service, pinned) => {
        if (!auth.currentUser) {
            showAlert('You must be logged in to add accounts', 'error');
            return;
        }

        const userId = auth.currentUser.uid;
        updateSyncStatus('syncing', 'Adding account...');

        const newAccountRef = db.collection('users').doc(userId).collection('accounts').doc();
        const accountId = newAccountRef.id;

        if (!navigator.onLine) {
            addPendingOperation('add', { id: accountId, name, secret, service, pinned, userId });
            updateSyncStatus('offline', 'Account will be synced when back online', 'fa-wifi-slash');
            showAlert('Account saved offline. It will sync when connection is restored.', 'warning');
            return;
        }

        const encryptedSecret = encryptSecret(secret);
        const newAccount = {
            id: accountId,
            name: name,
            secret: encryptedSecret,
            service: service,
            pinned: pinned,
            userId: userId
        };

        setAccounts(prevAccounts => [...prevAccounts, newAccount]); // Optimistic update

        try {
            await newAccountRef.set({
                name: name,
                secret: encryptedSecret,
                service: service,
                pinned: pinned,
                userId: userId,
                createdAt: window.firebase.firestore.FieldValue.serverTimestamp()
            }, { merge: true });
            showAlert('Account added successfully!', 'success');
        } catch (error) {
            console.error(`Error adding account for user ${userId}:`, error);
            addPendingOperation('add', { id: accountId, name, secret, service, pinned, userId });
            showAlert('Failed to add account: ' + error.message, 'error');
            updateSyncStatus('error', 'Failed to add account');
        }
    };

    const handleUpdateAccount = async (id, name, secret, service, pinned) => {
        if (!auth.currentUser) {
            showAlert('You must be logged in to update accounts', 'error');
            return;
        }

        const userId = auth.currentUser.uid;
        updateSyncStatus('syncing', 'Updating account...');

        if (!navigator.onLine) {
            addPendingOperation('update', { id, name, secret, service, pinned, userId });
            updateSyncStatus('offline', 'Changes will be synced when back online', 'fa-wifi-slash');
            showAlert('Changes saved offline. They will sync when connection is restored.', 'warning');
            return;
        }

        try {
            await executeUpdateAccount(id, name, secret, service, pinned);
            showAlert('Account updated successfully!', 'success');
        } catch (error) {
            console.error(`Error updating account ${id} for user ${userId}:`, error);
            addPendingOperation('update', { id, name, secret, service, pinned, userId });
            showAlert('Failed to update account: ' + error.message, 'error');
            updateSyncStatus('error', 'Failed to update account');
        }
    };

    const handleDeleteAccount = async (id) => {
        if (!auth.currentUser) {
            showAlert('You must be logged in to delete accounts', 'error');
            return;
        }

        if (window.confirm('Are you sure you want to delete this account?')) {
            const userId = auth.currentUser.uid;
            updateSyncStatus('syncing', 'Deleting account...');

            if (!navigator.onLine) {
                addPendingOperation('delete', { id, userId });
                updateSyncStatus('offline', 'Deletion will be synced when back online', 'fa-wifi-slash');
                showAlert('Deletion saved offline. It will sync when connection is restored.', 'warning');
                return;
            }

            try {
                await executeDeleteAccount(id);
                showAlert('Account deleted', 'success');
            } catch (error) {
                console.error(`Error deleting account ${id} for user ${userId}:`, error);
                addPendingOperation('delete', { id, userId });
                showAlert('Failed to delete account: ' + error.message, 'error');
                updateSyncStatus('error', 'Failed to delete account');
            }
        }
    };

    const handleLogin = async (email, password) => {
        updateSyncStatus('syncing', 'Signing in...');
        try {
            await auth.setPersistence(window.firebase.auth.Auth.Persistence.LOCAL);
            await auth.signInWithEmailAndPassword(email, password);
            showAlert('Signed in successfully!', 'success');
        } catch (error) {
            console.error("Sign in error:", error);
            updateSyncStatus('error', 'Sign in failed');
            showAlert('Authentication failed: ' + error.message, 'error');
        }
    };

    const handleRegister = async (email, password) => {
        try {
            await auth.setPersistence(window.firebase.auth.Auth.Persistence.LOCAL);
            await auth.createUserWithEmailAndPassword(email, password);
            showAlert('Account created! You have been signed in.', 'success');
            // setShowRegisterModal(false); // This state is now managed by LoginRegisterPage
        } catch (error) {
            console.error("Registration error:", error);
            showAlert('Registration failed: ' + error.message, 'error');
        }
    };

    const handleLogout = async () => {
        try {
            await auth.signOut();
            showAlert('Signed out successfully!', 'success');
        } catch (error) {
            console.error("Error signing out:", error);
            showAlert('Error signing out: ' + error.message, 'error');
        }
    };

    const handleExportAccounts = () => {
        if (!auth.currentUser || accounts.length === 0) {
            showAlert('No accounts to export', 'warning');
            return;
        }
        try {
            const exportData = accounts.map(account => ({
                id: account.id,
                name: account.name,
                secret: decryptSecret(account.secret),
                service: account.service || 'default',
                pinned: account.pinned,
            }));
            const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a'); // Declare 'a'
            a.href = url;
            a.download = `2fa-backup-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            setTimeout(() => {
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }, 0);
            showAlert('Accounts exported successfully!', 'success');
        } catch (error) {
            console.error('Export error:', error);
            showAlert('Failed to export accounts: ' + error.message, 'error');
        }
    };

    const handleImportAccounts = (file) => {
        if (!auth.currentUser) {
            showAlert('You must be logged in to import accounts', 'error');
            return;
        }
        const reader = new FileReader();
        reader.onload = async (e) => {
            try {
                const importData = JSON.parse(e.target.result);
                if (!Array.isArray(importData)) {
                    throw new Error('Invalid import file format');
                }
                if (!window.confirm(`Import ${importData.length} accounts? This will not overwrite existing accounts.`)) {
                    return;
                }
                updateSyncStatus('syncing', 'Importing accounts...');
                let successCount = 0;
                let failureCount = 0;
                for (const account of importData) {
                    if (!account.name || !account.secret) {
                        failureCount++;
                        continue;
                    }
                    try {
                        generateTOTP(account.secret); // Validate secret
                        const service = account.service || 'default';
                        await executeAddAccount(account.name, account.secret, service, null, account.pinned);
                        successCount++;
                    } catch (error) {
                        console.error('Error importing account:', error);
                        failureCount++;
                    }
                }
                if (successCount > 0) {
                    showAlert(`Successfully imported ${successCount} accounts${failureCount > 0 ? ` (${failureCount} failed)` : ''}`, 'success');
                } else {
                    showAlert('Failed to import any accounts', 'error');
                }
                updateSyncStatus('synced', 'Import complete');
            } catch (error) {
                console.error('Import error:', error);
                showAlert('Failed to import accounts: ' + error.message, 'error');
            }
        };
        reader.onerror = () => {
            showAlert('Failed to read import file', 'error');
        };
        reader.readAsText(file);
    };

    const handleRefreshAccounts = async () => {
        if (!auth.currentUser) {
            showAlert('You must be logged in to refresh accounts', 'warning');
            return;
        }
        updateSyncStatus('syncing', 'Refreshing accounts...');
        setAccounts([]); // Clear accounts optimistically
        try {
            const userId = auth.currentUser.uid;
            const snapshot = await db.collection('users').doc(userId).collection('accounts').orderBy('name').get();
            const refreshedAccounts = [];
            snapshot.forEach((doc) => {
                refreshedAccounts.push({ id: doc.id, ...doc.data() });
            });
            setAccounts(refreshedAccounts);
            if (navigator.onLine) {
                updateSyncStatus('synced', 'Accounts refreshed successfully');
                processPendingOperations(userId);
            } else {
                updateSyncStatus('offline', 'Using cached data. Changes will sync when back online', 'fa-wifi-slash');
            }
            showAlert('Accounts refreshed successfully', 'success');
        } catch (error) {
            console.error(`Error refreshing accounts:`, error);
            updateSyncStatus('error', 'Failed to refresh accounts: ' + error.message);
            showAlert('Failed to refresh accounts: ' + error.message, 'error');
        }
    };

    const togglePinAccount = async (id) => {
        if (!auth.currentUser) {
            showAlert('You must be logged in to pin accounts', 'error');
            return;
        }
        const userId = auth.currentUser.uid;
        const accountToToggle = accounts.find(a => a.id === id);
        if (!accountToToggle) {
            showAlert('Account not found', 'error');
            return;
        }
        const newPinStatus = !accountToToggle.pinned;

        if (!navigator.onLine) {
            setAccounts(prevAccounts => prevAccounts.map(acc => acc.id === id ? { ...acc, pinned: newPinStatus } : acc));
            addPendingOperation('update', { id, userId, updates: { pinned: newPinStatus } });
            updateSyncStatus('offline', 'Pin status will be synced when back online', 'fa-wifi-slash');
            showAlert(`Account ${newPinStatus ? 'pinned' : 'unpinned'}. It will sync when connection is restored.`, 'warning');
            return;
        }

        try {
            await db.collection('users').doc(userId).collection('accounts').doc(id).update({ pinned: newPinStatus });
            showAlert(`Account ${newPinStatus ? 'pinned' : 'unpinned'}`, 'success');
        } catch (error) {
            console.error(`Error updating pin status for account ${id}:`, error);
            addPendingOperation('update', { id, userId, updates: { pinned: newPinStatus } });
            showAlert('Failed to update pin status: ' + error.message, 'error');
            updateSyncStatus('error', 'Failed to update pin status');
        }
    };

    const changeViewMode = (mode) => {
        setViewMode(mode);
        localStorage.setItem('2fa_view_preference', mode);
    };

    const filteredAccounts = accounts.filter(account =>
        account.name.toLowerCase().includes(searchTerm.toLowerCase())
    );

    // PWA Install Logic (from app.js)
    const [deferredPrompt, setDeferredPrompt] = useState(null);
    const [showInstallPWAButton, setShowInstallPWAButton] = useState(false);

    useEffect(() => {
        const handleBeforeInstallPrompt = (e) => {
            e.preventDefault();
            setDeferredPrompt(e);
            setShowInstallPWAButton(true);
        };

        const handleAppInstalled = () => {
            setShowInstallPWAButton(false);
            setDeferredPrompt(null);
            showAlert('App installed successfully!', 'success');
        };

        window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
        window.addEventListener('appinstalled', handleAppInstalled);

        if (window.matchMedia('(display-mode: standalone)').matches) {
            setShowInstallPWAButton(false);
        }

        // Service Worker registration (if sw.js exists)
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/sw.js')
                .then(registration => {
                    console.log('ServiceWorker registration successful');
                })
                .catch(error => {
                    console.log('ServiceWorker registration failed: ', error);
                });
        }

        return () => {
            window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
            window.removeEventListener('appinstalled', handleAppInstalled);
        };
    }, []);

    const handleInstallPWA = () => {
        if (deferredPrompt) {
            deferredPrompt.prompt();
            deferredPrompt.userChoice.then((choiceResult) => {
                if (choiceResult.outcome === 'accepted') {
                    console.log('User accepted the A2HS prompt');
                } else {
                    console.log('User dismissed the A2HS prompt');
                }
                setDeferredPrompt(null);
            });
        }
    };

    return (
        <Router>
            <div className="container" id="appContainer">
                {!isFirebaseReady ? (
                    <div className="loading-screen">Loading application...</div>
                ) : (
                    <Routes>
                        <Route path="/" element={
                            isLoggedIn ? (
                                <MainAppContent
                                    userEmail={userEmail}
                                    syncStatus={syncStatus}
                                    accounts={filteredAccounts}
                                    searchTerm={searchTerm}
                                    setSearchTerm={setSearchTerm}
                                    viewMode={viewMode}
                                    changeViewMode={changeViewMode}
                                    onAddAccountClick={() => { setEditingAccount(null); setShowAddAccountModal(true); }}
                                    onExportAccounts={handleExportAccounts}
                                    onImportAccounts={handleImportAccounts}
                                    onRefreshAccounts={handleRefreshAccounts}
                                    onEditAccount={(account) => { setEditingAccount(account); setShowAddAccountModal(true); }}
                                    onDeleteAccount={handleDeleteAccount}
                                    togglePinAccount={togglePinAccount}
                                    generateTOTP={generateTOTP}
                                    getTimeRemaining={getTimeRemaining}
                                    SERVICE_ICONS={SERVICE_ICONS}
                                    decryptSecret={decryptSecret}
                                    handleLogout={handleLogout}
                                />
                            ) : (
                                <LoginRegisterPage
                                    onLogin={handleLogin}
                                    onRegister={handleRegister}
                                    onInstallPWA={handleInstallPWA}
                                    showInstallPWAButton={showInstallPWAButton}
                                    showAlert={showAlert}
                                />
                            )
                        } />
                        {/* Add other routes if necessary, e.g., for specific account details */}
                    </Routes>
                )}

                <AddAccountModal
                    show={showAddAccountModal}
                    onClose={() => setShowAddAccountModal(false)}
                    onSave={editingAccount ? handleUpdateAccount : handleAddAccount}
                    editingAccount={editingAccount}
                    SERVICE_ICONS={SERVICE_ICONS}
                    decryptSecret={decryptSecret}
                    generateTOTP={generateTOTP}
                    showAlert={showAlert}
                />

                <div id="alertContainer" className="alert-container"></div>
            </div>
        </Router>
    );
}

export default App;
