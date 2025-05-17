window.initializeGoogleApis = function() {
    console.log("Initializing Google APIs...");
    
    if (window.gApiLoaded) {
        console.log("Loading Google client API...");
        gapi.load('client', function() {
            console.log("Google client API loaded, initializing...");
            gapi.client.init({
                apiKey: window.getGoogleDriveConfig().apiKey,
                discoveryDocs: window.getGoogleDriveConfig().discoveryDocs,
            }).then(function() {
                console.log("Google client API initialized successfully");
                window.gapiInited = true;
            }).catch(function(error) {
                console.error("Error initializing Google client API:", error);
            });
        });
    }
    
    if (window.gisLoaded) {
        console.log("Initializing Google Identity Services...");
        window.tokenClient = google.accounts.oauth2.initTokenClient({
            client_id: window.getGoogleDriveConfig().clientId,
            scope: window.getGoogleDriveConfig().scopes,
            callback: function(response) {
                console.log("Google auth response received", response);
                if (response.error !== undefined) {
                    console.error("Google auth error:", response);
                    alert("Google Drive authorization failed");
                    return;
                }
                
                console.log("Google Drive authorization successful");
                // alert("Connected to Google Drive!");
                
                // Update UI to show connected state
                document.getElementById('gDriveConnected').style.display = 'block';
                document.getElementById('authorizeGDriveBtn').textContent = 'Disconnect Google Drive';
                document.getElementById('authorizeGDriveBtn').classList.remove('btn-primary');
                document.getElementById('authorizeGDriveBtn').classList.add('btn-outline-secondary');
                
                // Enable form fields
                document.querySelectorAll('#backupSettingsForm input, #backupSettingsForm select').forEach(function(el) {
                    el.disabled = false;
                });
                
                document.getElementById('saveBackupSettingsBtn').disabled = false;
                document.getElementById('backupNowBtn').disabled = false;
            }
        });
        window.gisInited = true;
    }
};

// Try to initialize when script loads
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(window.initializeGoogleApis, 1000);
});

// Get Firebase configuration securely
const firebaseConfig = window.getFirebaseConfig();

// Check if config is valid (not unauthorized)
if (firebaseConfig.unauthorized) {
    // Display error message instead of initializing Firebase
    document.getElementById('loginSection').innerHTML = '<div class="alert alert-danger">Unauthorized access attempt detected. Please use an authorized domain.</div>';
    throw new Error('Unauthorized access to Firebase configuration');
}

// Initialize Firebase
firebase.initializeApp(firebaseConfig);

// Enable Firestore offline persistence
firebase.firestore().enablePersistence()
  .catch((err) => {
      if (err.code == 'failed-precondition') {
          // Multiple tabs open, persistence can only be enabled in one tab
          console.log("Persistence failed: Multiple tabs open");
      } else if (err.code == 'unimplemented') {
          // Browser doesn't support persistence
          console.log("Persistence not supported by browser");
      }
  });

document.addEventListener('DOMContentLoaded', function() {
    // Firebase services
    const auth = firebase.auth();
    const db = firebase.firestore();
    
    // Constants
    const TOKEN_UPDATE_INTERVAL = 1000; // 1 second
    const OFFLINE_STORAGE_KEY = 'offline_2fa_accounts';
    const BACKUP_SETTINGS_KEY = '2fa_backup_settings';
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
    
    // Elements
    const appContainer = document.getElementById('appContainer');
    const loginSection = document.getElementById('loginSection');
    const mainApp = document.getElementById('mainApp');
    const userEmail = document.getElementById('userEmail');
    const syncStatus = document.getElementById('syncStatus');
    const accountsList = document.getElementById('accountsList');
    const noAccounts = document.getElementById('noAccounts');
    const searchInput = document.getElementById('searchInput');
    const addAccountForm = document.getElementById('addAccountForm');
    const saveAccountBtn = document.getElementById('saveAccountBtn');
    const pasteSecretBtn = document.getElementById('pasteSecretBtn');
    const accountNameInput = document.getElementById('accountName');
    const secretKeyInput = document.getElementById('secretKey');
    const loginForm = document.getElementById('loginForm');
    const loginBtn = document.getElementById('loginBtn');
    const registerBtn = document.getElementById('registerBtn');
    const registerForm = document.getElementById('registerForm');
    const createAccountBtn = document.getElementById('createAccountBtn');
    const logoutBtn = document.getElementById('logoutBtn');
    const serviceTypeSelect = document.getElementById('serviceType');
    const selectedServiceIcon = document.getElementById('selectedServiceIcon');
    
    // Bootstrap Modals
    const addAccountModal = new bootstrap.Modal(document.getElementById('addAccountModal'));
    const registerModal = new bootstrap.Modal(document.getElementById('registerModal'));
    const backupSettingsModal = new bootstrap.Modal(document.getElementById('backupSettingsModal'));
    const alertContainer = document.getElementById('alertContainer');
    
    // State
    let accounts = [];
    let updateInterval = null; // Explicitly initialize as null
    let currentUser = null;
    let unsubscribeListener = null;
    let isOnline = window.navigator.onLine;
    let pendingOperations = [];
    let currentViewMode = 'standard'; // Track the current view mode
    let lastTokenUpdate = 0; // Track when tokens were last updated
    
    // Check online status
    window.addEventListener('online', handleOnlineStatusChange);
    window.addEventListener('offline', handleOnlineStatusChange);
    
    function handleOnlineStatusChange() {
        isOnline = window.navigator.onLine;
        if (isOnline) {
            updateSyncStatus('syncing', 'Reconnected, syncing changes...');
            processPendingOperations();
        } else {
            updateSyncStatus('offline', 'You are offline. Changes will sync when connection is restored', 'fa-wifi-slash');
        }
    }
    
    // Process pending operations
    function processPendingOperations() {
        if (!isOnline || !currentUser) return;
        
        const userId = currentUser.uid;
        
        // Load pending operations from localStorage
        const pendingData = localStorage.getItem(OFFLINE_STORAGE_KEY);
        if (!pendingData) {
            updateSyncStatus('synced', 'All changes synced');
            return;
        }
        
        try {
            pendingOperations = JSON.parse(pendingData);
            
            // Filter operations to only include those belonging to the current user
            pendingOperations = pendingOperations.filter(op => 
                !op.data.userId || op.data.userId === userId
            );
            
            if (pendingOperations.length === 0) {
                updateSyncStatus('synced', 'All changes synced');
                localStorage.removeItem(OFFLINE_STORAGE_KEY);
                return;
            }
            
            // Process each pending operation
            updateSyncStatus('syncing', `Syncing ${pendingOperations.length} pending changes...`);
            
            const processNext = () => {
                if (pendingOperations.length === 0) {
                    localStorage.removeItem(OFFLINE_STORAGE_KEY);
                    updateSyncStatus('synced', 'All changes synced');
                    return;
                }
                
                const operation = pendingOperations.shift();
                
                // Skip operations for other users
                if (operation.data.userId && operation.data.userId !== userId) {
                    console.log(`Skipping operation for different user: ${operation.data.userId}`);
                    processNext();
                    return;
                }
                
                // Execute the operation based on type
                if (operation.type === 'add') {
                    executeAddAccount(operation.data.name, operation.data.secret, operation.data.service, operation.data.id, operation.data.pinned)
                        .then(() => {
                            console.log(`Pending add operation completed for user ${userId}`);
                            processNext();
                        })
                        .catch((error) => {
                            console.error(`Error executing pending add for user ${userId}:`, error);
                            // If failed, push back to pending operations
                            pendingOperations.push(operation);
                            savePendingOperations();
                            updateSyncStatus('error', 'Some changes failed to sync');
                        });
                } else if (operation.type === 'update') {
                    executeUpdateAccount(operation.data.id, operation.data.name, operation.data.secret, operation.data.service, operation.data.pinned)
                        .then(() => {
                            console.log(`Pending update operation completed for user ${userId}`);
                            processNext();
                        })
                        .catch((error) => {
                            console.error(`Error executing pending update for user ${userId}:`, error);
                            pendingOperations.push(operation);
                            savePendingOperations();
                            updateSyncStatus('error', 'Some changes failed to sync');
                        });
                } else if (operation.type === 'delete') {
                    executeDeleteAccount(operation.data.id)
                        .then(() => {
                            console.log(`Pending delete operation completed for user ${userId}`);
                            processNext();
                        })
                        .catch((error) => {
                            console.error(`Error executing pending delete for user ${userId}:`, error);
                            pendingOperations.push(operation);
                            savePendingOperations();
                            updateSyncStatus('error', 'Some changes failed to sync');
                        });
                } else {
                    // Unknown operation type, skip it
                    console.warn(`Unknown operation type: ${operation.type}`);
                    processNext();
                }
            };
            
            processNext();
        } catch (error) {
            console.error(`Error processing pending operations for user ${userId}:`, error);
            updateSyncStatus('error', 'Failed to sync some changes');
            localStorage.removeItem(OFFLINE_STORAGE_KEY);
        }
    }
    
    // Save pending operations to localStorage
    function savePendingOperations() {
        if (pendingOperations.length > 0) {
            localStorage.setItem(OFFLINE_STORAGE_KEY, JSON.stringify(pendingOperations));
        } else {
            localStorage.removeItem(OFFLINE_STORAGE_KEY);
        }
    }
    
    // Add a pending operation
    function addPendingOperation(type, data) {
        pendingOperations.push({ type, data, timestamp: Date.now() });
        savePendingOperations();
    }
    
    // Robust authentication state check
    auth.onAuthStateChanged(function(user) {
        if (user) {
            console.log("User is signed in:", user.uid);
            // User is signed in
            currentUser = user;
            userEmail.textContent = user.email;
            userEmail.title = user.email; // Set the tooltip with full email
            loginSection.style.display = 'none';
            mainApp.style.display = 'block';
            
            // Clear any existing accounts from previous user
            accounts = [];
            // Clear any existing interval
            if (updateInterval) {
                clearInterval(updateInterval);
                updateInterval = null;
            }
            lastTokenUpdate = 0;
            renderAccounts();
            
            // Start real-time listener for accounts
            setupAccountsListener();
        } else {
            console.log("User is signed out");
            // User is signed out
            currentUser = null;
            accounts = [];
            if (updateInterval) {
                clearInterval(updateInterval);
                updateInterval = null;
            }
            lastTokenUpdate = 0;
            
            // Remove listener if exists
            if (unsubscribeListener) {
                unsubscribeListener();
                unsubscribeListener = null;
            }
            
            mainApp.style.display = 'none';
            loginSection.style.display = 'block';
        }
    });
    
    // Set up real-time listener for accounts collection
    function setupAccountsListener() {
        updateSyncStatus('syncing', 'Connecting to database...');
        
        if (unsubscribeListener) {
            unsubscribeListener();
            unsubscribeListener = null;
        }
        
        // Clear any existing interval
        if (updateInterval) {
            clearInterval(updateInterval);
            updateInterval = null;
        }
        
        if (!currentUser) {
            console.error("No user is logged in, cannot set up listener");
            updateSyncStatus('error', 'Authentication error');
            return;
        }
        
        const userId = currentUser.uid;
        console.log(`Setting up listener for user: ${userId}, email: ${currentUser.email}`);
        
        if (!isOnline) {
            updateSyncStatus('offline', 'You are offline. Using locally cached data', 'fa-wifi-slash');
            // When offline, Firestore will use cached data if available
        }
        
        try {
            // Use the current user's UID to scope queries to only their data
            unsubscribeListener = db.collection('users').doc(userId)
                .collection('accounts')
                .onSnapshot(
                    (snapshot) => {
                        // Create a copy of the previous accounts for comparison
                        const previousAccounts = [...accounts];
                        accounts = [];
                        
                        snapshot.forEach((doc) => {
                            accounts.push({
                                id: doc.id,
                                ...doc.data()
                            });
                        });
                        
                        // Sort accounts: pinned first, then alphabetically by name
                        accounts.sort((a, b) => {
                            // First sort by pinned status
                            if (a.pinned && !b.pinned) return -1;
                            if (!a.pinned && b.pinned) return 1;
                            
                            // Then sort alphabetically by name
                            return a.name.localeCompare(b.name);
                        });
                        
                        // Only render if accounts actually changed to avoid unnecessary renders
                        const accountsChanged = 
                            previousAccounts.length !== accounts.length || 
                            JSON.stringify(previousAccounts.map(a => a.id).sort()) !== 
                            JSON.stringify(accounts.map(a => a.id).sort());
                        
                        console.log(`Loaded ${accounts.length} accounts for user ${userId}`);
                        
                        if (accountsChanged) {
                            renderAccounts();
                        } else {
                            console.log("Accounts unchanged, skipping re-render");
                        }
                        
                        if (isOnline) {
                            updateSyncStatus('synced', 'All accounts synced');
                            processPendingOperations();
                        } else {
                            updateSyncStatus('offline', 'Using offline data. Changes will sync when back online', 'fa-wifi-slash');
                        }
                    },
                    (error) => {
                        console.error(`Firestore listen error for user ${userId}:`, error);
                        updateSyncStatus('error', 'Sync error: ' + error.message);
                    }
                );
        } catch (error) {
            console.error(`Error setting up accounts listener for user ${userId}:`, error);
            updateSyncStatus('error', 'Failed to connect to database');
        }
    }
    
    // Login function
    function login(email, password) {
        updateSyncStatus('syncing', 'Signing in...');
        
        // First sign out if another user is signed in
        if (currentUser) {
            logout();
        }
        
        auth.setPersistence(firebase.auth.Auth.Persistence.LOCAL)
            .then(() => {
                console.log(`Attempting to sign in as: ${email}`);
                return auth.signInWithEmailAndPassword(email, password);
            })
            .then((userCredential) => {
                // Login successful
                console.log(`Signed in successfully as: ${userCredential.user.email} (${userCredential.user.uid})`);
                showAlert('Signed in successfully!', 'success');
            })
            .catch((error) => {
                console.error("Sign in error:", error);
                updateSyncStatus('error', 'Sign in failed');
                showAlert('Authentication failed: ' + error.message, 'error');
            });
    }
    
    // Register function
    function register(email, password) {
        // First sign out if another user is signed in
        if (currentUser) {
            logout();
        }
        
        auth.setPersistence(firebase.auth.Auth.Persistence.LOCAL)
            .then(() => {
                console.log(`Attempting to create account: ${email}`);
                return auth.createUserWithEmailAndPassword(email, password);
            })
            .then((userCredential) => {
                // Registration successful
                console.log(`Account created successfully: ${userCredential.user.email} (${userCredential.user.uid})`);
                showAlert('Account created! You have been signed in.', 'success');
                registerModal.hide();
            })
            .catch((error) => {
                console.error("Registration error:", error);
                showAlert('Registration failed: ' + error.message, 'error');
            });
    }
    
    // Logout function
    function logout() {
        auth.signOut()
            .then(() => {
                console.log("User signed out");
                // Clear local data
                accounts = [];
                renderAccounts();
            })
            .catch((error) => {
                console.error("Error signing out:", error);
                showAlert('Error signing out: ' + error.message, 'error');
            });
    }
    
    // Update sync status indicator
    function updateSyncStatus(status, message, iconOverride) {
        let icon = '';
        switch (status) {
            case 'synced':
                icon = '<i class="fas fa-check-circle"></i>';
                break;
            case 'syncing':
                icon = '<i class="fas fa-sync fa-spin"></i>';
                break;
            case 'error':
                icon = '<i class="fas fa-exclamation-circle"></i>';
                break;
            case 'offline':
                icon = '<i class="fas fa-wifi-slash"></i>';
                break;
            default:
                icon = iconOverride ? `<i class="fas ${iconOverride}"></i>` : '';
        }
        
        syncStatus.innerHTML = `${icon} ${message}`;
        
        // Update favicon with badge if there are pending operations
        const pendingCount = pendingOperations.length;
        if (pendingCount > 0) {
            // Add a visual indicator that changes are pending
            syncStatus.innerHTML += ` <span class="badge bg-warning text-dark">${pendingCount}</span>`;
        }
    }
    
    // Execute account operations
    // These functions actually perform the Firebase operations
    // They return promises to allow chaining
    function executeAddAccount(name, secret, service = 'default', id = null, pinned = false) {
        if (!currentUser) return Promise.reject(new Error("Not authenticated"));
        
        const userId = currentUser.uid;
        
        // Encrypt secret before storing
        const encryptedSecret = encryptSecret(secret);
        
        // If an ID is provided, use it, otherwise let Firestore generate one
        let accountRef;
        if (id) {
            accountRef = db.collection('users').doc(userId)
                .collection('accounts').doc(id);
        } else {
            accountRef = db.collection('users').doc(userId)
                .collection('accounts').doc();
        }
        
        // Use set with merge for better offline support
        return accountRef.set({
            name: name,
            secret: encryptedSecret,
            service: service, // Store service type
            pinned: pinned, // Store pinned status
            userId: userId, // Store user ID for extra security and clarity
            createdAt: firebase.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
    }
    
    function executeUpdateAccount(id, name, secret, service = 'default', pinned = false) {
        if (!currentUser) return Promise.reject(new Error("Not authenticated"));
        
        const userId = currentUser.uid;
        
        // Encrypt secret before storing
        const encryptedSecret = encryptSecret(secret);
        
        return db.collection('users').doc(userId)
            .collection('accounts')
            .doc(id)
            .update({
                name: name,
                secret: encryptedSecret,
                service: service, // Update service type
                pinned: pinned, // Update pinned status
                userId: userId, // Update user ID just in case
                updatedAt: firebase.firestore.FieldValue.serverTimestamp()
            });
    }
    
    function executeDeleteAccount(id) {
        if (!currentUser) return Promise.reject(new Error("Not authenticated"));
        
        const userId = currentUser.uid;
        
        return db.collection('users').doc(userId)
            .collection('accounts')
            .doc(id)
            .delete();
    }
    
    // Add a new account to Firestore
    function addAccount(name, secret, service = 'default', pinned = false) {
        if (!currentUser) {
            showAlert('You must be logged in to add accounts', 'error');
            return;
        }
        
        const userId = currentUser.uid;
        console.log(`Adding account for user ${userId}: ${name}, service: ${service}`);
        
        updateSyncStatus('syncing', 'Adding account...');
        
        // Generate unique document ID for better offline support
        const newAccountRef = db.collection('users').doc(userId)
            .collection('accounts').doc();
            
        const accountId = newAccountRef.id;
        
        if (!isOnline) {
            // Store the operation to be executed when back online
            addPendingOperation('add', { id: accountId, name, secret, service, pinned, userId });
            updateSyncStatus('offline', 'Account will be synced when back online', 'fa-wifi-slash');
            showAlert('Account saved offline. It will sync when connection is restored.', 'warning');
            return;
        }
        
        // Encrypt secret before storing
        const encryptedSecret = encryptSecret(secret);
        
        // Add the new account to the local accounts array to prevent disappearing entries
        const newAccount = {
            id: accountId,
            name: name,
            secret: encryptedSecret,
            service: service,
            pinned: pinned,
            userId: userId
        };
        
        // Add to local array first to maintain UI continuity
        accounts.push(newAccount);
        
        // Re-render with the new account included
        renderAccounts();
        
        // Now send to Firestore (the listener will update again when completed)
        newAccountRef.set({
            name: name,
            secret: encryptedSecret,
            service: service, // Store service type
            pinned: pinned, // Store pinned status
            userId: userId, // Store user ID for extra security and clarity
            createdAt: firebase.firestore.FieldValue.serverTimestamp()
        }, { merge: true })
            .then(() => {
                console.log(`Account added with ID: ${accountId} for user ${userId}`);
                showAlert('Account added successfully!', 'success');
            })
            .catch((error) => {
                console.error(`Error adding account for user ${userId}:`, error);
                // If failed and we're online, store for later retry
                addPendingOperation('add', { id: accountId, name, secret, service, pinned, userId });
                showAlert('Failed to add account: ' + error.message, 'error');
                updateSyncStatus('error', 'Failed to add account');
            });
    }
    
    // Update an existing account
    function updateAccount(id, name, secret, service = 'default', pinned = false) {
        if (!currentUser) {
            showAlert('You must be logged in to update accounts', 'error');
            return;
        }
        
        const userId = currentUser.uid;
        console.log(`Updating account ${id} for user ${userId}`);
        
        updateSyncStatus('syncing', 'Updating account...');
        
        if (!isOnline) {
            // Store the operation to be executed when back online
            addPendingOperation('update', { id, name, secret, service, pinned, userId });
            updateSyncStatus('offline', 'Changes will be synced when back online', 'fa-wifi-slash');
            showAlert('Changes saved offline. They will sync when connection is restored.', 'warning');
            return;
        }
        
        // Verify ownership before updating
        db.collection('users').doc(userId)
            .collection('accounts').doc(id).get()
            .then((doc) => {
                if (!doc.exists) {
                    throw new Error('Account not found or you do not have permission to update it');
                }
                
                return executeUpdateAccount(id, name, secret, service, pinned);
            })
            .then(() => {
                showAlert('Account updated successfully!', 'success');
            })
            .catch((error) => {
                console.error(`Error updating account ${id} for user ${userId}:`, error);
                // If failed and we're online, store for later retry
                addPendingOperation('update', { id, name, secret, service, pinned, userId });
                showAlert('Failed to update account: ' + error.message, 'error');
                updateSyncStatus('error', 'Failed to update account');
            });
    }
    
    // Delete an account
    function deleteAccount(id) {
        if (!currentUser) {
            showAlert('You must be logged in to delete accounts', 'error');
            return;
        }
        
        const userId = currentUser.uid;
        console.log(`Deleting account ${id} for user ${userId}`);
        
        if (confirm('Are you sure you want to delete this account?')) {
            updateSyncStatus('syncing', 'Deleting account...');
            
            if (!isOnline) {
                // Store the operation to be executed when back online
                addPendingOperation('delete', { id, userId });
                updateSyncStatus('offline', 'Deletion will be synced when back online', 'fa-wifi-slash');
                showAlert('Deletion saved offline. It will sync when connection is restored.', 'warning');
                return;
            }
            
            // Verify ownership before deleting
            db.collection('users').doc(userId)
                .collection('accounts').doc(id).get()
                .then((doc) => {
                    if (!doc.exists) {
                        throw new Error('Account not found or you do not have permission to delete it');
                    }
                    
                    return executeDeleteAccount(id);
                })
                .then(() => {
                    showAlert('Account deleted', 'success');
                })
                .catch((error) => {
                    console.error(`Error deleting account ${id} for user ${userId}:`, error);
                    // If failed and we're online, store for later retry
                    addPendingOperation('delete', { id, userId });
                    showAlert('Failed to delete account: ' + error.message, 'error');
                    updateSyncStatus('error', 'Failed to delete account');
                });
        }
    }
    
    // Simple encryption/decryption for secrets
    function encryptSecret(secret) {
        if (!currentUser) return secret;
        
        try {
            // Use user's UID as part of the encryption key
            const key = CryptoJS.SHA256(currentUser.uid).toString();
            const encrypted = CryptoJS.AES.encrypt(secret, key).toString();
            return encrypted;
        } catch (error) {
            console.error("Encryption error:", error);
            return secret; // Fallback to unencrypted
        }
    }
    
    function decryptSecret(encryptedSecret) {
        if (!currentUser) return encryptedSecret;
        
        try {
            // Use user's UID as part of the encryption key
            const key = CryptoJS.SHA256(currentUser.uid).toString();
            const decrypted = CryptoJS.AES.decrypt(encryptedSecret, key).toString(CryptoJS.enc.Utf8);
            return decrypted;
        } catch (error) {
            console.error("Decryption error:", error);
            return encryptedSecret; // Fallback to the encrypted string
        }
    }
    
    // Base32 decoding function
    function base32ToHex(base32) {
        const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let bits = '';
        let hex = '';
        
        // Convert each base32 character to 5 bits
        for (let i = 0; i < base32.length; i++) {
            const val = base32Chars.indexOf(base32.charAt(i).toUpperCase());
            if (val === -1) continue; // Skip non-base32 characters
            bits += val.toString(2).padStart(5, '0');
        }
        
        // Convert bits to hex
        for (let i = 0; i < bits.length - 3; i += 4) {
            const chunk = bits.substr(i, 4);
            hex += parseInt(chunk, 2).toString(16);
        }
        
        return hex;
    }
    
    // Generate TOTP code
    function generateTOTP(secret) {
        try {
            // Clean up the secret key (remove spaces and convert to uppercase)
            const cleanSecret = secret.replace(/\s+/g, '').toUpperCase();
            
            // Get current time window (30 seconds)
            const epoch = Math.floor(Date.now() / 1000);
            const timeWindow = Math.floor(epoch / 30);
            
            // Use CryptoJS if available
            if (typeof CryptoJS !== 'undefined') {
                // Convert time window to buffer
                const timeBytes = new Uint8Array(8);
                let time = timeWindow;
                for (let i = 7; i >= 0; i--) {
                    timeBytes[i] = time & 0xff;
                    time = time >> 8;
                }
                
                // Convert secret to hex
                const secretHex = base32ToHex(cleanSecret);
                
                // Calculate HMAC
                const wordArray = CryptoJS.enc.Hex.parse(secretHex);
                const timeWordArray = CryptoJS.enc.Hex.parse(Array.from(timeBytes).map(b => b.toString(16).padStart(2, '0')).join(''));
                const hash = CryptoJS.HmacSHA1(timeWordArray, wordArray);
                const hashHex = hash.toString(CryptoJS.enc.Hex);
                
                // Get offset and truncate
                const offset = parseInt(hashHex.substr(hashHex.length - 1), 16);
                let otp = parseInt(hashHex.substr(offset * 2, 8), 16) & 0x7fffffff;
                otp = otp % 1000000;
                
                return otp.toString().padStart(6, '0');
            }
            
            // Fallback to simple implementation if CryptoJS is not available
            return fallbackTOTP(cleanSecret, timeWindow);
        } catch (error) {
            console.error("Error generating TOTP:", error);
            // Use fallback method if there's an error
            const epoch = Math.floor(Date.now() / 1000);
            const timeWindow = Math.floor(epoch / 30);
            return fallbackTOTP(secret, timeWindow);
        }
    }
    
    // Fallback TOTP implementation (not cryptographically secure)
    function fallbackTOTP(secret, timeWindow) {
        // Simple hash function for fallback
        let hash = 0;
        const combined = secret + timeWindow;
        
        for (let i = 0; i < combined.length; i++) {
            hash = ((hash << 5) - hash) + combined.charCodeAt(i);
            hash |= 0; // Convert to 32-bit integer
        }
        
        // Generate a 6-digit code
        const code = Math.abs(hash) % 1000000;
        return code.toString().padStart(6, '0');
    }
    
    // Get time remaining until next token refresh
    function getTimeRemaining() {
        const epoch = Math.floor(Date.now() / 1000);
        return 30 - (epoch % 30);
    }
    
    // Render accounts list
    function renderAccounts() {
        if (accounts.length === 0) {
            noAccounts.style.display = 'block';
            if (updateInterval) {
                clearInterval(updateInterval);
                updateInterval = null;
            }
            return;
        }
        
        // Make the accounts available for backup
        window.accountsForBackup = [...accounts];
        console.log("Updated accounts for backup:", window.accountsForBackup.length);
        
        noAccounts.style.display = 'none';
        
        // Filter accounts based on search
        const searchTerm = searchInput.value.toLowerCase();
        const filteredAccounts = accounts.filter(account => 
            account.name.toLowerCase().includes(searchTerm)
        );
        
        // Clear existing content
        accountsList.innerHTML = filteredAccounts.length === 0 ? 
            '<div class="text-center p-4">No matching accounts found</div>' : '';
        
        // Check if we're in grid view mode
        const isGridView = accountsList.classList.contains('grid-view');
        const isCompactView = accountsList.classList.contains('mobile-compact-view');
        
        // Separate pinned and regular accounts
        const pinnedAccounts = filteredAccounts.filter(account => account.pinned);
        const regularAccounts = filteredAccounts.filter(account => !account.pinned);
        
        // Show pinned accounts section if there are any
        if (pinnedAccounts.length > 0) {
            const pinnedHeader = document.createElement('div');
            pinnedHeader.className = 'accounts-section-header';
            pinnedHeader.innerHTML = '<i class="fas fa-thumbtack"></i> Pinned Accounts';
            accountsList.appendChild(pinnedHeader);
            
            // Render pinned accounts
            renderAccountItems(pinnedAccounts, isGridView, isCompactView, true);
            
            // Add non-pinned header if we also have regular accounts
            if (regularAccounts.length > 0) {
                const regularHeader = document.createElement('div');
                regularHeader.className = 'accounts-section-header';
                regularHeader.innerHTML = '<i class="fas fa-list"></i> Other Accounts';
                accountsList.appendChild(regularHeader);
            }
        }
        
        // Render non-pinned accounts
        if (regularAccounts.length > 0) {
            renderAccountItems(regularAccounts, isGridView, isCompactView, false);
        }
        
        // Set the initial lastTokenUpdate value
        if (lastTokenUpdate === 0) {
            lastTokenUpdate = Math.floor(Math.floor(Date.now() / 1000) / 30);
        }
        
        // Properly manage the update interval - ensure only one exists
        if (!updateInterval) {
            updateInterval = setInterval(updateTokens, TOKEN_UPDATE_INTERVAL);
            console.log("Started token update interval");
        }
    }
    
    // Helper function to render account items
    function renderAccountItems(accountsToRender, isGridView, isCompactView, isPinned) {
        // Available token styles
        const tokenStyles = [
            'token-style-1',
            'token-style-2',
            'token-style-3',
            'token-style-4',
            'token-style-5',
            'token-style-6',
            'token-style-7',
            'token-style-8',
            'token-style-monospace',
            'token-style-outlined',
            'token-style-neon',
            'token-style-dark',
            'token-style-card',
            'token-style-neumorphic',
            'token-style-pastel',
            'token-style-blocks',
            'token-style-segmented',
            'token-style-retro'
        ];
        
        // Add accounts to list
        accountsToRender.forEach((account) => {
            // Decrypt the secret before generating token
            const decryptedSecret = decryptSecret(account.secret);
            const token = generateTOTP(decryptedSecret);
            const timeRemaining = getTimeRemaining();
            const progressValue = (timeRemaining / 30) * 100;
            const dashOffset = 251.2 - (251.2 * progressValue / 100);
            
            // Use a fixed token style instead of dynamic selection
            const tokenStyle = 'token-style-1';
            
            // Get service icon based on account.service or default
            const service = account.service || 'default';
            const iconClass = SERVICE_ICONS[service] || SERVICE_ICONS.default;
            const iconPrefix = ['google', 'facebook', 'github', 'twitter', 'microsoft', 'apple', 'amazon', 
                               'dropbox', 'slack', 'discord', 'linkedin', 'paypal', 'steam', 'gitlab', 
                               'wordpress', 'bitbucket'].includes(service) ? 'fab' : 'fas';
            
            const accountItem = document.createElement('div');
            accountItem.className = 'code-item d-flex align-items-center justify-content-between';
            if (account.pinned) {
                accountItem.classList.add('pinned');
            }
            accountItem.dataset.id = account.id;
            
            // Special handling for styles that need digit-by-digit rendering
            let tokenHTML = token;
            if (tokenStyle === 'token-style-blocks' || tokenStyle === 'token-style-segmented') {
                tokenHTML = '';
                for (let i = 0; i < token.length; i++) {
                    tokenHTML += `<span>${token[i]}</span>`;
                }
            }
            
            // PIN indicator for pinned accounts
            const pinIndicator = account.pinned ? 
                `<div class="pin-indicator"><i class="fas fa-thumbtack"></i></div>` : '';
            
            // Slightly different layout for compact view
            if (isCompactView && window.innerWidth <= 576) {
                accountItem.innerHTML = `
                    <div class="token-container">
                        <h5 class="mb-0" title="${account.name}">
                            <i class="${iconPrefix} ${iconClass}" style="color: #4B97C5;"></i>
                            <span>${account.name}</span>
                        </h5>
                        <div class="token ${tokenStyle}" title="Click to copy" style="cursor: pointer;" data-token="${token}">${tokenHTML}</div>
                    </div>
                    <div class="d-flex align-items-center actions-container">
                        <button class="copy-btn" title="Copy code" data-token="${token}">
                            <i class="fas fa-copy"></i>
                        </button>
                        <div class="progress-container">
                            <svg class="circular-progress" viewBox="0 0 100 100">
                                <circle class="progress-circle" cx="50" cy="50" r="40" />
                                <circle class="progress-value" cx="50" cy="50" r="40" 
                                        stroke-dasharray="251.2" 
                                        stroke-dashoffset="${dashOffset}" />
                            </svg>
                            <div class="time-remaining position-absolute top-50 start-50 translate-middle">
                                ${timeRemaining}s
                            </div>
                        </div>
                        <div class="dropdown">
                            <button class="btn btn-sm btn-light" type="button" data-bs-toggle="dropdown">
                                <i class="fas fa-ellipsis-v"></i>
                            </button>
                            <ul class="dropdown-menu dropdown-menu-end">
                                <li><button class="dropdown-item pin-btn" data-id="${account.id}">
                                    <i class="fas fa-thumbtack me-2"></i>${account.pinned ? 'Unpin' : 'Pin'}
                                </button></li>
                                <li><button class="dropdown-item edit-btn" data-id="${account.id}">
                                    <i class="fas fa-edit me-2"></i>Edit
                                </button></li>
                                <li><button class="dropdown-item delete-btn" data-id="${account.id}">
                                    <i class="fas fa-trash-alt me-2"></i>Delete
                                </button></li>
                            </ul>
                        </div>
                    </div>
                `;
            } else if (isGridView) {
                // Grid view layout with optimized account name for two lines
                accountItem.innerHTML = `
                    <div class="token-container">
                        <h5 class="mb-1" title="${account.name}">
                            <i class="${iconPrefix} ${iconClass}"></i>
                            <span>${account.name}</span>
                        </h5>
                        <div class="token ${tokenStyle}" title="Click to copy" style="cursor: pointer;" data-token="${token}">${tokenHTML}</div>
                    </div>
                    <div class="d-flex align-items-center actions-container">
                        <button class="copy-btn me-2" title="Copy code" data-token="${token}">
                            <i class="fas fa-copy"></i>
                        </button>
                        <div class="progress-container me-2">
                            <svg class="circular-progress" viewBox="0 0 100 100">
                                <circle class="progress-circle" cx="50" cy="50" r="40" />
                                <circle class="progress-value" cx="50" cy="50" r="40" 
                                        stroke-dasharray="251.2" 
                                        stroke-dashoffset="${dashOffset}" />
                            </svg>
                            <div class="time-remaining position-absolute top-50 start-50 translate-middle">
                                ${timeRemaining}s
                            </div>
                        </div>
                        <div class="dropdown">
                            <button class="btn btn-sm btn-light" type="button" data-bs-toggle="dropdown">
                                <i class="fas fa-ellipsis-v"></i>
                            </button>
                            <ul class="dropdown-menu dropdown-menu-end">
                                <li><button class="dropdown-item pin-btn" data-id="${account.id}">
                                    <i class="fas fa-thumbtack me-2"></i>${account.pinned ? 'Unpin' : 'Pin'}
                                </button></li>
                                <li><button class="dropdown-item edit-btn" data-id="${account.id}">
                                    <i class="fas fa-edit me-2"></i>Edit
                                </button></li>
                                <li><button class="dropdown-item delete-btn" data-id="${account.id}">
                                    <i class="fas fa-trash-alt me-2"></i>Delete
                                </button></li>
                            </ul>
                        </div>
                    </div>
                `;
            } else {
                // Standard view layout with optimized account name
                accountItem.innerHTML = `
                    <div class="token-container">
                        <h5 class="mb-1" title="${account.name}">
                            <i class="${iconPrefix} ${iconClass} me-2" style="color: #4B97C5;"></i>
                            <span>${account.name}</span>
                        </h5>
                        <div class="token ${tokenStyle}" title="Click to copy" style="cursor: pointer;" data-token="${token}">${tokenHTML}</div>
                    </div>
                    <div class="d-flex align-items-center actions-container">
                        <button class="copy-btn me-2" title="Copy code" data-token="${token}">
                            <i class="fas fa-copy"></i>
                        </button>
                        <div class="progress-container me-2">
                            <svg class="circular-progress" viewBox="0 0 100 100">
                                <circle class="progress-circle" cx="50" cy="50" r="40" />
                                <circle class="progress-value" cx="50" cy="50" r="40" 
                                        stroke-dasharray="251.2" 
                                        stroke-dashoffset="${dashOffset}" />
                            </svg>
                            <div class="time-remaining position-absolute top-50 start-50 translate-middle">
                                ${timeRemaining}s
                            </div>
                        </div>
                        <div class="dropdown">
                            <button class="btn btn-sm btn-light" type="button" data-bs-toggle="dropdown">
                                <i class="fas fa-ellipsis-v"></i>
                            </button>
                            <ul class="dropdown-menu dropdown-menu-end">
                                <li><button class="dropdown-item pin-btn" data-id="${account.id}">
                                    <i class="fas fa-thumbtack me-2"></i>${account.pinned ? 'Unpin' : 'Pin'}
                                </button></li>
                                <li><button class="dropdown-item edit-btn" data-id="${account.id}">
                                    <i class="fas fa-edit me-2"></i>Edit
                                </button></li>
                                <li><button class="dropdown-item delete-btn" data-id="${account.id}">
                                    <i class="fas fa-trash-alt me-2"></i>Delete
                                </button></li>
                            </ul>
                        </div>
                    </div>
                `;
            }
            accountsList.appendChild(accountItem);
            
            // Add event listener for copy button
            const copyBtn = accountItem.querySelector('.copy-btn');
            copyBtn.addEventListener('click', () => {
                navigator.clipboard.writeText(token)
                    .then(() => showAlert('Code copied to clipboard!', 'success'))
                    .catch(err => showAlert('Failed to copy code', 'error'));
            });
            
            // Add event listener for clicking on the token itself
            const tokenElement = accountItem.querySelector('.token');
            tokenElement.addEventListener('click', () => {
                navigator.clipboard.writeText(token)
                    .then(() => showAlert('Code copied to clipboard!', 'success'))
                    .catch(err => showAlert('Failed to copy code', 'error'));
            });
            
            // Add event listeners for edit and delete
            const editBtn = accountItem.querySelector('.edit-btn');
            editBtn.addEventListener('click', () => {
                const accountToEdit = accounts.find(a => a.id === account.id);
                editAccount(accountToEdit);
            });
            
            const deleteBtn = accountItem.querySelector('.delete-btn');
            deleteBtn.addEventListener('click', () => deleteAccount(account.id));
            
            // Add event listener for pin/unpin button
            const pinBtn = accountItem.querySelector('.pin-btn');
            pinBtn.addEventListener('click', () => togglePinAccount(account.id));
        });
    }
    
    // Edit an existing account (to populate modal)
    function editAccount(account) {
        accountNameInput.value = account.name;
        // Decrypt secret before showing in form
        secretKeyInput.value = decryptSecret(account.secret);
        
        // Set service type
        const service = account.service || 'default';
        serviceTypeSelect.value = service;
        
        // Update service icon
        const iconClass = SERVICE_ICONS[service] || SERVICE_ICONS.default;
        const iconPrefix = ['google', 'facebook', 'github', 'twitter', 'microsoft', 'apple', 'amazon', 
                          'dropbox', 'slack', 'discord', 'linkedin', 'paypal', 'steam', 'gitlab', 
                          'wordpress', 'bitbucket'].includes(service) ? 'fab' : 'fas';
        selectedServiceIcon.innerHTML = `<i class="${iconPrefix} ${iconClass}"></i>`;
        
        // Update the large preview icon
        const serviceIconPreview = document.getElementById('serviceIconPreview');
        serviceIconPreview.innerHTML = `<i class="${iconPrefix} ${iconClass} fa-2x"></i>`;
        
        // Set pin switch if it exists
        const pinAccountSwitch = document.getElementById('pinAccountSwitch');
        if (pinAccountSwitch) {
            pinAccountSwitch.checked = account.pinned || false;
        }
        
        // Change save button functionality
        saveAccountBtn.dataset.mode = 'edit';
        saveAccountBtn.dataset.id = account.id;
        
        // Update button text for edit mode
        saveAccountBtn.innerHTML = '<i class="fas fa-save me-2"></i>Save Changes';
        
        // Show the modal
        addAccountModal.show();
    }
    
    // Update tokens and progress bars
    function updateTokens() {
        const timeRemaining = getTimeRemaining();
        const progressValue = (timeRemaining / 30) * 100;
        const dashOffset = 251.2 - (251.2 * progressValue / 100);
        const currentEpoch = Math.floor(Date.now() / 1000);
        const currentWindow = Math.floor(currentEpoch / 30);
        
        // Update time remaining text
        document.querySelectorAll('.time-remaining').forEach(el => {
            el.textContent = `${timeRemaining}s`;
        });
        
        // Update progress rings
        document.querySelectorAll('.progress-value').forEach(el => {
            el.setAttribute('stroke-dashoffset', dashOffset);
        });
        
        // Only regenerate tokens when time window changes
        if (currentWindow > lastTokenUpdate) {
            console.log("Time window changed, regenerating tokens");
            lastTokenUpdate = currentWindow;
            renderAccounts();
        }
    }
    
    // Show alert message
    function showAlert(message, type) {
        const alert = document.createElement('div');
        alert.className = `custom-alert ${type}`;
        alert.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'warning' ? 'exclamation-triangle' : 'exclamation-circle'}"></i>
            <span>${message}</span>
        `;
        alertContainer.appendChild(alert);
        
        // Remove alert after animation completes
        setTimeout(() => {
            alert.remove();
        }, 3000);
    }
    
    // Event Listeners
    loginForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        login(email, password);
    });
    
    registerBtn.addEventListener('click', function() {
        registerModal.show();
    });
    
    createAccountBtn.addEventListener('click', function() {
        if (!registerForm.checkValidity()) {
            registerForm.reportValidity();
            return;
        }
        
        const email = document.getElementById('regEmail').value;
        const password = document.getElementById('regPassword').value;
        const confirm = document.getElementById('confirmPassword').value;
        
        if (password !== confirm) {
            showAlert('Passwords do not match', 'error');
            return;
        }
        
        register(email, password);
    });
    
    logoutBtn.addEventListener('click', logout);
    
    // Export accounts function
    function exportAccounts() {
        if (!currentUser || accounts.length === 0) {
            showAlert('No accounts to export', 'warning');
            return;
        }
        
        try {
            // Create export data with decrypted secrets
            const exportData = accounts.map(account => ({
                id: account.id,
                name: account.name,
                secret: decryptSecret(account.secret),
                service: account.service || 'default', // Include service type
                pinned: account.pinned, // Include pinned status
                // Don't include userId for security
            }));
            
            // Create a blob with the data
            const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            
            // Create a link to download the file
            const a = document.createElement('a');
            a.href = url;
            a.download = `2fa-backup-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            
            // Clean up
            setTimeout(() => {
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }, 0);
            
            showAlert('Accounts exported successfully!', 'success');
        } catch (error) {
            console.error('Export error:', error);
            showAlert('Failed to export accounts: ' + error.message, 'error');
        }
    }
    
    // Import accounts function
    function importAccounts(file) {
        if (!currentUser) {
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
                
                // Confirm import
                if (!confirm(`Import ${importData.length} accounts? This will not overwrite existing accounts.`)) {
                    return;
                }
                
                updateSyncStatus('syncing', 'Importing accounts...');
                
                // Track success/failure
                let successCount = 0;
                let failureCount = 0;
                
                // Process each account
                for (const account of importData) {
                    if (!account.name || !account.secret) {
                        failureCount++;
                        continue;
                    }
                    
                    try {
                        // Validate the secret
                        generateTOTP(account.secret);
                        
                        // Extract service type (use default if not specified)
                        const service = account.service || 'default';
                        
                        // Add the account
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
    }
    
    // Create hidden file input for import
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.accept = '.json';
    fileInput.style.display = 'none';
    document.body.appendChild(fileInput);
    
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            importAccounts(e.target.files[0]);
        }
        // Reset input so the same file can be selected again
        e.target.value = '';
    });
    
    // Add event listeners for export/import buttons
    const exportAccountsBtn = document.getElementById('exportAccountsBtn');
    exportAccountsBtn.addEventListener('click', exportAccounts);
    
    const importAccountsBtn = document.getElementById('importAccountsBtn');
    importAccountsBtn.addEventListener('click', () => {
        fileInput.click();
    });
    
    // Refresh accounts without full page reload
    function refreshAccounts() {
        if (!currentUser) {
            showAlert('You must be logged in to refresh accounts', 'warning');
            return;
        }
        
        // Start spinning the refresh icon
        const refreshBtn = document.getElementById('refreshAccountsBtn');
        const refreshIcon = refreshBtn.querySelector('i');
        refreshIcon.classList.add('fa-spin');
        refreshBtn.disabled = true;
        
        // Show refreshing status
        updateSyncStatus('syncing', 'Refreshing accounts...');
        
        // Clear existing accounts
        accounts = [];
        renderAccounts();
        
        const userId = currentUser.uid;
        
        // Get fresh data from Firestore
        db.collection('users').doc(userId)
            .collection('accounts')
            .orderBy('name')
            .get()
            .then((snapshot) => {
                accounts = [];
                snapshot.forEach((doc) => {
                    accounts.push({
                        id: doc.id,
                        ...doc.data()
                    });
                });
                
                console.log(`Refreshed ${accounts.length} accounts for user ${userId}`);
                renderAccounts();
                
                if (isOnline) {
                    updateSyncStatus('synced', 'Accounts refreshed successfully');
                    // Process any pending operations after refresh
                    processPendingOperations();
                } else {
                    updateSyncStatus('offline', 'Using cached data. Changes will sync when back online', 'fa-wifi-slash');
                }
                
                showAlert('Accounts refreshed successfully', 'success');
            })
            .catch((error) => {
                console.error(`Error refreshing accounts for user ${userId}:`, error);
                updateSyncStatus('error', 'Failed to refresh accounts: ' + error.message);
                showAlert('Failed to refresh accounts: ' + error.message, 'error');
            })
            .finally(() => {
                // Stop spinning and re-enable button
                refreshIcon.classList.remove('fa-spin');
                refreshBtn.disabled = false;
            });
    }
    
    // Add refresh button event listener
    const refreshAccountsBtn = document.getElementById('refreshAccountsBtn');
    refreshAccountsBtn.addEventListener('click', function(e) {
        e.preventDefault();
        e.stopPropagation();
        refreshAccounts();
    });
    
    // Add keyboard shortcut for refresh (Ctrl+R or Cmd+R)
    document.addEventListener('keydown', function(e) {
        // Check if Ctrl+R or Cmd+R is pressed and main app is visible
        if ((e.ctrlKey || e.metaKey) && e.key === 'r' && mainApp.style.display !== 'none') {
            e.preventDefault(); // Prevent default browser refresh
            refreshAccounts();
        }
    });
    
    saveAccountBtn.addEventListener('click', () => {
        if (!addAccountForm.checkValidity()) {
            addAccountForm.reportValidity();
            return;
        }
        
        const name = accountNameInput.value.trim();
        const secret = secretKeyInput.value.trim().replace(/\s/g, '');
        const service = serviceTypeSelect.value;
        
        // Use the pin switch instead of checking if name is empty
        const pinAccountSwitch = document.getElementById('pinAccountSwitch');
        const pinned = pinAccountSwitch ? pinAccountSwitch.checked : false;
        
        // Validate the secret
        try {
            generateTOTP(secret);
        } catch (e) {
            showAlert('Invalid secret key format', 'error');
            return;
        }
        
        if (saveAccountBtn.dataset.mode === 'edit') {
            const id = saveAccountBtn.dataset.id;
            updateAccount(id, name, secret, service, pinned);
        } else {
            addAccount(name, secret, service, pinned);
        }
        
        // Reset form and close modal
        addAccountForm.reset();
        saveAccountBtn.dataset.mode = 'add';
        delete saveAccountBtn.dataset.id;
        addAccountModal.hide();
    });
    
    pasteSecretBtn.addEventListener('click', async () => {
        try {
            const text = await navigator.clipboard.readText();
            secretKeyInput.value = text.trim();
        } catch (err) {
            showAlert('Could not access clipboard', 'error');
        }
    });
    
    searchInput.addEventListener('input', renderAccounts);
    
    addAccountModal.addEventListener('hidden.bs.modal', () => {
        addAccountForm.reset();
        saveAccountBtn.dataset.mode = 'add';
        delete saveAccountBtn.dataset.id;
        
        // Reset icon preview
        const serviceIconPreview = document.getElementById('serviceIconPreview');
        if (serviceIconPreview) {
            serviceIconPreview.innerHTML = '<i class="fas fa-shield-alt fa-2x"></i>';
        }
        selectedServiceIcon.innerHTML = '<i class="fas fa-globe"></i>';
        
        // Reset button text
        saveAccountBtn.innerHTML = '<i class="fas fa-check me-2"></i>Add Account';
        
        // Reset pin switch
        const pinAccountSwitch = document.getElementById('pinAccountSwitch');
        if (pinAccountSwitch) {
            pinAccountSwitch.checked = false;
        }
    });
    
    // Initialize
    try {
        // Initialize mobile view toggler
        const viewToggle = document.querySelector('.view-toggle');
        
        // Add event listeners to view toggle buttons
        viewToggle.querySelectorAll('.btn').forEach(btn => {
            btn.addEventListener('click', function() {
                console.log("View toggle clicked:", this.getAttribute('data-view'));
                
                // Remove active class from all buttons
                viewToggle.querySelectorAll('.btn').forEach(b => b.classList.remove('active'));
                
                // Add active class to clicked button
                this.classList.add('active');
                
                // Update view
                const view = this.getAttribute('data-view');
                
                // Clear existing view classes first
                accountsList.classList.remove('mobile-compact-view', 'grid-view');
                
                if (view === 'compact') {
                    accountsList.classList.add('mobile-compact-view');
                    console.log("Switched to compact view");
                } else if (view === 'grid') {
                    accountsList.classList.add('grid-view');
                    console.log("Switched to grid view");
                } else {
                    console.log("Switched to standard view");
                }
                
                // Save preference
                localStorage.setItem('2fa_view_preference', view);
                
                // Force re-render of accounts to ensure proper layout
                renderAccounts();
            });
        });
        
        // Update view toggle visibility on resize
        window.addEventListener('resize', function() {
            // Always keep view toggle visible, but adjust compact view on larger screens
            if (window.innerWidth > 576) {
                accountsList.classList.remove('mobile-compact-view');
            }
        });
        
        if (!isOnline) {
            updateSyncStatus('offline', 'You are offline. Changes will sync when connection is restored', 'fa-wifi-slash');
        }
        
        // Load saved view preference
        const savedView = localStorage.getItem('2fa_view_preference');
        if (savedView) {
            changeViewMode(savedView);
        }
        
        // Add PWA install support
        let deferredPrompt;
        const installPWABtn = document.getElementById('installPWA');
        
        window.addEventListener('beforeinstallprompt', (e) => {
            // Prevent the mini-infobar from appearing on mobile
            e.preventDefault();
            // Stash the event so it can be triggered later
            deferredPrompt = e;
            // Update UI to notify the user they can install the PWA
            installPWABtn.style.display = 'block';
            
            installPWABtn.addEventListener('click', () => {
                // Hide our user interface that shows our A2HS button
                installPWABtn.style.display = 'none';
                // Show the prompt
                deferredPrompt.prompt();
                // Wait for the user to respond to the prompt
                deferredPrompt.userChoice.then((choiceResult) => {
                    if (choiceResult.outcome === 'accepted') {
                        console.log('User accepted the A2HS prompt');
                        showAlert('App installed successfully!', 'success');
                } else {
                        console.log('User dismissed the A2HS prompt');
                    }
                    deferredPrompt = null;
                });
            });
        });
        
        // Handle installed state
        window.addEventListener('appinstalled', () => {
            // Hide the app-provided install promotion
            installPWABtn.style.display = 'none';
            deferredPrompt = null;
            console.log('PWA was installed');
        });
        
        // Check if app is already installed
        if (window.matchMedia('(display-mode: standalone)').matches) {
            console.log('App is running in standalone mode');
            installPWABtn.style.display = 'none';
        }
        
        // Add a service worker if file exists
        if ('serviceWorker' in navigator) {
            window.addEventListener('load', () => {
                navigator.serviceWorker.register('/sw.js')
                    .then(registration => {
                        console.log('ServiceWorker registration successful');
                    })
                    .catch(error => {
                        console.log('ServiceWorker registration failed: ', error);
                    });
            });
        }
    } catch (e) {
        console.error("Initialization error:", e);
    }

    // Update icon when service type changes
    serviceTypeSelect.addEventListener('change', function() {
        const service = this.value;
        const iconClass = SERVICE_ICONS[service] || SERVICE_ICONS.default;
        const iconPrefix = ['google', 'facebook', 'github', 'twitter', 'microsoft', 'apple', 'amazon', 
              'dropbox', 'slack', 'discord', 'linkedin', 'paypal', 'steam', 'gitlab', 
              'wordpress', 'bitbucket'].includes(service) ? 'fab' : 'fas';
        
        // Update the small icon in the input group
        selectedServiceIcon.innerHTML = `<i class="${iconPrefix} ${iconClass}"></i>`;
        
        // Update the large preview icon
        const serviceIconPreview = document.getElementById('serviceIconPreview');
        serviceIconPreview.innerHTML = `<i class="${iconPrefix} ${iconClass} fa-2x"></i>`;
        
        // Add animation class
        serviceIconPreview.classList.add('service-selected');
        
        // Remove animation class after transition completes
        setTimeout(() => {
            serviceIconPreview.classList.remove('service-selected');
        }, 500);
        
        // If service is selected, try to pre-fill the account name if it's empty
        if (service !== 'default' && service !== 'other' && accountNameInput.value.trim() === '') {
            accountNameInput.value = service.charAt(0).toUpperCase() + service.slice(1);
        }
    });

    // Pin/Unpin an account
    function togglePinAccount(id) {
        if (!currentUser) {
            showAlert('You must be logged in to pin accounts', 'error');
            return;
        }
        
        const userId = currentUser.uid;
        const accountToToggle = accounts.find(a => a.id === id);
        
        if (!accountToToggle) {
            showAlert('Account not found', 'error');
            return;
        }
        
        const isPinned = accountToToggle.pinned;
        const newPinStatus = !isPinned;
        
        // If offline, store operation
        if (!isOnline) {
            // Update local data first
            accountToToggle.pinned = newPinStatus;
            
            // Store the operation to be executed when back online
            addPendingOperation('update', { 
                id, 
                userId, 
                updates: { pinned: newPinStatus }
            });
            
            // Update UI and show message
            renderAccounts();
            updateSyncStatus('offline', 'Pin status will be synced when back online', 'fa-wifi-slash');
            showAlert(`Account ${newPinStatus ? 'pinned' : 'unpinned'}. It will sync when connection is restored.`, 'warning');
            return;
        }
        
        // Update the pinned status
        db.collection('users').doc(userId)
            .collection('accounts').doc(id)
            .update({ pinned: newPinStatus })
            .then(() => {
                // Update our local data
                accountToToggle.pinned = newPinStatus;
                
                // Update UI
                renderAccounts();
                showAlert(`Account ${newPinStatus ? 'pinned' : 'unpinned'}`, 'success');
            })
            .catch((error) => {
                console.error(`Error updating pin status for account ${id}:`, error);
                
                // If failed and we're online, store for later retry
                addPendingOperation('update', { 
                    id, 
                    userId, 
                    updates: { pinned: newPinStatus }
                });
                
                showAlert('Failed to update pin status: ' + error.message, 'error');
                updateSyncStatus('error', 'Failed to update pin status');
            });
    }

    // Google Drive API integration
    const authorizeGDriveBtn = document.getElementById('authorizeGDriveBtn');
    const enableBackupSwitch = document.getElementById('enableBackupSwitch');
    const backupFrequency = document.getElementById('backupFrequency');
    const maxBackupFiles = document.getElementById('maxBackupFiles');
    const saveBackupSettingsBtn = document.getElementById('saveBackupSettingsBtn');
    const backupNowBtn = document.getElementById('backupNowBtn');
    const gDriveConnected = document.getElementById('gDriveConnected');
    
    // Google auth variables
    let tokenClient;
    let gapiInited = false;
    let gisInited = false;
    let isGDriveAuthorized = false;
    let backupSchedule = null;
    
    // Backup settings
    let backupSettings = {
        enabled: false,
        frequency: 'weekly',
        maxFiles: 3,
        lastBackup: null,
        folderId: null
    };
    
    // Initialize the backup settings
    function initBackupSettings() {
        // Load backup settings from localStorage
        const savedSettings = localStorage.getItem(BACKUP_SETTINGS_KEY);
        if (savedSettings) {
            try {
                const parsedSettings = JSON.parse(savedSettings);
                backupSettings = { ...backupSettings, ...parsedSettings };
            } catch (e) {
                console.error('Error parsing backup settings:', e);
            }
        }
        
        // Update UI with saved settings
        enableBackupSwitch.checked = backupSettings.enabled;
        backupFrequency.value = backupSettings.frequency;
        maxBackupFiles.value = backupSettings.maxFiles.toString();
        
        // If backups are enabled, schedule them
        if (backupSettings.enabled && isGDriveAuthorized) {
            scheduleBackup();
        }
    }
    
    // Save backup settings
    function saveBackupSettings() {
        backupSettings.enabled = enableBackupSwitch.checked;
        backupSettings.frequency = backupFrequency.value;
        backupSettings.maxFiles = parseInt(maxBackupFiles.value);
        
        // Save to localStorage
        localStorage.setItem(BACKUP_SETTINGS_KEY, JSON.stringify(backupSettings));
        
        // If enabled and authorized, schedule backup
        if (backupSettings.enabled && isGDriveAuthorized) {
            scheduleBackup();
        } else {
            // Cancel any existing schedule
            if (backupSchedule) {
                clearTimeout(backupSchedule);
                backupSchedule = null;
            }
        }
        
        showAlert('Backup settings saved!', 'success');
    }
    
    // Schedule automatic backup based on frequency
    function scheduleBackup() {
        // Cancel any existing schedule
        if (backupSchedule) {
            clearTimeout(backupSchedule);
            backupSchedule = null;
        }
        
        if (!backupSettings.enabled || !isGDriveAuthorized) {
            return;
        }
        
        // Calculate next backup time
        let nextBackupTime;
        const now = new Date();
        const lastBackup = backupSettings.lastBackup ? new Date(backupSettings.lastBackup) : null;
        
        if (!lastBackup) {
            // If never backed up, schedule for soon (5 minutes)
            nextBackupTime = new Date(now.getTime() + 5 * 60 * 1000);
        } else {
            // Calculate based on frequency
            switch (backupSettings.frequency) {
                case 'daily':
                    nextBackupTime = new Date(lastBackup);
                    nextBackupTime.setDate(nextBackupTime.getDate() + 1);
                    break;
                case 'weekly':
                    nextBackupTime = new Date(lastBackup);
                    nextBackupTime.setDate(nextBackupTime.getDate() + 7);
                    break;
                case 'monthly':
                    nextBackupTime = new Date(lastBackup);
                    nextBackupTime.setMonth(nextBackupTime.getMonth() + 1);
                    break;
                default:
                    nextBackupTime = new Date(lastBackup);
                    nextBackupTime.setDate(nextBackupTime.getDate() + 7); // Default to weekly
            }
        }
        
        // If next backup time is in the past, schedule for soon
        if (nextBackupTime < now) {
            nextBackupTime = new Date(now.getTime() + 5 * 60 * 1000);
        }
        
        // Calculate delay in milliseconds
        const delay = nextBackupTime.getTime() - now.getTime();
        
        console.log(`Scheduled next backup for: ${nextBackupTime.toLocaleString()}`);
        
        // Schedule the backup
        backupSchedule = setTimeout(() => {
            console.log('Running scheduled backup...');
            performBackup()
                .then(() => {
                    // Schedule the next backup after this one completes
                    scheduleBackup();
                })
                .catch(error => {
                    console.error('Scheduled backup failed:', error);
                    // Try again later even if it failed
                    scheduleBackup();
                });
        }, delay);
    }
    
    // Initialize Google API client
    function initGapiClient() {
        gapi.client.init({
            apiKey: window.getGoogleDriveConfig().apiKey,
            discoveryDocs: window.getGoogleDriveConfig().discoveryDocs,
        }).then(() => {
            gapiInited = true;
            maybeEnableButtons();
        }).catch(error => {
            console.error('Error initializing GAPI client:', error);
            showAlert('Failed to initialize Google API', 'error');
        });
    }
    
    // Initialize Google Identity Services
    function initGisClient() {
        tokenClient = google.accounts.oauth2.initTokenClient({
            client_id: window.getGoogleDriveConfig().clientId,
            scope: window.getGoogleDriveConfig().scopes,
            callback: '', // Will be set later
        });
        gisInited = true;
        maybeEnableButtons();
    }
    
    // Enable buttons if APIs are initialized
    function maybeEnableButtons() {
        if (gapiInited && gisInited) {
            authorizeGDriveBtn.disabled = false;
            
            // Check if already authorized
            if (gapi.client.getToken() !== null) {
                isGDriveAuthorized = true;
                updateGDriveAuthUI(true);
                
                // Initialize backup settings
                initBackupSettings();
            }
        }
    }
    
    // Update Google Drive authorization UI
    function updateGDriveAuthUI(isAuthorized) {
        if (isAuthorized) {
            authorizeGDriveBtn.textContent = 'Disconnect Google Drive';
            authorizeGDriveBtn.classList.remove('btn-primary');
            authorizeGDriveBtn.classList.add('btn-outline-secondary');
            gDriveConnected.style.display = 'block';
            
            // Enable backup form
            document.querySelectorAll('#backupSettingsForm input, #backupSettingsForm select').forEach(el => {
                el.disabled = false;
            });
            
            saveBackupSettingsBtn.disabled = false;
            backupNowBtn.disabled = false;
        } else {
            authorizeGDriveBtn.textContent = 'Connect Google Drive';
            authorizeGDriveBtn.classList.remove('btn-outline-secondary');
            authorizeGDriveBtn.classList.add('btn-primary');
            gDriveConnected.style.display = 'none';
            
            // Disable backup form
            document.querySelectorAll('#backupSettingsForm input, #backupSettingsForm select').forEach(el => {
                el.disabled = true;
            });
            
            saveBackupSettingsBtn.disabled = true;
            backupNowBtn.disabled = true;
        }
    }
    
    // Authorize Google Drive 
    function handleAuthClick() {
        if (!isGDriveAuthorized) {
            // Request authorization
            tokenClient.callback = async (resp) => {
                if (resp.error !== undefined) {
                    console.error('Google authorization error:', resp);
                    showAlert('Google Drive authorization failed', 'error');
                    return;
                }
                
                isGDriveAuthorized = true;
                updateGDriveAuthUI(true);
                showAlert('Connected to Google Drive!', 'success');
                
                // Create backup folder if it doesn't exist
                ensureBackupFolder()
                    .then(() => {
                        // Initialize backup settings
                        initBackupSettings();
                    })
                    .catch(error => {
                        console.error('Error creating backup folder:', error);
                        showAlert('Failed to create backup folder', 'error');
                    });
            };
            
            // Prompt the user to select an account
            if (gapi.client.getToken() === null) {
                tokenClient.requestAccessToken({ prompt: 'consent' });
            } else {
                tokenClient.requestAccessToken({ prompt: '' });
            }
        } else {
            // Revoke authorization
            const token = gapi.client.getToken();
            if (token !== null) {
                google.accounts.oauth2.revoke(token.access_token, () => {
                    gapi.client.setToken('');
                    isGDriveAuthorized = false;
                    updateGDriveAuthUI(false);
                    showAlert('Disconnected from Google Drive', 'success');
                    
                    // Cancel any scheduled backup
                    if (backupSchedule) {
                        clearTimeout(backupSchedule);
                        backupSchedule = null;
                    }
                });
            }
        }
    }
    
    // Create a folder for backups if it doesn't exist
    async function ensureBackupFolder() {
        if (backupSettings.folderId) {
            // Check if folder still exists
            try {
                const response = await gapi.client.drive.files.get({
                    fileId: backupSettings.folderId,
                    fields: 'id, name'
                });
                
                console.log('Backup folder exists:', response.result);
                return backupSettings.folderId;
            } catch (error) {
                console.log('Backup folder not found, creating new one');
                // Folder not found, create a new one
            }
        }
        
        // Create a new folder
        const folderMetadata = {
            name: '2FA Manager Backups',
            mimeType: 'application/vnd.google-apps.folder'
        };
        
        try {
            const response = await gapi.client.drive.files.create({
                resource: folderMetadata,
                fields: 'id'
            });
            
            const folderId = response.result.id;
            backupSettings.folderId = folderId;
            
            // Save updated settings
            localStorage.setItem(BACKUP_SETTINGS_KEY, JSON.stringify(backupSettings));
            
            console.log('Backup folder created with ID:', folderId);
            return folderId;
        } catch (error) {
            console.error('Error creating backup folder:', error);
            throw error;
        }
    }
    
    // Create export data for backup
    function createBackupData() {
        // Get accounts data from global variable
        const backupAccounts = window.accountsForBackup || [];
        
        console.log("Creating backup with accounts:", backupAccounts.length);
        
        if (backupAccounts.length === 0) {
            console.warn("No accounts found for backup!");
            alert("No accounts found to backup. Please make sure you have added some 2FA accounts.");
        }
        
        // Tạo mảng đơn giản chỉ chứa thông tin tài khoản
        return JSON.stringify(backupAccounts.map(account => ({
            id: account.id,
            name: account.name,
            secret: account.secret,
            service: account.service || 'default',
            pinned: account.pinned || false
        })), null, 2);
    }
    
    // Perform backup to Google Drive
    async function performBackup() {
        console.log("Performing backup");
        
        // Return a promise to handle completion
        return new Promise(async (resolve, reject) => {
            try {
                if (!gapi.client.getToken()) {
                    alert("Please connect to Google Drive first");
                    return reject(new Error("Not connected to Google Drive"));
                }
            
            // Kiểm tra đăng nhập Firebase
            if (!firebase.auth().currentUser) {
                alert("Please sign in to your account first");
                return;
            }
            
            // alert("Starting backup. Please wait...");
            
            // Lấy dữ liệu tài khoản trực tiếp từ Firestore
            const userId = firebase.auth().currentUser.uid;
            console.log("Getting accounts for user:", userId);
            
            const snapshot = await firebase.firestore()
                .collection('users').doc(userId)
                .collection('accounts')
                .get();
            
            const accountsToBackup = [];
            snapshot.forEach(doc => {
                const account = doc.data();
                
                // Giải mã secret từ dạng mã hóa
                let decryptedSecret = account.secret;
                try {
                    // Sử dụng userId làm key để giải mã (tương tự như khi mã hóa)
                    const key = CryptoJS.SHA256(userId).toString();
                    const bytes = CryptoJS.AES.decrypt(account.secret, key);
                    decryptedSecret = bytes.toString(CryptoJS.enc.Utf8);
                    
                    // Nếu giải mã không thành công hoặc kết quả trống, giữ lại giá trị mã hóa
                    if (!decryptedSecret) {
                        decryptedSecret = account.secret;
                        console.warn("Failed to decrypt secret for account:", account.name);
                    } else {
                        console.log("Successfully decrypted secret for account:", account.name);
                    }
                } catch (error) {
                    console.error("Error decrypting secret for account:", account.name, error);
                    // Giữ lại giá trị gốc nếu có lỗi
                    decryptedSecret = account.secret;
                }
                
                accountsToBackup.push({
                    id: doc.id,
                    name: account.name,
                    secret: decryptedSecret,
                    service: account.service || 'default',
                    pinned: account.pinned || false
                });
            });
            
            console.log("Found accounts to backup:", accountsToBackup.length);
            
            if (accountsToBackup.length === 0) {
                alert("No accounts found to backup");
                return;
            }
            
            // Tạo dữ liệu backup (mảng tài khoản)
            const backupData = JSON.stringify(accountsToBackup, null, 2);
            console.log("Backup data created, length:", backupData.length);
            
            // Ensure we have a folder
            const folderId = await ensureBackupFolder();
            
            // Create file metadata
            const timestamp = new Date().toISOString().replace(/:/g, '-').split('.')[0];
            const fileName = `2fa-backup-${timestamp}.json`;
            
            const fileMetadata = {
                name: fileName,
                parents: [folderId]
            };
            
            // Create file content
            const file = new Blob([backupData], { type: 'application/json' });
            
            // Prepare form data
            const form = new FormData();
            form.append('metadata', new Blob([JSON.stringify(fileMetadata)], { type: 'application/json' }));
            form.append('file', file);
            
            // Upload the file
            const token = gapi.client.getToken();
            const response = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart', {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${token.access_token}`
                },
                body: form
            });
            
            if (!response.ok) {
                throw new Error(`Upload failed: ${response.status} ${response.statusText}`);
            }
            
            const result = await response.json();
            console.log("Backup created:", result);
            
            // Update settings with last backup time
            const settingsStr = localStorage.getItem('2fa_backup_settings');
            if (settingsStr) {
                const settings = JSON.parse(settingsStr);
                settings.lastBackup = new Date().toISOString();
                localStorage.setItem('2fa_backup_settings', JSON.stringify(settings));
            }
            
            // Show success popup
            const successTimestamp = new Date().toLocaleString();
            document.getElementById('backupSuccessInfo').textContent = `Backup created on: ${successTimestamp}`;
            const successModal = new bootstrap.Modal(document.getElementById('backupSuccessModal'));
            successModal.show();
            
            // Resolve the promise on success
            resolve();
        } catch (error) {
            console.error("Backup failed:", error);
            alert(`Backup failed: ${error.message}`);
            
            // Reject the promise on failure
            reject(error);
        }
    });
    }
    
    // Clean up old backups
    async function cleanupOldBackups() {
        if (!isGDriveAuthorized || !backupSettings.folderId) {
            return;
        }
        
        try {
            // List all backup files
            const response = await gapi.client.drive.files.list({
                q: `'${backupSettings.folderId}' in parents and mimeType='application/json'`,
                fields: 'files(id, name, createdTime)',
                orderBy: 'createdTime desc'
            });
            
            const files = response.result.files;
            console.log('Found backups:', files.length);
            
            // Keep only the desired number of recent backups
            if (files.length > backupSettings.maxFiles) {
                const filesToDelete = files.slice(backupSettings.maxFiles);
                
                for (const file of filesToDelete) {
                    try {
                        await gapi.client.drive.files.delete({
                            fileId: file.id
                        });
                        console.log('Deleted old backup:', file.name);
                    } catch (deleteError) {
                        console.error('Error deleting old backup:', deleteError);
                    }
                }
            }
        } catch (error) {
            console.error('Error cleaning up old backups:', error);
        }
    }
    
    // Load Google API and initialize
    function loadGoogleApi() {
        gapi.load('client', initGapiClient);
    }
    
    // Event listeners for backup functionality
    backupSettingsBtn.addEventListener('click', function() {
        backupSettingsModal.show();
        
        if (!gapiInited) {
            loadGoogleApi();
        }
        
        if (!gisInited) {
            initGisClient();
        }
    });
    
    authorizeGDriveBtn.addEventListener('click', handleAuthClick);
    
    saveBackupSettingsBtn.addEventListener('click', function() {
        saveBackupSettings();
    });
    
    backupNowBtn.addEventListener('click', function() {
        // Disable button and show loading state
        this.disabled = true;
        const originalText = this.innerHTML;
        this.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Backing up...';
        
        // Store reference to button for re-enabling later
        const buttonEl = this;
        
        // Start backup with callback to restore button state
        performBackup().finally(function() {
            // Re-enable button and restore original text
            buttonEl.disabled = false;
            buttonEl.innerHTML = originalText;
        });
    });
    
    // Add keyboard shortcut for backup settings (Ctrl+B or Cmd+B)
    document.addEventListener('keydown', function(e) {
        // Check if Ctrl+B or Cmd+B is pressed and main app is visible
        if ((e.ctrlKey || e.metaKey) && e.key === 'b' && mainApp.style.display !== 'none') {
            e.preventDefault(); // Prevent default browser behavior
            backupSettingsModal.show();
            
            if (!gapiInited) {
                loadGoogleApi();
            }
            
            if (!gisInited) {
                initGisClient();
            }
        }
    });
    
    // Add event listeners for edit and delete
});

// Function to change view mode
function changeViewMode(viewMode) {
    console.log("Changing view mode to:", viewMode);
    
    // Update UI buttons
    const viewBtns = document.querySelectorAll('.view-toggle .btn');
    viewBtns.forEach(btn => {
        if (btn.getAttribute('data-view') === viewMode) {
            btn.classList.add('active');
            btn.setAttribute('aria-pressed', 'true');
            } else {
            btn.classList.remove('active');
            btn.setAttribute('aria-pressed', 'false');
        }
    });
    
    // Get accounts list element
    const accountsList = document.getElementById('accountsList');
    
    // Remove existing view classes
    accountsList.classList.remove('mobile-compact-view', 'grid-view');
    
    // Apply new view class
    if (viewMode === 'grid') {
        accountsList.classList.add('grid-view');
    } else if (viewMode === 'compact') {
        accountsList.classList.add('mobile-compact-view');
    }
    
    // Save preference
    localStorage.setItem('2fa_view_preference', viewMode);
    
    // Force re-render accounts if needed
    if (typeof renderAccounts === 'function' && accounts && accounts.length > 0) {
        renderAccounts();
    }
}

// Add direct click handler for the Google Drive authorization button
document.addEventListener('DOMContentLoaded', function() {
    const authorizeButton = document.getElementById('authorizeGDriveBtn');
    const saveSettingsButton = document.getElementById('saveBackupSettingsBtn');
    const backupNowButton = document.getElementById('backupNowBtn');

    if (authorizeButton) {
        authorizeButton.addEventListener('click', function() {
            console.log("Authorize button clicked");
            if (!window.gapiInited || !window.gisInited) {
                console.log("APIs not initialized yet, initializing...");
                window.initializeGoogleApis();
                setTimeout(handleAuth, 1000); // Try again after a delay
            } else {
                handleAuth();
            }
        });
    }

    // Add event listener for Save Settings button
    if (saveSettingsButton) {
        saveSettingsButton.addEventListener('click', function() {
            console.log("Save Settings button clicked");
            saveBackupSettings();
        });
    }

    // Add event listener for Backup Now button
    if (backupNowButton) {
        backupNowButton.addEventListener('click', function() {
            console.log("Backup Now button clicked");
            
            // Disable button and show loading state
            this.disabled = true;
            const originalText = this.innerHTML;
            this.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Backing up...';
            
            // Store reference to button for re-enabling later
            const buttonEl = this;
            
            // Start backup with callback to restore button state
            backupNowToGoogleDrive().finally(function() {
                // Re-enable button and restore original text
                buttonEl.disabled = false;
                buttonEl.innerHTML = originalText;
            });
        });
    }
    
    // Hàm sao lưu mới lấy dữ liệu trực tiếp từ Firestore
    async function backupNowToGoogleDrive() {
        console.log("Starting direct backup to Google Drive");
        
        // Return a promise so we can handle completion
        return new Promise(async (resolve, reject) => {
            try {
                if (!gapi.client.getToken()) {
                    alert("Please connect to Google Drive first");
                    return reject(new Error("Not connected to Google Drive"));
                }
                
                // Kiểm tra đăng nhập Firebase
                if (!firebase.auth().currentUser) {
                    alert("Please sign in to your account first");
                    return reject(new Error("Not signed in"));
                }
            
            // alert("Starting backup. Please wait...");
            
            // Lấy dữ liệu tài khoản trực tiếp từ Firestore
            const userId = firebase.auth().currentUser.uid;
            console.log("Getting accounts for user:", userId);
            
            const snapshot = await firebase.firestore()
                .collection('users').doc(userId)
                .collection('accounts')
                .get();
            
            const accountsToBackup = [];
            snapshot.forEach(doc => {
                const account = doc.data();
                
                // Giải mã secret từ dạng mã hóa
                let decryptedSecret = account.secret;
                try {
                    // Sử dụng userId làm key để giải mã (tương tự như khi mã hóa)
                    const key = CryptoJS.SHA256(userId).toString();
                    const bytes = CryptoJS.AES.decrypt(account.secret, key);
                    decryptedSecret = bytes.toString(CryptoJS.enc.Utf8);
                    
                    // Nếu giải mã không thành công hoặc kết quả trống, giữ lại giá trị mã hóa
                    if (!decryptedSecret) {
                        decryptedSecret = account.secret;
                        console.warn("Failed to decrypt secret for account:", account.name);
                    } else {
                        console.log("Successfully decrypted secret for account:", account.name);
                    }
                } catch (error) {
                    console.error("Error decrypting secret for account:", account.name, error);
                    // Giữ lại giá trị gốc nếu có lỗi
                    decryptedSecret = account.secret;
                }
                
                accountsToBackup.push({
                    id: doc.id,
                    name: account.name,
                    secret: decryptedSecret,
                    service: account.service || 'default',
                    pinned: account.pinned || false
                });
            });
            
            console.log("Found accounts to backup:", accountsToBackup.length);
            
            if (accountsToBackup.length === 0) {
                alert("No accounts found to backup");
                return;
            }
            
            // Tạo dữ liệu backup (mảng tài khoản)
            const backupData = JSON.stringify(accountsToBackup, null, 2);
            console.log("Backup data created, length:", backupData.length);
            
            // Ensure we have a folder
            const folderId = await ensureBackupFolder();
            
            // Create file metadata
            const timestamp = new Date().toISOString().replace(/:/g, '-').split('.')[0];
            const fileName = `2fa-backup-${timestamp}.json`;
            
            const fileMetadata = {
                name: fileName,
                parents: [folderId]
            };
            
            // Create file content
            const file = new Blob([backupData], { type: 'application/json' });
            
            // Prepare form data
            const form = new FormData();
            form.append('metadata', new Blob([JSON.stringify(fileMetadata)], { type: 'application/json' }));
            form.append('file', file);
            
            // Upload the file
            const token = gapi.client.getToken();
            const response = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart', {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${token.access_token}`
                },
                body: form
            });
            
            if (!response.ok) {
                throw new Error(`Upload failed: ${response.status} ${response.statusText}`);
            }
            
            const result = await response.json();
            console.log("Backup created:", result);
            
            // Update settings with last backup time
            const settingsStr = localStorage.getItem('2fa_backup_settings');
            if (settingsStr) {
                const settings = JSON.parse(settingsStr);
                settings.lastBackup = new Date().toISOString();
                localStorage.setItem('2fa_backup_settings', JSON.stringify(settings));
            }
            
            // Show success popup
            const backupTimestamp = new Date().toLocaleString();
            document.getElementById('backupSuccessInfo').textContent = `Backup created on: ${backupTimestamp}`;
            const successModal = new bootstrap.Modal(document.getElementById('backupSuccessModal'));
            successModal.show();
            
            // Resolve the promise on success
            resolve();
        } catch (error) {
            console.error("Backup failed:", error);
            
            // Reject the promise on failure
            reject(error);
            alert(`Backup failed: ${error.message}`);
        }
    });
    }
    
    function saveBackupSettings() {
        console.log("Saving backup settings");
        
        // Get form values
        const enableBackupSwitch = document.getElementById('enableBackupSwitch');
        const backupFrequency = document.getElementById('backupFrequency');
        const maxBackupFiles = document.getElementById('maxBackupFiles');
        
        // Create settings object
        const settings = {
            enabled: enableBackupSwitch.checked,
            frequency: backupFrequency.value,
            maxFiles: parseInt(maxBackupFiles.value),
            lastBackup: null, // Will be set on first backup
            folderId: window.backupFolderId || null
        };
        
        // Save to localStorage
        localStorage.setItem('2fa_backup_settings', JSON.stringify(settings));
        
        // Schedule backup if enabled
        if (settings.enabled) {
            console.log("Scheduling backup with frequency:", settings.frequency);
            // Here you would schedule the backup based on frequency
        }
        
        alert('Backup settings saved!');
    }
    
    async function ensureBackupFolder() {
        // Check if we already have a folder ID stored
        const settingsStr = localStorage.getItem('2fa_backup_settings');
        if (settingsStr) {
            const settings = JSON.parse(settingsStr);
            if (settings.folderId) {
                // Verify folder still exists
                try {
                    const response = await gapi.client.drive.files.get({
                        fileId: settings.folderId,
                        fields: 'id,name'
                    });
                    console.log("Found existing backup folder:", response.result);
                    return settings.folderId;
                } catch (error) {
                    console.log("Folder not found, will create new one");
                }
            }
        }
        
        // Create a new folder
        const folderMetadata = {
            name: '2FA Manager Backups',
            mimeType: 'application/vnd.google-apps.folder'
        };
        
        const response = await gapi.client.drive.files.create({
            resource: folderMetadata,
            fields: 'id'
        });
        
        const folderId = response.result.id;
        console.log("Created backup folder:", folderId);
        
        // Store the folder ID
        window.backupFolderId = folderId;
        
        // Update settings
        if (settingsStr) {
            const settings = JSON.parse(settingsStr);
            settings.folderId = folderId;
            localStorage.setItem('2fa_backup_settings', JSON.stringify(settings));
        } else {
            const settings = {
                enabled: false,
                frequency: 'weekly',
                maxFiles: 3,
                lastBackup: null,
                folderId: folderId
            };
            localStorage.setItem('2fa_backup_settings', JSON.stringify(settings));
        }
        
        return folderId;
    }
    
    function createBackupData() {
        // Mock accounts data for testing
        // In the real app, you would get this from your accounts array
        const mockAccounts = window.accounts || [];
        
        // Tạo mảng đơn giản chỉ chứa thông tin tài khoản
        return JSON.stringify(mockAccounts.map(account => ({
            id: account.id,
            name: account.name,
            secret: account.secret,
            service: account.service || 'default',
            pinned: account.pinned || false
        })), null, 2);
    }
    
    function handleAuth() {
        console.log("Handling authorization");
        // Check if we're already authorized
        const token = gapi.client.getToken();
        
        if (token === null) {
            // Not authorized yet, request access
            console.log("Requesting access token with prompt");
            window.tokenClient.requestAccessToken({ prompt: 'consent' });
        } else {
            // Already authorized, revoke access
            console.log("Already authorized, revoking access");
            google.accounts.oauth2.revoke(token.access_token, function() {
                gapi.client.setToken('');
                console.log("Access revoked");
                
                // Update UI to show disconnected state
                document.getElementById('gDriveConnected').style.display = 'none';
                document.getElementById('authorizeGDriveBtn').textContent = 'Connect Google Drive';
                document.getElementById('authorizeGDriveBtn').classList.remove('btn-outline-secondary');
                document.getElementById('authorizeGDriveBtn').classList.add('btn-primary');
                
                // Disable form fields
                document.querySelectorAll('#backupSettingsForm input, #backupSettingsForm select').forEach(function(el) {
                    el.disabled = true;
                });
                
                document.getElementById('saveBackupSettingsBtn').disabled = true;
                document.getElementById('backupNowBtn').disabled = true;
                
                alert("Disconnected from Google Drive");
            });
        }
    }
});

// Make accounts globally accessible for backup purposes
window.makeAccountsGlobalForBackup = function(accountsData) {
    window.accountsForBackup = accountsData;
    console.log("Accounts data made available for backup:", window.accountsForBackup.length);
};
