import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import reportWebVitals from './reportWebVitals';
import { getFirebaseConfig } from './config'; // Import Firebase config

const root = ReactDOM.createRoot(document.getElementById('root'));

// Function to initialize Firebase and render the app
const initializeAndRenderApp = () => {
  const firebaseConfig = getFirebaseConfig();
  if (firebaseConfig.unauthorized) {
    console.error('Unauthorized access to Firebase configuration');
    // Render an error message or handle appropriately
    root.render(
      <React.StrictMode>
        <div style={{ textAlign: 'center', padding: '50px', color: 'red' }}>
          Unauthorized access to Firebase. Please use an authorized domain.
        </div>
      </React.StrictMode>
    );
    return;
  }

  // Initialize Firebase if not already initialized
  if (window.firebase && !window.firebaseApp) {
    window.firebaseApp = window.firebase.initializeApp(firebaseConfig);
    window.firebase.firestore().enablePersistence()
      .then(() => console.log("Firestore persistence enabled from index.js"))
      .catch((err) => {
        if (err.code === 'failed-precondition') {
          console.log("Persistence failed: Multiple tabs open");
        } else if (err.code === 'unimplemented') {
          console.log("Persistence not supported by browser");
        }
      });
  }

  root.render(
    <React.StrictMode>
      <App />
    </React.StrictMode>
  );
};

// Load Firebase SDK scripts dynamically and then initialize/render
const loadFirebaseScripts = () => {
  const firebaseAppScript = document.createElement('script');
  firebaseAppScript.src = "https://www.gstatic.com/firebasejs/9.22.0/firebase-app-compat.js";
  firebaseAppScript.onload = () => {
    console.log('Firebase App loaded');
    const firebaseAuthScript = document.createElement('script');
    firebaseAuthScript.src = "https://www.gstatic.com/firebasejs/9.22.0/firebase-auth-compat.js";
    firebaseAuthScript.onload = () => {
      console.log('Firebase Auth loaded');
      const firestoreScript = document.createElement('script');
      firestoreScript.src = "https://www.gstatic.com/firebasejs/9.22.0/firebase-firestore-compat.js";
      firestoreScript.onload = () => {
        console.log('Firebase Firestore loaded');
        initializeAndRenderApp(); // Initialize Firebase and render app after all scripts are loaded
      };
      document.head.appendChild(firestoreScript);
    };
    document.head.appendChild(firebaseAuthScript);
  };
  document.head.appendChild(firebaseAppScript);
};

// Start loading Firebase scripts
loadFirebaseScripts();

reportWebVitals();
