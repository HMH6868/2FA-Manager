import React, { useState, useEffect } from 'react';

export const AccountItem = ({ account, generateTOTP, getTimeRemaining, SERVICE_ICONS, decryptSecret, onEditAccount, onDeleteAccount, togglePinAccount, isGridView, isCompactView }) => {
    const [token, setToken] = useState('');
    const [timeRemaining, setTimeRemaining] = useState(getTimeRemaining());

    useEffect(() => {
        const decryptedSecret = decryptSecret(account.secret);
        setToken(generateTOTP(decryptedSecret));

        const interval = setInterval(() => {
            const newTimeRemaining = getTimeRemaining();
            setTimeRemaining(newTimeRemaining);
            if (newTimeRemaining === 30) { // Regenerate token at the start of a new 30-second window
                setToken(generateTOTP(decryptedSecret));
            }
        }, 1000);

        return () => clearInterval(interval);
    }, [account.secret, decryptSecret, generateTOTP]);

    const progressValue = (timeRemaining / 30) * 100;
    const dashOffset = 251.2 - (251.2 * progressValue / 100);

    const tokenStyle = 'token-style-1'; // Fixed style
    let tokenHTML = token;
    if (tokenStyle === 'token-style-blocks' || tokenStyle === 'token-style-segmented') {
        tokenHTML = token.split('').map((digit, i) => <span key={i}>{digit}</span>);
    }

    const service = account.service || 'default';
    const iconClass = SERVICE_ICONS[service] || SERVICE_ICONS.default;
    const iconPrefix = ['google', 'facebook', 'github', 'twitter', 'microsoft', 'apple', 'amazon',
        'dropbox', 'slack', 'discord', 'linkedin', 'paypal', 'steam', 'gitlab',
        'wordpress', 'bitbucket'].includes(service) ? 'fab' : 'fas';

    const handleCopyClick = () => {
        navigator.clipboard.writeText(token)
            .then(() => alert('Code copied to clipboard!', 'success')) // Using native alert for now
            .catch(err => alert('Failed to copy code', 'error'));
    };

    return (
        <div className={`code-item d-flex align-items-center justify-content-between ${account.pinned ? 'pinned' : ''}`}>
            {account.pinned && <div className="pin-indicator"><i className="fas fa-thumbtack"></i></div>}
            <div className="token-container">
                <div className="account-header d-flex align-items-start mb-1">
                    <div className="account-icon me-2 mt-1">
                        <i className={`${iconPrefix} ${iconClass}`} style={{ color: '#4B97C5', fontSize: '1.2rem' }}></i>
                    </div>
                    <h5 className="mb-0 account-name" title={account.name}>
                        {account.name}
                    </h5>
                </div>
                <div className={`token ${tokenStyle}`} title="Click to copy" style={{ cursor: 'pointer' }} onClick={handleCopyClick}>
                    {tokenHTML}
                </div>
            </div>
            <div className="d-flex align-items-center actions-container">
                <button className="copy-btn" title="Copy code" onClick={handleCopyClick}>
                    <i className="fas fa-copy"></i>
                </button>
                <div className="progress-container">
                    <svg className="circular-progress" viewBox="0 0 100 100">
                        <circle className="progress-circle" cx="50" cy="50" r="40" />
                        <circle className="progress-value" cx="50" cy="50" r="40"
                            strokeDasharray="251.2"
                            strokeDashoffset={dashOffset} />
                    </svg>
                    <div className="time-remaining position-absolute top-50 start-50 translate-middle">
                        {timeRemaining}s
                    </div>
                </div>
                <div className="dropdown">
                    <button className="btn btn-sm btn-light" type="button" data-bs-toggle="dropdown">
                        <i className="fas fa-ellipsis-v"></i>
                    </button>
                    <ul className="dropdown-menu dropdown-menu-end">
                        <li><button className="dropdown-item pin-btn" onClick={() => togglePinAccount(account.id)}>
                            <i className="fas fa-thumbtack me-2"></i>{account.pinned ? 'Unpin' : 'Pin'}
                        </button></li>
                        <li><button className="dropdown-item edit-btn" onClick={() => onEditAccount(account)}>
                            <i className="fas fa-edit me-2"></i>Edit
                        </button></li>
                        <li><button className="dropdown-item delete-btn" onClick={() => onDeleteAccount(account.id)}>
                            <i className="fas fa-trash-alt me-2"></i>Delete
                        </button></li>
                    </ul>
                </div>
            </div>
        </div>
    );
};
