import React, { useState, useEffect } from 'react';
import * as bootstrap from 'bootstrap';

export const AddAccountModal = ({ show, onClose, onSave, editingAccount, SERVICE_ICONS, decryptSecret, generateTOTP, showAlert }) => {
    const [serviceType, setServiceType] = useState('default');
    const [accountName, setAccountName] = useState('');
    const [secretKey, setSecretKey] = useState('');
    const [pinAccount, setPinAccount] = useState(false);
    const modalRef = React.useRef(null);
    const bsModalRef = React.useRef(null);

    useEffect(() => {
        if (editingAccount) {
            setServiceType(editingAccount.service || 'default');
            setAccountName(editingAccount.name);
            setSecretKey(decryptSecret(editingAccount.secret));
            setPinAccount(editingAccount.pinned || false);
        } else {
            setServiceType('default');
            setAccountName('');
            setSecretKey('');
            setPinAccount(false);
        }
    }, [editingAccount, decryptSecret]);

    useEffect(() => {
        const modalElement = modalRef.current;
        if (modalElement) {
            bsModalRef.current = new bootstrap.Modal(modalElement);
            modalElement.addEventListener('hidden.bs.modal', onClose);
        }
        return () => {
            if (modalElement) {
                modalElement.removeEventListener('hidden.bs.modal', onClose);
            }
        };
    }, [onClose]);

    useEffect(() => {
        if (bsModalRef.current) {
            if (show) {
                bsModalRef.current.show();
            } else {
                bsModalRef.current.hide();
            }
        }
    }, [show]);

    const handleSubmit = () => {
        if (!accountName.trim() || !secretKey.trim()) {
            showAlert('Please fill all required fields.', 'error');
            return;
        }
        try {
            generateTOTP(secretKey.trim()); // Validate secret
        } catch (e) {
            showAlert('Invalid secret key format', 'error');
            return;
        }

        if (editingAccount) {
            onSave(editingAccount.id, accountName.trim(), secretKey.trim(), serviceType, pinAccount);
        } else {
            onSave(accountName.trim(), secretKey.trim(), serviceType, pinAccount);
        }
        onClose();
    };

    const handlePasteSecret = async () => {
        try {
            const text = await navigator.clipboard.readText();
            setSecretKey(text.trim());
        } catch (err) {
            showAlert('Could not access clipboard', 'error');
        }
    };

    const iconClass = SERVICE_ICONS[serviceType] || SERVICE_ICONS.default;
    const iconPrefix = ['google', 'facebook', 'github', 'twitter', 'microsoft', 'apple', 'amazon',
        'dropbox', 'slack', 'discord', 'linkedin', 'paypal', 'steam', 'gitlab',
        'wordpress', 'bitbucket'].includes(serviceType) ? 'fab' : 'fas';

    return (
        <div className="modal fade" id="addAccountModal" tabIndex="-1" aria-hidden="true" ref={modalRef}>
            <div className="modal-dialog modal-dialog-centered">
                <div className="modal-content border-0 shadow">
                    <div className="modal-header bg-primary text-white" style={{ backgroundImage: 'var(--primary-gradient)' }}>
                        <h5 className="modal-title"><i className="fas fa-shield-alt me-2"></i>{editingAccount ? 'Edit 2FA Account' : 'Add New 2FA Account'}</h5>
                        <button type="button" className="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close" onClick={onClose}></button>
                    </div>
                    <div className="modal-body p-4">
                        <div className="text-center mb-4 add-account-icon">
                            <div className="account-icon-preview mb-2" id="serviceIconPreview">
                                <i className={`${iconPrefix} ${iconClass} fa-2x`}></i>
                            </div>
                        </div>

                        <form id="addAccountForm">
                            <div className="mb-3">
                                <label htmlFor="serviceType" className="form-label">Service Type</label>
                                <div className="input-group">
                                    <span className="input-group-text" id="selectedServiceIcon"><i className={`${iconPrefix} ${iconClass}`}></i></span>
                                    <select className="form-select" id="serviceType" value={serviceType} onChange={(e) => {
                                        setServiceType(e.target.value);
                                        if (e.target.value !== 'default' && e.target.value !== 'other' && accountName.trim() === '') {
                                            setAccountName(e.target.value.charAt(0).toUpperCase() + e.target.value.slice(1));
                                        }
                                    }}>
                                        <option value="default">Select service...</option>
                                        {Object.keys(SERVICE_ICONS).map(key => (
                                            key !== 'default' && key !== 'other' && (
                                                <option key={key} value={key}>{key.charAt(0).toUpperCase() + key.slice(1)}</option>
                                            )
                                        ))}
                                        <option value="other">Other</option>
                                    </select>
                                </div>
                            </div>

                            <div className="mb-3">
                                <label htmlFor="accountName" className="form-label">Account Name</label>
                                <div className="input-group">
                                    <span className="input-group-text"><i className="fas fa-tag"></i></span>
                                    <input type="text" className="form-control" id="accountName" required placeholder="e.g. Work Email, Personal Account" value={accountName} onChange={(e) => setAccountName(e.target.value)} />
                                </div>
                            </div>

                            <div className="mb-4">
                                <label htmlFor="secretKey" className="form-label">Secret Key</label>
                                <div className="input-group">
                                    <span className="input-group-text"><i className="fas fa-key"></i></span>
                                    <input type="text" className="form-control" id="secretKey" required placeholder="Enter the secret key" value={secretKey} onChange={(e) => setSecretKey(e.target.value)} />
                                    <button className="btn btn-outline-primary" type="button" id="pasteSecretBtn" title="Paste from clipboard" style={{ backgroundImage: 'var(--primary-gradient)', color: 'white', border: 'none' }} onClick={handlePasteSecret}>
                                        <i className="fas fa-paste"></i>
                                    </button>
                                </div>
                                <small className="form-text text-muted mt-1">Enter the secret key provided by the service</small>
                            </div>

                            <div className="d-flex mb-3">
                                <div className="form-check form-switch ms-auto">
                                    <input className="form-check-input" type="checkbox" id="pinAccountSwitch" checked={pinAccount} onChange={(e) => setPinAccount(e.target.checked)} />
                                    <label className="form-check-label" htmlFor="pinAccountSwitch">
                                        <i className="fas fa-thumbtack me-1"></i> Pin this account
                                    </label>
                                </div>
                            </div>
                        </form>
                    </div>
                    <div className="modal-footer justify-content-between">
                        <button type="button" className="btn btn-light" data-bs-dismiss="modal" onClick={onClose}>Cancel</button>
                        <button type="button" className="btn btn-primary px-4" id="saveAccountBtn" onClick={handleSubmit}>
                            <i className="fas fa-check me-2"></i>{editingAccount ? 'Save Changes' : 'Add Account'}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};
