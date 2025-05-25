import React, { useState, useEffect } from 'react';
import * as bootstrap from 'bootstrap';

export const RegisterModal = ({ show, onClose, onRegister, showAlert }) => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const modalRef = React.useRef(null);
    const bsModalRef = React.useRef(null);

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
        if (password !== confirmPassword) {
            showAlert('Passwords do not match', 'error');
            return;
        }
        onRegister(email, password);
    };

    return (
        <div className="modal fade" id="registerModal" tabIndex="-1" aria-hidden="true" ref={modalRef}>
            <div className="modal-dialog">
                <div className="modal-content">
                    <div className="modal-header">
                        <h5 className="modal-title">Create Account</h5>
                        <button type="button" className="btn-close" data-bs-dismiss="modal" aria-label="Close" onClick={onClose}></button>
                    </div>
                    <div className="modal-body">
                        <form id="registerForm">
                            <div className="mb-3">
                                <label htmlFor="regEmail" className="form-label">Email</label>
                                <input type="email" className="form-control" id="regEmail" required value={email} onChange={(e) => setEmail(e.target.value)} />
                            </div>
                            <div className="mb-3">
                                <label htmlFor="regPassword" className="form-label">Password</label>
                                <input type="password" className="form-control" id="regPassword" required minLength="8" value={password} onChange={(e) => setPassword(e.target.value)} />
                                <small className="form-text text-muted">Password must be at least 8 characters</small>
                            </div>
                            <div className="mb-3">
                                <label htmlFor="confirmPassword" className="form-label">Confirm Password</label>
                                <input type="password" className="form-control" id="confirmPassword" required value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} />
                            </div>
                        </form>
                    </div>
                    <div className="modal-footer">
                        <button type="button" className="btn btn-secondary" data-bs-dismiss="modal" onClick={onClose}>Cancel</button>
                        <button type="button" className="btn btn-primary" id="createAccountBtn" onClick={handleSubmit}>Create Account</button>
                    </div>
                </div>
            </div>
        </div>
    );
};
