import React from 'react';
import { AccountItem } from './AccountItem'; // Assuming AccountItem is in a separate file now

const MainAppContent = ({
    userEmail, syncStatus, accounts, searchTerm, setSearchTerm, viewMode, changeViewMode,
    onAddAccountClick, onExportAccounts, onImportAccounts, onRefreshAccounts,
    onEditAccount, onDeleteAccount, togglePinAccount, generateTOTP, getTimeRemaining, SERVICE_ICONS, decryptSecret, handleLogout
}) => {
    const fileInputRef = React.useRef(null);

    const handleImportClick = () => {
        fileInputRef.current.click();
    };

    const handleFileChange = (e) => {
        if (e.target.files.length > 0) {
            onImportAccounts(e.target.files[0]);
        }
        e.target.value = ''; // Reset input
    };

    return (
        <div className="card" id="mainApp">
            <div className="d-flex justify-content-between align-items-center mb-3">
                <h2 className="card-title mb-0"><i className="fas fa-shield-alt"></i>2FA Code Manager</h2>
                <div className="user-info">
                    <span className="user-email" id="userEmail" title={userEmail}>{userEmail}</span>
                    <button className="btn" id="logoutBtn" title="Sign Out" onClick={handleLogout}>
                        <i className="fas fa-sign-out-alt"></i>
                    </button>
                </div>
            </div>
            <p className="text-muted mb-2">Securely store and manage your two-factor authentication codes</p>
            <div className="sync-status mb-4" id="syncStatus">
                <i className={`fas ${syncStatus.icon} ${syncStatus.status === 'syncing' ? 'fa-spin' : ''}`}></i> {syncStatus.message}
                {syncStatus.status === 'error' && <span className="badge bg-warning text-dark ms-2">Error</span>}
            </div>

            <div className="mb-4 action-buttons">
                <button className="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addAccountModal" onClick={onAddAccountClick}>
                    <i className="fas fa-plus me-2"></i>Add New Account
                </button>
                <button className="btn btn-outline-primary ms-2" id="exportAccountsBtn" style={{ backgroundImage: 'var(--primary-gradient)', color: 'white', border: 'none' }} onClick={onExportAccounts}>
                    <i className="fas fa-file-export me-2"></i><span className="button-text">Export</span>
                </button>
                <button className="btn btn-outline-primary ms-2" id="importAccountsBtn" style={{ backgroundImage: 'var(--primary-gradient)', color: 'white', border: 'none' }} onClick={handleImportClick}>
                    <i className="fas fa-file-import me-2"></i><span className="button-text">Import</span>
                </button>
                <input type="file" ref={fileInputRef} accept=".json" style={{ display: 'none' }} onChange={handleFileChange} />
                <button className="btn btn-outline-secondary ms-2" id="refreshAccountsBtn" title="Refresh accounts" onClick={onRefreshAccounts}>
                    <i className="fas fa-sync-alt"></i><span className="button-text">Refresh</span>
                </button>
            </div>

            <div className="d-flex flex-column flex-md-row justify-content-between align-items-md-center mb-3">
                <div className="search-container flex-grow-1 me-md-3">
                    <i className="fas fa-search search-icon"></i>
                    <input
                        type="text"
                        id="searchInput"
                        className="form-control"
                        placeholder="Search accounts..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                    />
                </div>

                <div className="view-toggle mt-2 mt-md-0">
                    <div className="btn-group" role="group" aria-label="View mode selection">
                        <button type="button" className={`btn ${viewMode === 'standard' ? 'active' : ''}`} data-view="standard" onClick={() => changeViewMode('standard')} aria-pressed={viewMode === 'standard'}>
                            <i className="fas fa-th-list me-1" aria-hidden="true"></i><span className="d-none d-sm-inline">List</span>
                        </button>
                        <button type="button" className={`btn ${viewMode === 'compact' ? 'active' : ''}`} data-view="compact" onClick={() => changeViewMode('compact')} aria-pressed={viewMode === 'compact'}>
                            <i className="fas fa-list me-1" aria-hidden="true"></i><span className="d-none d-sm-inline">Compact</span>
                        </button>
                        <button type="button" className={`btn ${viewMode === 'grid' ? 'active' : ''}`} data-view="grid" onClick={() => changeViewMode('grid')} aria-pressed={viewMode === 'grid'}>
                            <i className="fas fa-th me-1" aria-hidden="true"></i><span className="d-none d-sm-inline">Grid</span>
                        </button>
                    </div>
                </div>
            </div>

            <div id="accountsList" className={`thin-scrollbar ${viewMode === 'compact' ? 'mobile-compact-view' : ''} ${viewMode === 'grid' ? 'grid-view' : ''}`}>
                {accounts.length === 0 ? (
                    <div className="no-accounts" id="noAccounts">
                        <i className="fas fa-user-shield fa-3x mb-3" style={{ color: '#e0e6ed' }}></i>
                        <h5>No 2FA accounts added yet</h5>
                        <p>Add your first account to get started</p>
                    </div>
                ) : (
                    <>
                        {accounts.filter(acc => acc.pinned).length > 0 && (
                            <div className="accounts-section-header">
                                <i className="fas fa-thumbtack"></i> Pinned Accounts
                            </div>
                        )}
                        {accounts.filter(acc => acc.pinned).map(account => (
                            <AccountItem
                                key={account.id}
                                account={account}
                                generateTOTP={generateTOTP}
                                getTimeRemaining={getTimeRemaining}
                                SERVICE_ICONS={SERVICE_ICONS}
                                decryptSecret={decryptSecret}
                                onEditAccount={onEditAccount}
                                onDeleteAccount={onDeleteAccount}
                                togglePinAccount={togglePinAccount}
                                isGridView={viewMode === 'grid'}
                                isCompactView={viewMode === 'compact'}
                            />
                        ))}
                        {accounts.filter(acc => !acc.pinned).length > 0 && (
                            <div className="accounts-section-header">
                                <i className="fas fa-list"></i> Other Accounts
                            </div>
                        )}
                        {accounts.filter(acc => !acc.pinned).map(account => (
                            <AccountItem
                                key={account.id}
                                account={account}
                                generateTOTP={generateTOTP}
                                getTimeRemaining={getTimeRemaining}
                                SERVICE_ICONS={SERVICE_ICONS}
                                decryptSecret={decryptSecret}
                                onEditAccount={onEditAccount}
                                onDeleteAccount={onDeleteAccount}
                                togglePinAccount={togglePinAccount}
                                isGridView={viewMode === 'grid'}
                                isCompactView={viewMode === 'compact'}
                            />
                        ))}
                    </>
                )}
            </div>
        </div>
    );
};

export default MainAppContent;
