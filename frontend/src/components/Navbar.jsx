
function Navbar() {
    return (
        <nav className="navbar">
            <div className="brand">
                <span className="brand-icon">🛡️</span>
                <h2>TrustShield AI</h2>
            </div>

            <div className="nav-links">
                <a href="#dashboard">Dashboard</a>
                <a href="#scanner">Scanner</a>
                <a href="#history">History</a>
            </div>

            <div className="status">
                <span className="status-dot"></span>
                Security Platform
            </div>
        </nav>
    );
}

export default Navbar;
