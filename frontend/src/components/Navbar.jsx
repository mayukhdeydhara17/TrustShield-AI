import { useEffect, useState } from "react";

function Navbar({ backendStatus, account, onLogout }) {
  const [scrolled, setScrolled] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    const onScroll = () =>
      setScrolled((window.scrollY || document.documentElement.scrollTop) > 20);
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const accountName = account?.name || account?.email || "My account";
  const initial = accountName.trim().charAt(0).toUpperCase() || "U";

  return (
    <nav className={`navbar ${scrolled ? "navbar-scrolled" : ""}`}>
      <a className="brand" href="#top">
        <svg className="brand-mark" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" />
          <path d="m8.5 12 2.5 2.5 4.5-5" />
        </svg>
        <span>TrustShield AI</span>
      </a>

      <div className="nav-links">
        <a href="#demo">Live demo</a>
        <a href="#story">Why</a>
        <a href="#steps">How it works</a>
        <a href="#views">Coverage</a>
        <a href="#history">Your scans</a>
      </div>

      <div className="nav-right">
        <div className={`status ${backendStatus.replace(/\W/g, "").toLowerCase()}`}>
          <span className="status-dot"></span>
          Backend: {backendStatus}
        </div>
        {account ? (
          <div
            className={`profile-menu ${menuOpen ? "open" : ""}`}
            onMouseEnter={() => setMenuOpen(true)}
            onMouseLeave={() => setMenuOpen(false)}
          >
            <button
              className="profile-trigger"
              type="button"
              aria-label={`Account menu for ${accountName}`}
              aria-expanded={menuOpen}
              onClick={() => setMenuOpen((open) => !open)}
              onFocus={() => setMenuOpen(true)}
            >
              <span className="profile-avatar">{initial}</span>
              <span className="profile-label">Profile</span>
              <span className="profile-chevron">⌄</span>
            </button>
            <div className="profile-popover" role="menu">
              <span className="profile-caption">SIGNED IN AS</span>
              <strong>{accountName}</strong>
              <span className="profile-email">{account.email}</span>
              <a href="#history" onClick={() => setMenuOpen(false)}>My scan history</a>
              <button type="button" onClick={onLogout}>Sign out</button>
            </div>
          </div>
        ) : (
          <a className="nav-signin" href="#/sign-in">Sign in</a>
        )}
      </div>
    </nav>
  );
}

export default Navbar;
