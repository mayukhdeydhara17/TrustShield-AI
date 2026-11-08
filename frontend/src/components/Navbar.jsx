import { useEffect, useState } from "react";

function Navbar({ backendStatus }) {
    const [scrolled, setScrolled] = useState(false);

    useEffect(() => {
        const handleScroll = () => {
            setScrolled(
                (window.scrollY || document.documentElement.scrollTop) > 20
            );
        };

        window.addEventListener("scroll", handleScroll, { passive: true });
        handleScroll();

        return () => {
            window.removeEventListener("scroll", handleScroll);
        };
    }, []);

    return (
        <nav className={`navbar ${scrolled ? "navbar-scrolled" : ""}`}>
            <div className="brand">
                <span className="brand-icon">🛡️</span>
                <h2>TrustShield AI</h2>
            </div>

            <div className={`status ${backendStatus.replace(/\W/g, "").toLowerCase()}`}>
                <span className="status-dot"></span>
                Backend: {backendStatus}
            </div>
        </nav>
    );
}

export default Navbar;