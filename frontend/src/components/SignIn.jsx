import { useCallback, useState } from "react";
import AttackField from "./AttackField";
import "./SignIn.css";

const API_URL = (import.meta.env.VITE_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

export default function SignIn() {
  const [signUp, setSignUp] = useState(false);
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [msg, setMsg] = useState({ text: "", ok: false });
  const [log, setLog] = useState([
    { id: 1, text: "Suspicious login attempt", blocked: true },
    { id: 2, text: "Malicious redirect", blocked: true },
  ]);
  const [count, setCount] = useState(1284);
  const onEvent = useCallback((text, blocked) => {
    setLog((items) => [...items.slice(-3), { id: `${Date.now()}-${Math.random()}`, text, blocked }]);
  }, []);
  const onBlock = useCallback(() => setCount((value) => value + 1), []);
  const set = (key) => (event) => setForm((previous) => ({ ...previous, [key]: event.target.value }));

  async function submit(event) {
    event.preventDefault();
    setMsg({ text: "", ok: false });
    const name = form.name.trim();
    const email = form.email.trim().toLowerCase();
    if (signUp && !name) return setMsg({ text: "Enter your full name.", ok: false });
    if (!/^\S+@\S+\.\S+$/.test(email)) return setMsg({ text: "Enter a valid email address.", ok: false });
    if (signUp && form.password.length < 8) return setMsg({ text: "Use at least 8 characters for your password.", ok: false });
    if (!signUp && !form.password) return setMsg({ text: "Enter your password.", ok: false });

    setBusy(true);
    try {
      const response = await fetch(`${API_URL}/auth/${signUp ? "signup" : "login"}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(signUp
          ? { name, email, password: form.password }
          : { email, password: form.password }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || "Authentication failed. Please try again.");
      localStorage.setItem("trustshield_access_token", data.access_token);
      localStorage.setItem("trustshield_user", JSON.stringify(data.user));
      setMsg({ text: signUp ? "Account created successfully. Redirecting…" : "Signed in successfully. Redirecting…", ok: true });
      window.setTimeout(() => { window.location.hash = ""; }, 500);
    } catch (error) {
      setMsg({
        text: error instanceof TypeError
          ? "Can't reach the server. Start the TrustShield backend and try again."
          : error.message,
        ok: false,
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="signin">
      <AttackField onEvent={onEvent} onBlock={onBlock} />
      <main className="signin-wrap">
        <section className="signin-left">
          <a className="signin-brand" href="#">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" /><path d="m8.5 12 2.5 2.5 4.5-5" /></svg>
            TrustShield AI
          </a>
          <div>
            <h1>Every attack<br />stops at the <em>door.</em></h1>
            <p className="signin-sub">Sign in to keep your link scans and security reports in one place.</p>
            <div className="signin-log" aria-live="off">
              {log.map((item) => (
                <div key={item.id}>
                  <b className={item.blocked ? "k" : "x"}>{item.blocked ? "blocked" : "incoming"}</b>
                  <span>{item.text}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="signin-card">
          <div className="signin-tabs" role="tablist" aria-label="Authentication">
            <button type="button" role="tab" aria-selected={!signUp} onClick={() => { setSignUp(false); setMsg({ text: "", ok: false }); }}>Sign in</button>
            <button type="button" role="tab" aria-selected={signUp} onClick={() => { setSignUp(true); setMsg({ text: "", ok: false }); }}>Create account</button>
          </div>
          <h2>{signUp ? "Create your account" : "Welcome back"}</h2>
          <p className="signin-note">Your account keeps your TrustShield experience together.</p>
          <div className="signin-or">secure email authentication</div>

          <form onSubmit={submit} noValidate>
            {signUp && (
              <div className="signin-f">
                <label htmlFor="su-name">Full name</label>
                <input id="su-name" autoComplete="name" placeholder="Your full name" value={form.name} onChange={set("name")} />
              </div>
            )}
            <div className="signin-f">
              <label htmlFor="su-email">Email</label>
              <input id="su-email" type="email" autoComplete="email" placeholder="you@example.com" value={form.email} onChange={set("email")} />
            </div>
            <div className="signin-f">
              <label htmlFor="su-pw">Password</label>
              <input id="su-pw" type={show ? "text" : "password"} autoComplete={signUp ? "new-password" : "current-password"} placeholder={signUp ? "At least 8 characters" : "Your password"} value={form.password} onChange={set("password")} />
              <button type="button" className="signin-eye" onClick={() => setShow((value) => !value)}>{show ? "Hide" : "Show"}</button>
            </div>
            <p className={`signin-msg ${msg.ok ? "ok" : ""}`} role="status" aria-live="polite">{msg.text}</p>
            <button className="signin-go" type="submit" disabled={busy}>
              {busy ? "Please wait…" : signUp ? "Create account" : "Sign in"}
            </button>
          </form>
          <p className="signin-alt">
            <a href="#" onClick={(event) => { event.preventDefault(); setSignUp((value) => !value); setMsg({ text: "Switch between sign in and account creation to continue.", ok: true }); }}>
              {signUp ? "Already have an account? Sign in" : "New to TrustShield? Create account"}
            </a>
            <a href="#top">Back to home</a>
          </p>
        </section>
      </main>
      <div className="signin-stat">threats blocked <b>{count.toLocaleString()}</b></div>
    </div>
  );
}
