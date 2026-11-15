import { useCallback, useState } from "react";
import AttackField from "./AttackField";
import "./SignIn.css";

const ACTIONS = ["blocked", "quarantined", "sandboxed", "flagged"];

export default function SignIn() {
  const [signUp, setSignUp] = useState(false);
  const [show, setShow] = useState(false);
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [msg, setMsg] = useState({ text: "", ok: false });
  const [log, setLog] = useState([
    { id: 1, text: "paypa1-secure-login.com", blocked: false },
    { id: 2, text: "SQL injection", blocked: true, act: "blocked" },
  ]);
  const [count, setCount] = useState(1284);

  const onEvent = useCallback((text, blocked) => {
    setLog((l) => [...l.slice(-5), { id: Math.random(), text, blocked, act: ACTIONS[(Math.random() * 4) | 0] }]);
  }, []);
  const onBlock = useCallback(() => setCount((n) => n + 1), []);

  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  function submit(e) {
    e.preventDefault();
    const { name, email, password } = form;
    if (signUp && !name.trim()) return setMsg({ text: "Enter your full name.", ok: false });
    if (!/^\S+@\S+\.\S+$/.test(email.trim())) return setMsg({ text: "Enter a valid email address.", ok: false });
    if (signUp ? password.length < 8 : !password) return setMsg({ text: signUp ? "Use at least 8 characters for your password." : "Enter your password.", ok: false });
    // TODO: replace with your real auth call (e.g. POST `${import.meta.env.VITE_API_URL}/auth/...`)
    localStorage.setItem("trustshield_user", JSON.stringify({ name: name.trim(), email: email.trim() }));
    setMsg({ text: signUp ? "Account created." : "Signed in. Redirecting…", ok: true });
    setTimeout(() => { window.location.hash = ""; }, 900);
  }

  function social(p) { setMsg({ text: `Connecting to ${p}…`, ok: true }); }

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
            <div className="signin-log">
              {log.map((r) => (
                <div key={r.id}>
                  <b className={r.blocked ? "k" : "x"}>{r.blocked ? r.act : "incoming"}</b>
                  <span>{r.text}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="signin-card">
          <div className="signin-tabs" role="tablist">
            <button role="tab" aria-selected={!signUp} onClick={() => { setSignUp(false); setMsg({ text: "" }); }}>Sign in</button>
            <button role="tab" aria-selected={signUp} onClick={() => { setSignUp(true); setMsg({ text: "" }); }}>Create account</button>
          </div>
          <h2>{signUp ? "Create your account" : "Welcome back"}</h2>
          <p className="signin-note">Read our <a href="#privacy">Privacy Policy</a> and <a href="#terms">Terms of Service</a> before continuing.</p>

          <div className="signin-soc">
            <button type="button" onClick={() => social("Google")}>Continue with Google</button>
            <button type="button" onClick={() => social("GitHub")}>Continue with GitHub</button>
          </div>
          <div className="signin-or">or with email</div>

          <form onSubmit={submit} noValidate>
            {signUp && (
              <div className="signin-f"><label htmlFor="su-name">Full name</label>
                <input id="su-name" autoComplete="name" placeholder="Ada Lovelace" value={form.name} onChange={set("name")} /></div>
            )}
            <div className="signin-f"><label htmlFor="su-email">Email</label>
              <input id="su-email" type="email" autoComplete="email" placeholder="you@example.com" value={form.email} onChange={set("email")} /></div>
            <div className="signin-f">
              <label htmlFor="su-pw">Password {!signUp && <a href="#reset">Forgot?</a>}</label>
              <input id="su-pw" type={show ? "text" : "password"} autoComplete={signUp ? "new-password" : "current-password"} placeholder={signUp ? "At least 8 characters" : "Your password"} value={form.password} onChange={set("password")} />
              <button type="button" className="signin-eye" onClick={() => setShow(!show)}>{show ? "Hide" : "Show"}</button>
            </div>
            <p className={`signin-msg ${msg.ok ? "ok" : ""}`} role="status">{msg.text}</p>
            <button className="signin-go" type="submit">{signUp ? "Create account" : "Sign in"}</button>
          </form>
          <p className="signin-alt"><a href="#magic">Use a magic link</a><a href="#">Continue without an account</a></p>
        </section>
      </main>
      <div className="signin-stat">threats blocked today <b>{count.toLocaleString()}</b></div>
    </div>
  );
}
