import { useEffect, useRef, useState } from "react";
import "./LiveDemo.css";

/*
  "Watch it work" — a looping, animated walkthrough of a scan.
  A suspicious message arrives, the link is typed into the scanner, five
  checks resolve one by one, and the risk gauge settles on a verdict.
  Then it repeats with a safe link so people see both outcomes.
*/
const CASES = [
  {
    msg: "SBI Alert: your KYC expires today. Update now:",
    url: "sbi-kyc-update.in/verify",
    score: 94, level: "High Risk", tone: "bad", note: "Threat blocked. Don’t open this link.",
    checks: [
      ["Domain & DNS", "Registered 3 days ago", "bad"],
      ["SSL certificate", "Valid, but issued 3 days ago", "warn"],
      ["Redirects", "302 to /verify, form posts to another domain", "bad"],
      ["Phishing rules", "Lookalike of a bank brand", "bad"],
      ["Threat intelligence", "Listed in OpenPhish", "bad"],
    ],
  },
  {
    msg: "Here’s the repo we talked about:",
    url: "github.com/torvalds/linux",
    score: 6, level: "Low Risk", tone: "ok", note: "Looks safe to open.",
    checks: [
      ["Domain & DNS", "Registered 17 years ago", "ok"],
      ["SSL certificate", "Valid, trusted issuer", "ok"],
      ["Redirects", "No redirects", "ok"],
      ["Phishing rules", "No deceptive patterns", "ok"],
      ["Threat intelligence", "No indicators found", "ok"],
    ],
  },
];
const LOOP = 110; // ticks of 100 ms per case
const ARC = Math.PI * 90;

export default function LiveDemo() {
  const root = useRef(null);
  const [inView, setInView] = useState(false);
  const [t, setT] = useState(0);
  const [ci, setCi] = useState(0);
  const still = typeof matchMedia !== "undefined" && matchMedia("(prefers-reduced-motion: reduce)").matches;

  useEffect(() => {
    const io = new IntersectionObserver(([e]) => setInView(e.isIntersecting), { threshold: 0.25 });
    io.observe(root.current);
    return () => io.disconnect();
  }, []);

  useEffect(() => {
    if (!inView || still) return;
    const id = setInterval(() => {
      setT((v) => {
        if (v + 1 >= LOOP) { setCi((c) => (c + 1) % CASES.length); return 0; }
        return v + 1;
      });
    }, 100);
    return () => clearInterval(id);
  }, [inView, still]);

  const k = CASES[ci];
  const tt = still ? LOOP - 5 : t;
  const typed = k.url.slice(0, Math.max(0, Math.min(k.url.length, Math.floor((tt - 6) * 1.7))));
  const state = (i) => (tt >= 28 + i * 8 ? "done" : tt >= 22 + i * 8 ? "scan" : "wait");
  const p = Math.max(0, Math.min(1, (tt - 64) / 18));
  const score = Math.round(k.score * (1 - Math.pow(1 - p, 3)));
  const verdict = tt >= 84;

  return (
    <section className="section ld" id="demo" ref={root}>
      <span className="eyebrow">Live demo</span>
      <h2>Watch a link get investigated.</h2>
      <p className="lead">Paste a link, and TrustShield AI checks the domain, certificate, redirects, phishing rules and threat feeds. Then it gives you one clear answer.</p>

      <div className={`ld-card tone-${verdict ? k.tone : "idle"}`}>
        <div className="ld-col">
          <div className={`ld-msg ${tt >= 2 ? "in" : ""}`}>
            <small>Incoming message</small>
            <p>{k.msg} <u>{k.url}</u></p>
          </div>
          <div className="ld-bar" aria-hidden="true">
            <span className="ld-url">{typed}<i className={tt >= 6 && tt < 24 ? "blink" : ""} /></span>
            <span className={`ld-btn ${tt >= 22 ? "on" : ""}`}>{tt >= 22 && !verdict ? "Scanning…" : "Scan Website"}</span>
          </div>
          <ul className="ld-checks">
            {k.checks.map(([n, f, s], i) => {
              const st = state(i);
              return (
                <li key={n} className={`st-${st} ${st === "done" ? "r-" + s : ""}`}>
                  <span className="dot" />
                  <b>{n}</b>
                  <em>{st === "done" ? f : st === "scan" ? "checking…" : ""}</em>
                </li>
              );
            })}
          </ul>
        </div>

        <div className="ld-gauge">
          <svg viewBox="0 0 220 130" role="img" aria-label={`Risk score ${score} out of 100`}>
            <path d="M20 110 A90 90 0 0 1 200 110" className="g-track" />
            <path d="M20 110 A90 90 0 0 1 200 110" className="g-fill" style={{ strokeDasharray: ARC, strokeDashoffset: ARC * (1 - (score / 100)) }} />
            <text x="110" y="98" textAnchor="middle" className="g-num">{score}</text>
            <text x="110" y="122" textAnchor="middle" className="g-cap">risk score</text>
          </svg>
          <div className={`ld-verdict ${verdict ? "show" : ""}`}>
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" /><path d={k.tone === "bad" ? "m9 9 6 6m0-6-6 6" : "m8.5 12 2.5 2.5 4.5-5"} /></svg>
            <strong>{k.level}</strong>
            <span>{k.note}</span>
          </div>
        </div>
      </div>
    </section>
  );
}
