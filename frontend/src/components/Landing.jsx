/* Landing sections for TrustShield AI */

const NODES = [
  { x: 130, y: 70, t: "DNS", s: "resolves · 3 days old" },
  { x: 130, y: 290, t: "Redirects", s: "302 → /verify" },
  { x: 670, y: 70, t: "SSL", s: "valid · issuer checked" },
  { x: 670, y: 290, t: "Threat intel", s: "indicator matched" },
  { x: 400, y: 36, t: "Phishing rules", s: "lookalike domain" },
];

export function EvidenceGraph() {
  return (
    <div className="graph-wrap" aria-label="Sample evidence graph">
      <div className="graph-head">
        <span>Evidence graph · hover a node</span>
        <span className="graph-tag">Sample investigation</span>
      </div>
      <svg viewBox="0 0 800 350" className="graph" role="img">
        {NODES.map((n, i) => (
          <line key={i} x1="400" y1="175" x2={n.x} y2={n.y} className="g-link" style={{ animationDelay: `${i * 0.4}s` }} />
        ))}
        <line x1="400" y1="175" x2="400" y2="305" className="g-link g-hot" />
        {NODES.map((n) => (
          <g key={n.t} className="g-node" transform={`translate(${n.x} ${n.y})`}>
            <title>{n.t}: {n.s}</title>
            <circle r="26" />
            <text y="4" textAnchor="middle" className="g-t">{n.t}</text>
            <text y="46" textAnchor="middle" className="g-s">{n.s}</text>
          </g>
        ))}
        <g className="g-core" transform="translate(400 175)">
          <circle r="40" className="g-ring" />
          <circle r="30" />
          <text y="4" textAnchor="middle" className="g-t">URL</text>
          <text y="-52" textAnchor="middle" className="g-url">paypa1-secure-login.com</text>
        </g>
        <g className="g-risk" transform="translate(400 305)">
          <rect x="-48" y="-16" width="96" height="32" rx="16" />
          <text y="5" textAnchor="middle">High Risk</text>
        </g>
      </svg>
    </div>
  );
}

export function Story() {
  return (
    <section className="section story" id="story">
      <span className="eyebrow">01 / Look closer</span>
      <h2>A padlock proves encryption.<br /><em>Not who you're talking to.</em></h2>
      <p className="lead">A familiar logo, a convincing message, a valid certificate. Trust takes more than appearances, so TrustShield AI connects the signals behind a link.</p>
      <div className="check-card">
        <code>https://sbi-kyc-update.in/verify</code>
        <ul>
          <li>Connection encrypted <b className="pass">Pass</b></li>
          <li>Domain is established <b className="fail">Fail</b></li>
          <li>Matches known threats <b className="fail">Fail</b></li>
        </ul>
        <span className="level-badge high">High Risk</span>
      </div>
    </section>
  );
}

const STEPS = [
  ["Submit", "Paste a link or domain."],
  ["Investigate", "DNS, domain age, SSL certificate."],
  ["Analyse", "Phishing rules and threat intelligence."],
  ["Assess", "A 0–100 score and a clear risk level."],
  ["Report", "Download the full findings."],
];

export function Steps() {
  return (
    <section className="section" id="steps">
      <span className="eyebrow">02 / How it works</span>
      <h2>Five steps. One answer.</h2>
      <ol className="steps">
        {STEPS.map(([t, d], i) => (
          <li className="step" key={t}>
            <span className="step-n">0{i + 1}</span>
            <h3>{t}</h3>
            <p>{d}</p>
          </li>
        ))}
      </ol>
    </section>
  );
}

const VIEWS = [
  ["Link & domain", "Lookalikes, odd TLDs, IP-based URLs."],
  ["SSL certificate", "Issuer, expiry and validity."],
  ["Website security", "Domain age and risky signals."],
  ["Phishing engine", "Rules that flag deceptive URLs."],
  ["Threat intelligence", "Known-bad indicators."],
  ["Risk score", "One score, one clear level."],
];

export function Views() {
  return (
    <section className="section" id="views">
      <span className="eyebrow">03 / Coverage</span>
      <h2>Six views of one link.</h2>
      <div className="views-grid">
        {VIEWS.map(([t, d], i) => (
          <article className="view-card" key={t}>
            <span className="view-n">{String(i + 1).padStart(2, "0")}</span>
            <h3>{t}</h3>
            <p>{d}</p>
          </article>
        ))}
      </div>
    </section>
  );
}

const CASES = [
  ["low", 12, "Established site, valid certificate", "Low Risk"],
  ["medium", 47, "Young domain, some warning signs", "Medium Risk"],
  ["high", 86, "Lookalike domain, known indicator", "High Risk"],
];

export function Cases() {
  return (
    <section className="section" id="cases">
      <span className="eyebrow">04 / Clear outcomes</span>
      <h2>Built to avoid false alarms.</h2>
      <div className="cases">
        {CASES.map(([k, n, d, l]) => (
          <div className={`case ${k}`} key={k}>
            <span className="case-score">{n}</span>
            <p>{d}</p>
            <span className={`level-badge ${k}`}>{l}</span>
          </div>
        ))}
      </div>
      <p className="fine">Sample outcomes for illustration.</p>
    </section>
  );
}

export function Cta() {
  return (
    <section className="cta">
      <h2>Check the link before you click.</h2>
      <a className="btn-primary" href="#top">Scan a website</a>
    </section>
  );
}

export function Footer() {
  return (
    <footer className="footer">
      <strong>TrustShield AI</strong>
      <span>Risk signals, not guarantees. No scanner can promise a site is safe.</span>
    </footer>
  );
}
