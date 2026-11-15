import { useEffect, useRef } from "react";

/*
  Attack / defense animation
  Red threats fly in from every side toward a shield. Each one is stopped
  at the shield edge with a ripple + sparks, and named ones are written to
  the rolling log through onEvent(text, blocked).
*/
const THREATS = [
  "paypa1-secure-login.com", "SQL injection", "credential stuffing",
  "bank-verify.xyz", "XSS payload", "free-gift-claim.top", "session hijack",
  "brute force", "fake-kyc-update.net", "DDoS burst", "typosquat: g00gle.com",
  "malicious redirect",
];

export default function AttackField({ onEvent, onBlock }) {
  const ref = useRef(null);
  const cb = useRef({ onEvent, onBlock });
  cb.current = { onEvent, onBlock };

  useEffect(() => {
    const cv = ref.current;
    const c = cv.getContext("2d");
    const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
    const css = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
    let W, H, cx, cy, R, raf, last = 0, t0 = 0;
    const COL = { acc: css("--orange-hi") || "#E6701A", bad: css("--danger") || "#E5604A", ok: css("--safe") || "#86B35A", mute: css("--muted") || "#A89A86" };
    const narrow = () => innerWidth <= 900;

    function size() {
      const d = Math.min(devicePixelRatio || 1, 2);
      W = innerWidth; H = innerHeight;
      cv.width = W * d; cv.height = H * d;
      c.setTransform(d, 0, 0, d, 0, 0);
      cx = narrow() ? W / 2 : W * 0.3;
      cy = narrow() ? H * 0.3 : H * 0.5;
      R = Math.min(narrow() ? W * 0.22 : W * 0.12, 120);
    }
    size();
    addEventListener("resize", size);

    const stars = Array.from({ length: 110 }, () => ({ x: Math.random(), y: Math.random(), r: Math.random() * 1.3 + 0.2, p: Math.random() * 6 }));
    const atk = [], fx = [];

    function spawn() {
      const a = Math.random() * Math.PI * 2, d = Math.max(W, H) * 0.62;
      atk.push({ x: cx + Math.cos(a) * d, y: cy + Math.sin(a) * d, a, sp: 1.6 + Math.random() * 2.2, n: THREATS[(Math.random() * THREATS.length) | 0], trail: [], lab: Math.random() < 0.35, seen: false, wob: Math.random() * 6 });
    }

    function frame(ts) {
      const dt = Math.min((ts - t0) / 16.7 || 1, 3); t0 = ts;
      c.clearRect(0, 0, W, H);
      const g = c.createRadialGradient(cx, cy, 0, cx, cy, Math.max(W, H) * 0.7);
      g.addColorStop(0, "rgba(230,112,26,.16)"); g.addColorStop(1, "rgba(230,112,26,0)");
      c.fillStyle = g; c.fillRect(0, 0, W, H);

      c.fillStyle = COL.mute;
      for (const s of stars) { c.globalAlpha = 0.25 + 0.25 * Math.sin(ts / 900 + s.p); c.beginPath(); c.arc(s.x * W, s.y * H, s.r, 0, 7); c.fill(); }
      c.globalAlpha = 1;

      // rolling rings
      for (let i = 0; i < 3; i++) {
        const rr = R * (1.5 + i * 0.55), ang = (ts / (2600 + i * 900)) * (i % 2 ? -1 : 1);
        c.strokeStyle = COL.acc; c.globalAlpha = 0.35 - i * 0.08; c.lineWidth = 1.2;
        c.setLineDash([6 + i * 6, 10 + i * 8]); c.beginPath(); c.arc(cx, cy, rr, ang, ang + Math.PI * 2); c.stroke();
      }
      c.setLineDash([]); c.globalAlpha = 1;

      // shield
      const pulse = 1 + Math.sin(ts / 500) * 0.03, k = R * 0.62;
      c.save(); c.translate(cx, cy); c.scale(pulse, pulse);
      const sg = c.createRadialGradient(0, 0, 0, 0, 0, R);
      sg.addColorStop(0, "rgba(230,112,26,.30)"); sg.addColorStop(1, "rgba(230,112,26,.04)");
      c.fillStyle = sg; c.strokeStyle = COL.acc; c.lineWidth = 2.4; c.lineJoin = "round";
      c.beginPath(); c.moveTo(0, -k * 1.2); c.lineTo(k, -k * 0.7); c.lineTo(k, k * 0.1);
      c.quadraticCurveTo(k * 0.9, k * 0.9, 0, k * 1.3); c.quadraticCurveTo(-k * 0.9, k * 0.9, -k, k * 0.1);
      c.lineTo(-k, -k * 0.7); c.closePath(); c.fill(); c.stroke();
      c.strokeStyle = COL.ok; c.lineWidth = 3; c.lineCap = "round";
      c.beginPath(); c.moveTo(-k * 0.35, 0); c.lineTo(-k * 0.05, k * 0.3); c.lineTo(k * 0.4, -k * 0.3); c.stroke();
      c.restore();

      // radar sweep
      const sw = ts / 1400;
      c.fillStyle = COL.acc; c.globalAlpha = 0.08; c.beginPath(); c.moveTo(cx, cy); c.arc(cx, cy, R * 2.6, sw, sw + 0.5); c.closePath(); c.fill(); c.globalAlpha = 1;

      if (!still && ts - last > (narrow() ? 650 : 520)) { last = ts; spawn(); }

      for (let i = atk.length - 1; i >= 0; i--) {
        const a = atk[i], dx = cx - a.x, dy = cy - a.y, d = Math.hypot(dx, dy);
        a.wob += 0.1;
        a.x += (dx / d) * a.sp * dt + Math.sin(a.wob) * 0.5;
        a.y += (dy / d) * a.sp * dt + Math.cos(a.wob) * 0.5;
        a.trail.push(a.x, a.y); if (a.trail.length > 28) a.trail.splice(0, 2);
        if (!a.seen && d < Math.max(W, H) * 0.5) { a.seen = true; if (a.lab) cb.current.onEvent?.(a.n, false); }
        c.lineWidth = 2; c.lineCap = "round";
        for (let j = 2; j < a.trail.length; j += 2) {
          c.strokeStyle = COL.bad; c.globalAlpha = (j / a.trail.length) * 0.55;
          c.beginPath(); c.moveTo(a.trail[j - 2], a.trail[j - 1]); c.lineTo(a.trail[j], a.trail[j + 1]); c.stroke();
        }
        c.globalAlpha = 1; c.fillStyle = COL.bad; c.beginPath(); c.arc(a.x, a.y, 3.4, 0, 7); c.fill();
        if (a.lab && d > R * 1.6) { c.font = "11px JetBrains Mono, monospace"; c.globalAlpha = 0.85; c.fillText(a.n, a.x + 9, a.y - 8); c.globalAlpha = 1; }
        if (d < R * 1.05) {
          for (let n = 0; n < 16; n++) {
            const s = Math.random() * 3 + 0.8, gg = a.a + Math.PI + (Math.random() - 0.5) * 2.4;
            fx.push({ k: "p", x: a.x, y: a.y, vx: Math.cos(gg) * s, vy: Math.sin(gg) * s, l: 1 });
          }
          fx.push({ k: "r", rad: R, l: 1, a: a.a });
          cb.current.onBlock?.();
          if (a.lab) cb.current.onEvent?.(a.n, true);
          atk.splice(i, 1);
        }
      }

      for (let i = fx.length - 1; i >= 0; i--) {
        const f = fx[i];
        if (f.k === "p") { f.x += f.vx * dt; f.y += f.vy * dt; f.l -= 0.03 * dt; c.fillStyle = f.l > 0.55 ? COL.ok : COL.acc; c.globalAlpha = Math.max(f.l, 0); c.beginPath(); c.arc(f.x, f.y, 2, 0, 7); c.fill(); }
        else { f.rad += 2.2 * dt; f.l -= 0.035 * dt; c.strokeStyle = COL.ok; c.lineWidth = 2.5; c.globalAlpha = Math.max(f.l, 0); c.beginPath(); c.arc(cx, cy, f.rad, f.a - 0.9, f.a + 0.9); c.stroke(); }
        c.globalAlpha = 1; if (f.l <= 0) fx.splice(i, 1);
      }
      raf = requestAnimationFrame(frame);
    }
    raf = requestAnimationFrame(frame);
    return () => { cancelAnimationFrame(raf); removeEventListener("resize", size); };
  }, []);

  return <canvas ref={ref} className="atk-canvas" aria-hidden="true" />;
}
