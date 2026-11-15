import { useEffect, useRef } from "react";

/*
  Page-wide background: threats stream in from every edge and shatter on a
  large shield ring that sits behind the hero. Fixed, non-interactive, and
  kept faint so text stays readable. Pauses when the tab is hidden.
*/
const TAGS = ["phishing", "xss", "sqli", "typosquat", "malware", "redirect", "spoof", "ddos"];

export default function ThreatBackdrop() {
  const ref = useRef(null);

  useEffect(() => {
    const cv = ref.current, c = cv.getContext("2d");
    const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
    const css = (n, f) => getComputedStyle(document.documentElement).getPropertyValue(n).trim() || f;
    const COL = { acc: css("--orange-hi", "#E6701A"), bad: css("--danger", "#E5604A"), ok: css("--safe", "#86B35A") };
    let W, H, cx, cy, R, raf, last = 0, t0 = 0;
    const atk = [], fx = [];

    function size() {
      const d = Math.min(devicePixelRatio || 1, 2);
      W = innerWidth; H = innerHeight;
      cv.width = W * d; cv.height = H * d; c.setTransform(d, 0, 0, d, 0, 0);
      cx = W / 2; cy = H * 0.46; R = Math.min(W, H) * (W < 700 ? 0.42 : 0.36);
    }
    size(); addEventListener("resize", size);

    function spawn() {
      const a = Math.random() * Math.PI * 2, d = Math.hypot(W, H) * 0.6;
      atk.push({ x: cx + Math.cos(a) * d, y: cy + Math.sin(a) * d, a, sp: 1.2 + Math.random() * 1.8, tag: Math.random() < 0.3 ? TAGS[(Math.random() * TAGS.length) | 0] : "", trail: [], w: Math.random() * 6 });
    }

    function frame(ts) {
      raf = requestAnimationFrame(frame);
      if (document.hidden) { t0 = ts; return; }
      const dt = Math.min((ts - t0) / 16.7 || 1, 3); t0 = ts;
      c.clearRect(0, 0, W, H);

      // shield ring + slow rotating dashes
      c.lineWidth = 1.5;
      for (let i = 0; i < 2; i++) {
        const r = R * (1 + i * 0.16), ang = (ts / (5200 + i * 1800)) * (i ? -1 : 1);
        c.strokeStyle = COL.acc; c.globalAlpha = 0.2 - i * 0.07;
        c.setLineDash([10 + i * 8, 16 + i * 10]); c.beginPath(); c.arc(cx, cy, r, ang, ang + Math.PI * 2); c.stroke();
      }
      c.setLineDash([]);
      const sw = ts / 2200;
      c.fillStyle = COL.acc; c.globalAlpha = 0.05; c.beginPath(); c.moveTo(cx, cy); c.arc(cx, cy, R * 1.16, sw, sw + 0.55); c.closePath(); c.fill();

      if (!still && ts - last > (W < 700 ? 900 : 650)) { last = ts; spawn(); }

      for (let i = atk.length - 1; i >= 0; i--) {
        const a = atk[i], dx = cx - a.x, dy = cy - a.y, d = Math.hypot(dx, dy);
        a.w += 0.08;
        a.x += (dx / d) * a.sp * dt + Math.sin(a.w) * 0.35;
        a.y += (dy / d) * a.sp * dt + Math.cos(a.w) * 0.35;
        a.trail.push(a.x, a.y); if (a.trail.length > 36) a.trail.splice(0, 2);
        c.lineWidth = 1.8; c.lineCap = "round"; c.strokeStyle = COL.bad;
        for (let j = 2; j < a.trail.length; j += 2) {
          c.globalAlpha = (j / a.trail.length) * 0.4;
          c.beginPath(); c.moveTo(a.trail[j - 2], a.trail[j - 1]); c.lineTo(a.trail[j], a.trail[j + 1]); c.stroke();
        }
        c.globalAlpha = 0.85; c.fillStyle = COL.bad; c.beginPath(); c.arc(a.x, a.y, 3, 0, 7); c.fill();
        if (a.tag && d > R * 1.3) { c.font = "11px JetBrains Mono, monospace"; c.globalAlpha = 0.5; c.fillText(a.tag, a.x + 8, a.y - 7); }
        if (d < R * 1.16) {
          for (let n = 0; n < 12; n++) {
            const s = Math.random() * 2.6 + 0.6, g = a.a + Math.PI + (Math.random() - 0.5) * 2.4;
            fx.push({ k: "p", x: a.x, y: a.y, vx: Math.cos(g) * s, vy: Math.sin(g) * s, l: 1 });
          }
          fx.push({ k: "r", a: a.a, rad: R * 1.16, l: 1 });
          atk.splice(i, 1);
        }
      }

      for (let i = fx.length - 1; i >= 0; i--) {
        const f = fx[i];
        if (f.k === "p") { f.x += f.vx * dt; f.y += f.vy * dt; f.l -= 0.035 * dt; c.fillStyle = f.l > 0.5 ? COL.ok : COL.acc; c.globalAlpha = Math.max(f.l, 0) * 0.8; c.beginPath(); c.arc(f.x, f.y, 1.8, 0, 7); c.fill(); }
        else { f.rad += 1.6 * dt; f.l -= 0.03 * dt; c.strokeStyle = COL.ok; c.lineWidth = 2; c.globalAlpha = Math.max(f.l, 0) * 0.5; c.beginPath(); c.arc(cx, cy, f.rad, f.a - 0.7, f.a + 0.7); c.stroke(); }
        if (f.l <= 0) fx.splice(i, 1);
      }
      c.globalAlpha = 1;
    }
    raf = requestAnimationFrame(frame);
    return () => { cancelAnimationFrame(raf); removeEventListener("resize", size); };
  }, []);

  return <canvas ref={ref} className="threat-backdrop" aria-hidden="true" />;
}
