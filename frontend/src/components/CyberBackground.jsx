import { useEffect, useRef } from "react";
import * as THREE from "three";

/*
  3D cybersecurity background
  - A drifting network of nodes linked by "packets" (lines)
  - The cursor acts as a threat scanner: nearby nodes glow orange,
    get pulled toward it, and link to it
  - A wireframe shield core turns to follow the cursor
  - With no pointer (touch / idle), the scanner patrols on its own
*/

const ORANGE = new THREE.Color("#E6701A");
const DIM = new THREE.Color("#8A7863");

function dotTexture() {
  const c = document.createElement("canvas");
  c.width = c.height = 64;
  const g = c.getContext("2d");
  const grad = g.createRadialGradient(32, 32, 0, 32, 32, 32);
  grad.addColorStop(0, "rgba(255,255,255,1)");
  grad.addColorStop(0.4, "rgba(255,255,255,0.55)");
  grad.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = grad;
  g.fillRect(0, 0, 64, 64);
  return new THREE.CanvasTexture(c);
}

export default function CyberBackground() {
  const hostRef = useRef(null);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    let renderer;
    try {
      renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
    } catch {
      return; // no WebGL: page still works without the background
    }

    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(window.innerWidth, window.innerHeight);
    host.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 200);
    camera.position.set(0, 0, 30);

    /* ---------- nodes ---------- */
    const aspect = window.innerWidth / window.innerHeight;
    const N = window.innerWidth < 700 ? 90 : 170;
    const B = [Math.max(20, 17.3 * aspect + 6), 20, 14];
    const pos = new Float32Array(N * 3);
    const vel = new Float32Array(N * 3);
    const col = new Float32Array(N * 3);
    const heat = new Float32Array(N);

    for (let i = 0; i < N; i++) {
      for (let a = 0; a < 3; a++) {
        pos[i * 3 + a] = (Math.random() * 2 - 1) * B[a];
        vel[i * 3 + a] = (Math.random() - 0.5) * 0.025;
      }
    }

    const pGeo = new THREE.BufferGeometry();
    pGeo.setAttribute("position", new THREE.BufferAttribute(pos, 3).setUsage(THREE.DynamicDrawUsage));
    pGeo.setAttribute("color", new THREE.BufferAttribute(col, 3).setUsage(THREE.DynamicDrawUsage));
    const tex = dotTexture();
    const pMat = new THREE.PointsMaterial({
      size: 1.0,
      map: tex,
      vertexColors: true,
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
    });
    const points = new THREE.Points(pGeo, pMat);
    points.frustumCulled = false;
    scene.add(points);

    /* ---------- links ---------- */
    const MAX = 1400;
    const LINK = 8;
    const R = 9; // scanner radius
    const lPos = new Float32Array(MAX * 6);
    const lCol = new Float32Array(MAX * 6);
    const lGeo = new THREE.BufferGeometry();
    lGeo.setAttribute("position", new THREE.BufferAttribute(lPos, 3).setUsage(THREE.DynamicDrawUsage));
    lGeo.setAttribute("color", new THREE.BufferAttribute(lCol, 3).setUsage(THREE.DynamicDrawUsage));
    lGeo.setDrawRange(0, 0);
    const lMat = new THREE.LineBasicMaterial({
      vertexColors: true,
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
    });
    const lines = new THREE.LineSegments(lGeo, lMat);
    lines.frustumCulled = false;
    scene.add(lines);

    /* ---------- shield core ---------- */
    const core = new THREE.Group();
    core.position.set(0, 0, -6);
    const icoMat = new THREE.LineBasicMaterial({ color: ORANGE, transparent: true, opacity: 0.26, blending: THREE.AdditiveBlending, depthWrite: false });
    const octMat = new THREE.LineBasicMaterial({ color: ORANGE, transparent: true, opacity: 0.5, blending: THREE.AdditiveBlending, depthWrite: false });
    const icoGeo = new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(7, 1));
    const octGeo = new THREE.EdgesGeometry(new THREE.OctahedronGeometry(3.6, 0));
    const ico = new THREE.LineSegments(icoGeo, icoMat);
    const oct = new THREE.LineSegments(octGeo, octMat);
    core.add(ico, oct);
    scene.add(core);

    /* ---------- cursor scanner ---------- */
    const ringMat = new THREE.MeshBasicMaterial({ color: ORANGE, transparent: true, opacity: 0.75, blending: THREE.AdditiveBlending, side: THREE.DoubleSide, depthWrite: false });
    const haloMat = new THREE.MeshBasicMaterial({ color: ORANGE, transparent: true, opacity: 0.16, blending: THREE.AdditiveBlending, side: THREE.DoubleSide, depthWrite: false });
    const ringGeo = new THREE.RingGeometry(1.5, 1.7, 48);
    const haloGeo = new THREE.RingGeometry(R - 0.08, R, 72);
    const dotGeo = new THREE.CircleGeometry(0.28, 20);
    const ring = new THREE.Mesh(ringGeo, ringMat);
    const halo = new THREE.Mesh(haloGeo, haloMat);
    const dot = new THREE.Mesh(dotGeo, ringMat);
    scene.add(ring, halo, dot);

    /* ---------- input ---------- */
    const mouse = { x: 0, y: 0 };
    const cur = { x: 0, y: 0 };
    let lastMove = -Infinity;

    const onMove = (e) => {
      mouse.x = (e.clientX / window.innerWidth) * 2 - 1;
      mouse.y = -((e.clientY / window.innerHeight) * 2 - 1);
      lastMove = performance.now();
    };

    const onResize = () => {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
      if (reduce) renderer.render(scene, camera);
    };

    /* ---------- frame ---------- */
    const v = new THREE.Vector3();
    const cw = new THREE.Vector3();
    let raf = 0;

    function frame(t) {
      const time = t * 0.001;
      const idle = t - lastMove > 3000;
      const tx = idle ? Math.sin(time * 0.45) * 0.6 : mouse.x;
      const ty = idle ? Math.cos(time * 0.32) * 0.4 : mouse.y;
      cur.x += (tx - cur.x) * 0.08;
      cur.y += (ty - cur.y) * 0.08;

      // camera parallax
      camera.position.x += (cur.x * 3 - camera.position.x) * 0.03;
      camera.position.y += (cur.y * 2 - camera.position.y) * 0.03;
      camera.lookAt(0, 0, 0);
      camera.updateMatrixWorld();

      // cursor position on the z = 0 plane
      v.set(cur.x, cur.y, 0.5).unproject(camera).sub(camera.position).normalize();
      cw.copy(camera.position).addScaledVector(v, -camera.position.z / v.z);

      // nodes
      for (let i = 0; i < N; i++) {
        const k = i * 3;
        for (let a = 0; a < 3; a++) {
          pos[k + a] += vel[k + a];
          if (Math.abs(pos[k + a]) > B[a]) vel[k + a] *= -1;
        }
        const dx = cw.x - pos[k];
        const dy = cw.y - pos[k + 1];
        const d = Math.hypot(dx, dy);
        let h = 0;
        if (d < R) {
          h = 1 - d / R;
          if (d > 2.5) {
            pos[k] += (dx / d) * h * 0.04;
            pos[k + 1] += (dy / d) * h * 0.04;
          }
        }
        heat[i] = h;
        const b = 0.5 + 0.5 * h;
        col[k] = (DIM.r + (ORANGE.r - DIM.r) * h) * b;
        col[k + 1] = (DIM.g + (ORANGE.g - DIM.g) * h) * b;
        col[k + 2] = (DIM.b + (ORANGE.b - DIM.b) * h) * b;
      }

      // links between close nodes
      let s = 0;
      for (let i = 0; i < N && s < MAX; i++) {
        for (let j = i + 1; j < N && s < MAX; j++) {
          const dx = pos[i * 3] - pos[j * 3];
          const dy = pos[i * 3 + 1] - pos[j * 3 + 1];
          const dz = pos[i * 3 + 2] - pos[j * 3 + 2];
          const d = Math.sqrt(dx * dx + dy * dy + dz * dz);
          if (d >= LINK) continue;
          const f = 1 - d / LINK;
          const h = (heat[i] + heat[j]) * 0.5;
          const r = (DIM.r * 0.6 + (ORANGE.r - DIM.r * 0.6) * h) * f;
          const g = (DIM.g * 0.6 + (ORANGE.g - DIM.g * 0.6) * h) * f;
          const bl = (DIM.b * 0.6 + (ORANGE.b - DIM.b * 0.6) * h) * f;
          const o = s * 6;
          lPos[o] = pos[i * 3]; lPos[o + 1] = pos[i * 3 + 1]; lPos[o + 2] = pos[i * 3 + 2];
          lPos[o + 3] = pos[j * 3]; lPos[o + 4] = pos[j * 3 + 1]; lPos[o + 5] = pos[j * 3 + 2];
          lCol[o] = lCol[o + 3] = r;
          lCol[o + 1] = lCol[o + 4] = g;
          lCol[o + 2] = lCol[o + 5] = bl;
          s++;
        }
      }

      // scanner beams: cursor -> flagged nodes
      for (let i = 0; i < N && s < MAX; i++) {
        if (heat[i] < 0.15) continue;
        const o = s * 6;
        lPos[o] = cw.x; lPos[o + 1] = cw.y; lPos[o + 2] = 0;
        lPos[o + 3] = pos[i * 3]; lPos[o + 4] = pos[i * 3 + 1]; lPos[o + 5] = pos[i * 3 + 2];
        const f = heat[i];
        lCol[o] = lCol[o + 3] = ORANGE.r * f;
        lCol[o + 1] = lCol[o + 4] = ORANGE.g * f;
        lCol[o + 2] = lCol[o + 5] = ORANGE.b * f;
        s++;
      }

      pGeo.attributes.position.needsUpdate = true;
      pGeo.attributes.color.needsUpdate = true;
      lGeo.attributes.position.needsUpdate = true;
      lGeo.attributes.color.needsUpdate = true;
      lGeo.setDrawRange(0, s * 2);

      // shield core follows the cursor
      core.rotation.y = time * 0.15 + cur.x * 0.6;
      core.rotation.x = time * 0.08 - cur.y * 0.5;
      core.scale.setScalar(1 + Math.sin(time * 1.5) * 0.02);
      oct.rotation.y = -time * 0.4;
      oct.rotation.z = time * 0.2;

      // scanner rings
      ring.position.copy(cw);
      halo.position.copy(cw);
      dot.position.copy(cw);
      ring.rotation.z = time * 0.8;
      ring.scale.setScalar(1 + 0.15 * Math.sin(time * 3));

      renderer.render(scene, camera);
    }

    function loop(t) {
      frame(t);
      raf = requestAnimationFrame(loop);
    }

    window.addEventListener("resize", onResize);
    if (reduce) {
      frame(0);
    } else {
      window.addEventListener("pointermove", onMove, { passive: true });
      raf = requestAnimationFrame(loop);
    }

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", onResize);
      window.removeEventListener("pointermove", onMove);
      [pGeo, lGeo, icoGeo, octGeo, ringGeo, haloGeo, dotGeo].forEach((g) => g.dispose());
      [pMat, lMat, icoMat, octMat, ringMat, haloMat].forEach((m) => m.dispose());
      tex.dispose();
      renderer.dispose();
      if (renderer.domElement.parentNode === host) host.removeChild(renderer.domElement);
    };
  }, []);

  return <div className="cyber-bg" ref={hostRef} aria-hidden="true" />;
}
