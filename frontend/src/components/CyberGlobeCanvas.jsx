import React, { useEffect, useRef, useMemo } from 'react';

// Geographic cyber hubs around the world
const CYBER_HUBS = [
  { id: 'panama', name: 'Panama Offshore Hub', lat: 8.9824, lon: -79.5199, type: 'offshore' },
  { id: 'curacao', name: 'Curacao Gaming Hub', lat: 12.1696, lon: -68.9900, type: 'gambling' },
  { id: 'delhi', name: 'CERT-In / New Delhi', lat: 28.6139, lon: 77.2090, type: 'soc' },
  { id: 'mumbai', name: 'Financial Intercept / Mumbai', lat: 19.0760, lon: 72.8777, type: 'finance' },
  { id: 'frankfurt', name: 'DE-CIX / Frankfurt', lat: 50.1109, lon: 8.6821, type: 'backbone' },
  { id: 'london', name: 'LINX / London', lat: 51.5074, lon: -0.1278, type: 'backbone' },
  { id: 'singapore', name: 'Equinix SG1 / Singapore', lat: 1.3521, lon: 103.8198, type: 'backbone' },
  { id: 'tokyo', name: 'JPIX / Tokyo', lat: 35.6762, lon: 139.6503, type: 'telecom' },
  { id: 'newyork', name: 'Telx / New York', lat: 40.7128, lon: -74.0060, type: 'finance' },
  { id: 'sf', name: 'Cloudflare / San Francisco', lat: 37.7749, lon: -122.4194, type: 'cloud' },
  { id: 'dubai', name: 'UAE Intercept / Dubai', lat: 25.2048, lon: 55.2708, type: 'offshore' },
  { id: 'sydney', name: 'Oceania SOC / Sydney', lat: -33.8688, lon: 151.2093, type: 'soc' },
  { id: 'saopaulo', name: 'LATAM Core / São Paulo', lat: -23.5505, lon: -46.6333, type: 'backbone' }
];

// Active threat routing routes
const NETWORK_ROUTES = [
  { from: 'panama', to: 'mumbai', risk: 'high', active: true },
  { from: 'curacao', to: 'delhi', risk: 'critical', active: true },
  { from: 'frankfurt', to: 'delhi', risk: 'normal', active: true },
  { from: 'sf', to: 'tokyo', risk: 'normal', active: true },
  { from: 'london', to: 'frankfurt', risk: 'normal', active: true },
  { from: 'singapore', to: 'mumbai', risk: 'normal', active: true },
  { from: 'dubai', to: 'delhi', risk: 'high', active: true },
  { from: 'newyork', to: 'london', risk: 'normal', active: true },
  { from: 'panama', to: 'newyork', risk: 'high', active: true },
  { from: 'curacao', to: 'frankfurt', risk: 'high', active: true }
];

/**
 * Procedurally generates world landmass points for high-density cyber visualization
 */
function generateLandmassDots() {
  const dots = [];
  const boxes = [
    // North America
    { minLat: 25, maxLat: 62, minLon: -128, maxLon: -68, count: 260 },
    // South America
    { minLat: -50, maxLat: 10, minLon: -78, maxLon: -38, count: 180 },
    // Europe
    { minLat: 36, maxLat: 66, minLon: -10, maxLon: 38, count: 240 },
    // Africa
    { minLat: -32, maxLat: 34, minLon: -15, maxLon: 48, count: 220 },
    // India & South Asia (High detail)
    { minLat: 8, maxLat: 34, minLon: 68, maxLon: 92, count: 190 },
    // East Asia & China
    { minLat: 20, maxLat: 50, minLon: 95, maxLon: 140, count: 230 },
    // Middle East
    { minLat: 14, maxLat: 38, minLon: 36, maxLon: 64, count: 110 },
    // Australia & NZ
    { minLat: -40, maxLat: -14, minLon: 114, maxLon: 154, count: 130 },
    // Southeast Asia / Indo
    { minLat: -8, maxLat: 18, minLon: 98, maxLon: 128, count: 110 }
  ];

  // Deterministic PRNG
  let seed = 1337;
  const rand = () => {
    seed = (seed * 16807) % 2147483647;
    return (seed - 1) / 2147483646;
  };

  boxes.forEach((box) => {
    for (let i = 0; i < box.count; i++) {
      const lat = box.minLat + rand() * (box.maxLat - box.minLat);
      const lon = box.minLon + rand() * (box.maxLon - box.minLon);
      dots.push({
        lat: (lat * Math.PI) / 180,
        lon: (lon * Math.PI) / 180,
        size: 0.85 + rand() * 1.3,
        pulseOffset: rand() * Math.PI * 2,
        isHub: rand() > 0.94
      });
    }
  });

  // Regular spherical cyber-coordinate grid (parallels & meridians)
  for (let latDeg = -75; latDeg <= 75; latDeg += 25) {
    for (let lonDeg = -180; lonDeg < 180; lonDeg += 15) {
      dots.push({
        lat: (latDeg * Math.PI) / 180,
        lon: (lonDeg * Math.PI) / 180,
        size: 0.75,
        pulseOffset: Math.random() * Math.PI * 2,
        isGrid: true
      });
    }
  }

  return dots;
}

export default function CyberGlobeCanvas({
  isScanning = false,
  scanStep = 0,
  hoveredPanel = null,
  targetHost = null,
  mousePos = { x: 0, y: 0 }
}) {
  const canvasRef = useRef(null);
  const dotsRef = useRef(null);
  if (!dotsRef.current) dotsRef.current = generateLandmassDots();

  // Network packets traveling along routes
  const packetsRef = useRef(
    Array.from({ length: 28 }, (_, i) => ({
      routeIdx: i % NETWORK_ROUTES.length,
      progress: (i / 28) + Math.random() * 0.1,
      speed: 0.0035 + Math.random() * 0.0045,
      size: 1.5 + Math.random() * 1.5
    }))
  );

  // Free-floating ambient cyber particles
  const floatingParticlesRef = useRef(
    Array.from({ length: 65 }, () => ({
      radius: 1.1 + Math.random() * 0.45,
      theta: Math.random() * Math.PI * 2,
      phi: (Math.random() - 0.5) * Math.PI,
      speedTheta: (Math.random() - 0.5) * 0.002,
      speedPhi: (Math.random() - 0.5) * 0.001,
      size: 1.0 + Math.random() * 1.8,
      alpha: 0.3 + Math.random() * 0.5
    }))
  );

  // Expanding scanning radar shockwaves
  const scanWavesRef = useRef([
    { radius: 0.4, alpha: 0.7, speed: 0.004 },
    { radius: 0.8, alpha: 0.4, speed: 0.004 }
  ]);

  // Burst particles triggered when scan reaches final state
  const burstParticlesRef = useRef([]);

  useEffect(() => {
    if (scanStep === 7 || scanStep === 8) {
      // Create dramatic particle burst from the globe
      burstParticlesRef.current = Array.from({ length: 80 }, () => {
        const angle = Math.random() * Math.PI * 2;
        const speed = 1.8 + Math.random() * 4.2;
        return {
          x: 0,
          y: 0,
          vx: Math.cos(angle) * speed,
          vy: Math.sin(angle) * speed,
          alpha: 1,
          size: 1.8 + Math.random() * 2.5
        };
      });
    }
  }, [scanStep]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d', { alpha: true });
    let animationFrameId;

    let rotY = 0;
    let rotX = 0.22; // default 12.6 deg tilt
    let targetRotY = 0;
    let targetRotX = 0.22;

    const handleResize = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = rect.width * dpr;
      canvas.height = rect.height * dpr;
      ctx.scale(dpr, dpr);
    };

    handleResize();
    window.addEventListener('resize', handleResize);

    const hubsMap = new Map();
    CYBER_HUBS.forEach((h) => hubsMap.set(h.id, h));

    const render = (time) => {
      const rect = canvas.getBoundingClientRect();
      const W = rect.width;
      const H = rect.height;
      if (!W || !H) {
        animationFrameId = requestAnimationFrame(render);
        return;
      }

      ctx.clearRect(0, 0, W, H);

      const cx = W / 2;
      const cy = H / 2;
      const baseRadius = Math.min(W, H) * 0.38;

      // Mouse Parallax Damping
      const mouseFactorX = (mousePos.x / (window.innerWidth || 1) - 0.5) * 0.55;
      const mouseFactorY = (mousePos.y / (window.innerHeight || 1) - 0.5) * 0.4;

      targetRotY += isScanning ? 0.009 : 0.0032;
      rotY += (targetRotY + mouseFactorX - rotY) * 0.06;
      rotX += (0.22 - mouseFactorY - rotX) * 0.06;

      const cosX = Math.cos(rotX);
      const sinX = Math.sin(rotX);

      // 3D projection function: (lat, lon, rBoost) -> { x, y, z, visible }
      const project = (lat, lon, rBoost = 1.0) => {
        const r = baseRadius * rBoost;
        const adjLon = lon + rotY;

        // Spherical to 3D Cartesian
        const x0 = r * Math.cos(lat) * Math.sin(adjLon);
        const y0 = -r * Math.sin(lat);
        const z0 = r * Math.cos(lat) * Math.cos(adjLon);

        // Pitch tilt (rotX)
        const y1 = y0 * cosX - z0 * sinX;
        const z1 = y0 * sinX + z0 * cosX;
        const x1 = x0;

        return {
          x: cx + x1,
          y: cy + y1,
          z: z1,
          depthNorm: z1 / r, // [-1 to 1]
          visible: z1 > -r * 0.18
        };
      };

      // 1. Draw Deep Cyber Atmosphere Glow
      const glowGrad = ctx.createRadialGradient(cx, cy, baseRadius * 0.5, cx, cy, baseRadius * 1.45);
      glowGrad.addColorStop(0, 'rgba(4, 28, 58, 0.45)');
      glowGrad.addColorStop(0.65, 'rgba(6, 182, 212, 0.12)');
      glowGrad.addColorStop(0.85, 'rgba(34, 211, 238, 0.06)');
      glowGrad.addColorStop(1, 'rgba(2, 6, 23, 0)');
      ctx.fillStyle = glowGrad;
      ctx.beginPath();
      ctx.arc(cx, cy, baseRadius * 1.45, 0, Math.PI * 2);
      ctx.fill();

      // 2. Draw Concentric Expanding Sonar Shockwaves
      scanWavesRef.current.forEach((wave) => {
        wave.radius += isScanning ? 0.007 : wave.speed;
        if (wave.radius > 1.35) wave.radius = 0.35;
        const waveR = Math.max(0.1, baseRadius * wave.radius);
        const alpha = Math.max(0, 0.55 * (1 - (wave.radius - 0.35) / 1.0));

        ctx.strokeStyle = `rgba(34, 211, 238, ${alpha})`;
        ctx.lineWidth = 1.2;
        ctx.setLineDash([4, 6]);
        ctx.beginPath();
        ctx.arc(cx, cy, waveR, 0, Math.PI * 2);
        ctx.stroke();
        ctx.setLineDash([]);
      });

      // 3. Draw Outer Scanning Rings (Equator & Horizon)
      ctx.save();
      ctx.strokeStyle = 'rgba(34, 211, 238, 0.25)';
      ctx.lineWidth = 1.0;
      ctx.beginPath();
      ctx.ellipse(cx, cy, baseRadius * 1.08, baseRadius * 0.35, rotX * 0.4, 0, Math.PI * 2);
      ctx.stroke();

      // Scanning Reticle Beam during scan
      if (isScanning) {
        const sweepAngle = (time * 0.0035) % (Math.PI * 2);
        ctx.strokeStyle = 'rgba(0, 240, 255, 0.7)';
        ctx.lineWidth = 1.8;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(cx + Math.cos(sweepAngle) * baseRadius * 1.15, cy + Math.sin(sweepAngle) * baseRadius * 1.15);
        ctx.stroke();
      }
      ctx.restore();

      // 4. Draw Landmass Dots & Coordinates
      const dots = dotsRef.current;
      for (let i = 0; i < dots.length; i++) {
        const d = dots[i];
        const p = project(d.lat, d.lon, 1.0);

        if (!p.visible) {
          // Dim faint back hemisphere
          ctx.fillStyle = 'rgba(14, 116, 144, 0.08)';
          ctx.beginPath();
          ctx.arc(p.x, p.y, d.size * 0.75, 0, Math.PI * 2);
          ctx.fill();
          continue;
        }

        // Front Hemisphere: Bright, crisp, layered electric cyan
        const depthAlpha = Math.max(0.18, 0.2 + 0.8 * p.depthNorm);
        const pulse = 0.8 + 0.2 * Math.sin(time * 0.003 + d.pulseOffset);

        if (d.isHub) {
          ctx.fillStyle = `rgba(34, 211, 238, ${depthAlpha * pulse})`;
          ctx.shadowColor = '#00f0ff';
          ctx.shadowBlur = 6;
          ctx.beginPath();
          ctx.arc(p.x, p.y, d.size * 1.5, 0, Math.PI * 2);
          ctx.fill();
          ctx.shadowBlur = 0;
        } else if (d.isGrid) {
          ctx.fillStyle = `rgba(56, 189, 248, ${depthAlpha * 0.35})`;
          ctx.beginPath();
          ctx.arc(p.x, p.y, d.size, 0, Math.PI * 2);
          ctx.fill();
        } else {
          ctx.fillStyle = `rgba(34, 211, 238, ${depthAlpha * 0.75})`;
          ctx.beginPath();
          ctx.arc(p.x, p.y, d.size, 0, Math.PI * 2);
          ctx.fill();
        }
      }

      // 5. Draw Great Circle Threat Routes & Arcs
      NETWORK_ROUTES.forEach((route, idx) => {
        const h1 = hubsMap.get(route.from);
        const h2 = hubsMap.get(route.to);
        if (!h1 || !h2) return;

        const p1 = project((h1.lat * Math.PI) / 180, (h1.lon * Math.PI) / 180, 1.0);
        const p2 = project((h2.lat * Math.PI) / 180, (h2.lon * Math.PI) / 180, 1.0);

        // Calculate elevated arc midpoint
        const midLat = ((h1.lat + h2.lat) / 2 * Math.PI) / 180;
        const midLon = ((h1.lon + h2.lon) / 2 * Math.PI) / 180;
        const pMid = project(midLat, midLon, 1.24); // raised off surface

        // Only draw arc if at least one endpoint is facing the camera
        if (p1.z > -baseRadius * 0.2 || p2.z > -baseRadius * 0.2 || pMid.z > 0) {
          const isCritical = route.risk === 'critical';
          const isHigh = route.risk === 'high';
          const arcColor = isCritical
            ? 'rgba(244, 63, 94, '
            : isHigh
            ? 'rgba(251, 138, 60, '
            : 'rgba(34, 211, 238, ';

          const alpha = Math.max(0.12, (pMid.depthNorm + 1) * 0.35);

          ctx.strokeStyle = `${arcColor}${alpha})`;
          ctx.lineWidth = isCritical ? 1.8 : 1.2;
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.quadraticCurveTo(pMid.x, pMid.y, p2.x, p2.y);
          ctx.stroke();
        }
      });

      // 6. Draw Moving Network Packets (Photons)
      packetsRef.current.forEach((pkt) => {
        pkt.progress += isScanning ? pkt.speed * 2.2 : pkt.speed;
        if (pkt.progress >= 1) pkt.progress = 0;

        const route = NETWORK_ROUTES[pkt.routeIdx];
        const h1 = hubsMap.get(route.from);
        const h2 = hubsMap.get(route.to);
        if (!h1 || !h2) return;

        const t = pkt.progress;
        // Interpolate along spherical arc
        const lat = (((1 - t) * h1.lat + t * h2.lat) * Math.PI) / 180;
        const lon = (((1 - t) * h1.lon + t * h2.lon) * Math.PI) / 180;
        const arcElev = 1.0 + Math.sin(Math.PI * t) * 0.24;

        const pos = project(lat, lon, arcElev);
        if (pos.z > -baseRadius * 0.1) {
          const isCrit = route.risk === 'critical';
          ctx.fillStyle = isCrit ? '#f43f5e' : '#00f0ff';
          ctx.shadowColor = isCrit ? '#f43f5e' : '#00f0ff';
          ctx.shadowBlur = 8;
          ctx.beginPath();
          ctx.arc(pos.x, pos.y, pkt.size * (1 + 0.3 * Math.sin(time * 0.01)), 0, Math.PI * 2);
          ctx.fill();
          ctx.shadowBlur = 0;
        }
      });

      // 7. Draw Major Cyber Hub Nodes & Radar Rings
      CYBER_HUBS.forEach((hub) => {
        const p = project((hub.lat * Math.PI) / 180, (hub.lon * Math.PI) / 180, 1.0);
        if (p.depthNorm > 0.05) {
          const isSpecial = hub.type === 'gambling' || hub.type === 'offshore';
          const nodeColor = isSpecial ? '#fb923c' : '#22d3ee';

          // Hub Core Dot
          ctx.fillStyle = nodeColor;
          ctx.shadowColor = nodeColor;
          ctx.shadowBlur = 9;
          ctx.beginPath();
          ctx.arc(p.x, p.y, 2.8, 0, Math.PI * 2);
          ctx.fill();
          ctx.shadowBlur = 0;

          // Pulsing Ping Ring around Hub (safe positive radius for all latitudes)
          const pingPhase = Math.abs((time * 0.002 + Math.abs(hub.lat)) % 1);
          const pingR = Math.max(0.1, 4 + 7 * pingPhase);
          const pingAlpha = Math.max(0, 1 - pingR / 11);
          ctx.strokeStyle = `rgba(${isSpecial ? '251, 146, 60' : '34, 211, 238'}, ${pingAlpha})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.arc(p.x, p.y, pingR, 0, Math.PI * 2);
          ctx.stroke();

          // Subtle Label on major hubs
          if (p.depthNorm > 0.35 && (hub.id === 'delhi' || hub.id === 'panama' || hub.id === 'curacao')) {
            ctx.fillStyle = 'rgba(226, 232, 240, 0.75)';
            ctx.font = '9px "IBM Plex Mono", monospace';
            ctx.fillText(hub.name, p.x + 8, p.y + 3);
          }
        }
      });

      // 8. Draw Ambient Orbiting Data Particles
      floatingParticlesRef.current.forEach((part) => {
        part.theta += part.speedTheta * (isScanning ? 2.5 : 1.0);
        part.phi += part.speedPhi;
        const p = project(part.phi, part.theta, part.radius);
        if (p.z > -baseRadius * 0.3) {
          ctx.fillStyle = `rgba(34, 211, 238, ${part.alpha * (p.depthNorm > 0 ? 0.75 : 0.25)})`;
          ctx.beginPath();
          ctx.arc(p.x, p.y, part.size, 0, Math.PI * 2);
          ctx.fill();
        }
      });

      // 9. Draw Particle Burst on Scan Completion
      if (burstParticlesRef.current.length > 0) {
        for (let i = burstParticlesRef.current.length - 1; i >= 0; i--) {
          const bp = burstParticlesRef.current[i];
          bp.x += bp.vx;
          bp.y += bp.vy;
          bp.vx *= 0.96;
          bp.vy *= 0.96;
          bp.alpha -= 0.015;

          if (bp.alpha <= 0) {
            burstParticlesRef.current.splice(i, 1);
            continue;
          }

          ctx.fillStyle = `rgba(0, 240, 255, ${bp.alpha})`;
          ctx.shadowColor = '#00f0ff';
          ctx.shadowBlur = 8;
          ctx.beginPath();
          ctx.arc(cx + bp.x, cy + bp.y, bp.size, 0, Math.PI * 2);
          ctx.fill();
          ctx.shadowBlur = 0;
        }
      }

      animationFrameId = requestAnimationFrame(render);
    };

    animationFrameId = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', handleResize);
    };
  }, [isScanning, scanStep, mousePos]);

  return (
    <div className="relative h-full w-full select-none overflow-hidden">
      <canvas
        ref={canvasRef}
        className="block h-full w-full cursor-grab active:cursor-grabbing"
        title="Interactive Cyber Threat Globe (3D)"
      />
    </div>
  );
}
