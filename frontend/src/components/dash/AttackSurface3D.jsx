import { useEffect, useRef, useState, useMemo } from "react";
import * as THREE from "three";
import { motion, AnimatePresence } from "motion/react";
import { Orbit, RotateCcw, Eye, ShieldAlert } from "lucide-react";

function pad2(val) {
  return String(val ?? 0).padStart(2, "0");
}

export function AttackSurface3D({ surface }) {
  const containerRef = useRef(null);
  const canvasRef = useRef(null);
  const [activeNode, setActiveNode] = useState(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const [cameraTelemetry, setCameraTelemetry] = useState({ pitch: 35, azimuth: 45 });
  const [autoRotate, setAutoRotate] = useState(true);

  // Normalize node data
  const rawNodes = useMemo(() => {
    return (surface?.nodes || []).slice(0, 8).map((n, i) => {
      const angle = (i / 8) * Math.PI * 2;
      const radius = 32 + (i % 3) * 18;
      const isHot = n.severity === "critical" || n.severity === "high";
      const height = isHot ? 24 : n.severity === "medium" ? 16 : 10;
      return {
        id: n.src_ip,
        ip: n.src_ip,
        vector: n.attack_type,
        severity: n.severity,
        count: n.alert_count,
        x: Math.cos(angle) * radius,
        z: Math.sin(angle) * radius,
        y: height,
        isHot,
      };
    });
  }, [surface]);

  // Three.js Scene Setup & Animation Loop
  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    let width = container.clientWidth || 320;
    let height = 260;

    // Scene, Camera, Renderer
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(40, width / height, 1, 1000);
    const renderer = new THREE.WebGLRenderer({
      canvas,
      antialias: true,
      alpha: true,
      powerPreference: "high-performance",
    });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    // Spherical Camera Orbit Coordinates
    let radius = 175;
    let theta = Math.PI / 4; // Azimuth
    let phi = Math.PI / 3; // Pitch (from zenith)
    let targetTheta = theta;
    let targetPhi = phi;

    function updateCamera() {
      // Clamp phi to prevent flipping
      phi = Math.max(0.2, Math.min(Math.PI / 2.05, phi));
      camera.position.x = radius * Math.sin(phi) * Math.sin(theta);
      camera.position.y = radius * Math.cos(phi);
      camera.position.z = radius * Math.sin(phi) * Math.cos(theta);
      camera.lookAt(0, 6, 0);

      const pitchDeg = Math.round((90 - (phi * 180) / Math.PI));
      const azDeg = Math.round(((theta * 180) / Math.PI) % 360);
      setCameraTelemetry({
        pitch: pitchDeg,
        azimuth: azDeg < 0 ? azDeg + 360 : azDeg,
      });
    }
    updateCamera();

    // Lighting
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.7);
    scene.add(ambientLight);

    const coreLight = new THREE.PointLight(0x38bdf8, 2.2, 120);
    coreLight.position.set(0, 8, 0);
    scene.add(coreLight);

    // Root Group for Scene Geometry
    const rootGroup = new THREE.Group();
    scene.add(rootGroup);

    // 1. Concentric Hologram Radar Rings on Ground Plane (XZ)
    const ringRadii = [25, 45, 65, 85];
    const ringsGroup = new THREE.Group();
    rootGroup.add(ringsGroup);

    ringRadii.forEach((r, idx) => {
      const ringGeo = new THREE.BufferGeometry();
      const points = [];
      const segments = idx === 3 ? 48 : 64;
      for (let i = 0; i <= segments; i++) {
        const a = (i / segments) * Math.PI * 2;
        points.push(new THREE.Vector3(Math.cos(a) * r, 0, Math.sin(a) * r));
      }
      ringGeo.setFromPoints(points);

      const ringMat = new THREE.LineBasicMaterial({
        color: idx === 1 ? 0x38bdf8 : 0x0369a1,
        transparent: true,
        opacity: idx === 1 ? 0.6 : 0.25,
      });
      const ringLine = new THREE.Line(ringGeo, ringMat);
      ringsGroup.add(ringLine);
    });

    // Outer Compass Tick Ring
    const compassGroup = new THREE.Group();
    ringsGroup.add(compassGroup);
    for (let i = 0; i < 24; i++) {
      const a = (i / 24) * Math.PI * 2;
      const r1 = 83;
      const r2 = i % 6 === 0 ? 88 : 85;
      const tickGeo = new THREE.BufferGeometry().setFromPoints([
        new THREE.Vector3(Math.cos(a) * r1, 0, Math.sin(a) * r1),
        new THREE.Vector3(Math.cos(a) * r2, 0, Math.sin(a) * r2),
      ]);
      const tickMat = new THREE.LineBasicMaterial({
        color: 0x38bdf8,
        transparent: true,
        opacity: i % 6 === 0 ? 0.65 : 0.2,
      });
      compassGroup.add(new THREE.Line(tickGeo, tickMat));
    }

    // Coordinate Crosshairs
    const crossGeo = new THREE.BufferGeometry().setFromPoints([
      new THREE.Vector3(-85, 0, 0),
      new THREE.Vector3(85, 0, 0),
      new THREE.Vector3(0, 0, -85),
      new THREE.Vector3(0, 0, 85),
    ]);
    const crossMat = new THREE.LineBasicMaterial({
      color: 0x334155,
      transparent: true,
      opacity: 0.35,
    });
    const crossLine = new THREE.LineSegments(crossGeo, crossMat);
    ringsGroup.add(crossLine);

    // 2. Rotating Radar Sweeper Sector
    const sweeperGroup = new THREE.Group();
    rootGroup.add(sweeperGroup);

    const sweepGeo = new THREE.BufferGeometry().setFromPoints([
      new THREE.Vector3(0, 0.2, 0),
      new THREE.Vector3(85, 0.2, 0),
    ]);
    const sweepMat = new THREE.LineBasicMaterial({
      color: 0x38bdf8,
      transparent: true,
      opacity: 0.85,
    });
    const sweepBeam = new THREE.Line(sweepGeo, sweepMat);
    sweeperGroup.add(sweepBeam);

    // Subtle faint sweep wedge trail
    const sweepWedgeGeo = new THREE.RingGeometry(0, 85, 16, 1, 0, Math.PI / 4);
    sweepWedgeGeo.rotateX(-Math.PI / 2);
    const sweepWedgeMat = new THREE.MeshBasicMaterial({
      color: 0x0ea5e9,
      transparent: true,
      opacity: 0.08,
      side: THREE.DoubleSide,
    });
    const sweepWedge = new THREE.Mesh(sweepWedgeGeo, sweepWedgeMat);
    sweepWedge.position.y = 0.1;
    sweeperGroup.add(sweepWedge);

    // 3. Central Holographic Core (Dominant Subnet Hub)
    const coreGroup = new THREE.Group();
    rootGroup.add(coreGroup);

    // Inner glowing sphere
    const coreSphereGeo = new THREE.SphereGeometry(6.5, 24, 24);
    const coreSphereMat = new THREE.MeshBasicMaterial({
      color: 0x0284c7,
      transparent: true,
      opacity: 0.35,
    });
    const coreSphere = new THREE.Mesh(coreSphereGeo, coreSphereMat);
    coreSphere.position.y = 4;
    coreGroup.add(coreSphere);

    // Wireframe gyro ring
    const gyroGeo = new THREE.TorusGeometry(8.5, 0.35, 8, 32);
    const gyroMat = new THREE.MeshBasicMaterial({
      color: 0xe0f2fe,
      transparent: true,
      opacity: 0.75,
    });
    const gyroRing = new THREE.Mesh(gyroGeo, gyroMat);
    gyroRing.position.y = 4;
    coreGroup.add(gyroRing);

    // 4. Interactive 3D Threat Nodes
    const interactiveMeshes = [];
    const nodeMeshes = [];

    rawNodes.forEach((node) => {
      const nodeGroup = new THREE.Group();
      rootGroup.add(nodeGroup);

      // (a) Vertical Laser Drop Stalk: from ground (x, 0, z) up to (x, y, z)
      const stalkGeo = new THREE.BufferGeometry().setFromPoints([
        new THREE.Vector3(node.x, 0, node.z),
        new THREE.Vector3(node.x, node.y, node.z),
      ]);
      const stalkMat = new THREE.LineBasicMaterial({
        color: node.isHot ? 0xef4444 : 0x0284c7,
        transparent: true,
        opacity: node.isHot ? 0.75 : 0.35,
      });
      const stalk = new THREE.Line(stalkGeo, stalkMat);
      nodeGroup.add(stalk);

      // (b) Spoke connecting Core to Node
      const spokeGeo = new THREE.BufferGeometry().setFromPoints([
        new THREE.Vector3(0, 4, 0),
        new THREE.Vector3(node.x, node.y, node.z),
      ]);
      const spokeMat = new THREE.LineBasicMaterial({
        color: node.isHot ? 0xef4444 : 0x075985,
        transparent: true,
        opacity: node.isHot ? 0.45 : 0.15,
      });
      const spoke = new THREE.Line(spokeGeo, spokeMat);
      nodeGroup.add(spoke);

      // (c) Ground Anchor Ring on floor
      const anchorGeo = new THREE.BufferGeometry();
      const anchorPts = [];
      for (let j = 0; j <= 24; j++) {
        const a = (j / 24) * Math.PI * 2;
        anchorPts.push(new THREE.Vector3(node.x + Math.cos(a) * 4, 0.2, node.z + Math.sin(a) * 4));
      }
      anchorGeo.setFromPoints(anchorPts);
      const anchorMat = new THREE.LineBasicMaterial({
        color: node.isHot ? 0xef4444 : 0x0284c7,
        transparent: true,
        opacity: 0.5,
      });
      const anchorRing = new THREE.Line(anchorGeo, anchorMat);
      nodeGroup.add(anchorRing);

      // (d) 3D Floating Node Sphere
      const sphereGeo = new THREE.SphereGeometry(node.isHot ? 3.8 : 3.0, 16, 16);
      const sphereMat = new THREE.MeshStandardMaterial({
        color: node.isHot ? 0xef4444 : 0x38bdf8,
        emissive: node.isHot ? 0xb91c1c : 0x0284c7,
        emissiveIntensity: 0.8,
        roughness: 0.2,
        metalness: 0.6,
      });
      const sphere = new THREE.Mesh(sphereGeo, sphereMat);
      sphere.position.set(node.x, node.y, node.z);
      sphere.userData = { node };
      nodeGroup.add(sphere);

      // (e) Pulsing Aura Halo around Sphere
      const auraGeo = new THREE.SphereGeometry(node.isHot ? 6.5 : 4.8, 12, 12);
      const auraMat = new THREE.MeshBasicMaterial({
        color: node.isHot ? 0xef4444 : 0x38bdf8,
        transparent: true,
        opacity: node.isHot ? 0.22 : 0.12,
      });
      const aura = new THREE.Mesh(auraGeo, auraMat);
      aura.position.set(node.x, node.y, node.z);
      nodeGroup.add(aura);

      interactiveMeshes.push(sphere);
      nodeMeshes.push({ sphere, aura, anchorRing, node, originalY: node.y });
    });

    // Mouse Controls (Drag to Orbit, Hover Raycast)
    let isDragging = false;
    let previousMousePosition = { x: 0, y: 0 };
    const raycaster = new THREE.Raycaster();
    const mouseVec = new THREE.Vector2(-9999, -9999);

    const onPointerDown = (e) => {
      isDragging = true;
      setAutoRotate(false);
      previousMousePosition = { x: e.clientX, y: e.clientY };
    };

    const onPointerMove = (e) => {
      const rect = canvas.getBoundingClientRect();
      const clientX = e.clientX - rect.left;
      const clientY = e.clientY - rect.top;

      mouseVec.x = (clientX / width) * 2 - 1;
      mouseVec.y = -(clientY / height) * 2 + 1;

      if (isDragging) {
        const deltaX = e.clientX - previousMousePosition.x;
        const deltaY = e.clientY - previousMousePosition.y;

        targetTheta -= deltaX * 0.008;
        targetPhi -= deltaY * 0.008;
        targetPhi = Math.max(0.15, Math.min(Math.PI / 2.05, targetPhi));

        previousMousePosition = { x: e.clientX, y: e.clientY };
      }
    };

    const onPointerUp = () => {
      isDragging = false;
    };

    canvas.addEventListener("pointerdown", onPointerDown);
    window.addEventListener("pointermove", onPointerMove);
    window.addEventListener("pointerup", onPointerUp);

    // Resize Handler
    const handleResize = () => {
      if (!container) return;
      width = container.clientWidth || 320;
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      renderer.setSize(width, height);
    };
    window.addEventListener("resize", handleResize);

    // Animation Loop
    let animId;
    let clock = new THREE.Clock();

    const animate = () => {
      animId = requestAnimationFrame(animate);
      const delta = clock.getDelta();
      const time = clock.getElapsedTime();

      // Auto-orbit rotation if enabled
      if (autoRotate && !isDragging) {
        targetTheta += 0.0035;
      }

      // Smooth Camera Inertia
      theta += (targetTheta - theta) * 0.08;
      phi += (targetPhi - phi) * 0.08;
      updateCamera();

      // Rotate radar sweep
      sweeperGroup.rotation.y += 0.016;

      // Gyro core animation
      gyroRing.rotation.x = time * 0.9;
      gyroRing.rotation.y = time * 1.3;
      coreSphere.scale.setScalar(0.92 + Math.sin(time * 3) * 0.08);

      // Node breathing / pulsing
      nodeMeshes.forEach((item, idx) => {
        const pulse = Math.sin(time * 2.5 + idx * 0.8);
        item.aura.scale.setScalar(0.95 + pulse * 0.18);
        // Gentle hovering floating bob
        item.sphere.position.y = item.originalY + Math.sin(time * 1.8 + idx) * 0.8;
      });

      // Raycasting for interactive hover
      raycaster.setFromCamera(mouseVec, camera);
      const intersects = raycaster.intersectObjects(interactiveMeshes);

      if (intersects.length > 0) {
        const hit = intersects[0].object;
        const hitNode = hit.userData?.node;
        if (hitNode) {
          setActiveNode(hitNode);
          canvas.style.cursor = "pointer";

          // Calculate screen position for tooltip
          const wp = hit.getWorldPosition(new THREE.Vector3());
          wp.project(camera);
          const screenX = ((wp.x + 1) * width) / 2;
          const screenY = ((-wp.y + 1) * height) / 2;
          setTooltipPos({ x: screenX, y: screenY });
        }
      } else {
        if (!isDragging) {
          setActiveNode(null);
          canvas.style.cursor = "grab";
        }
      }

      renderer.render(scene, camera);
    };
    animate();

    // Reset Camera Function on container
    container.resetCamera = () => {
      targetTheta = Math.PI / 4;
      targetPhi = Math.PI / 3;
      setAutoRotate(true);
    };

    // Cleanup
    return () => {
      cancelAnimationFrame(animId);
      canvas.removeEventListener("pointerdown", onPointerDown);
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerup", onPointerUp);
      window.removeEventListener("resize", handleResize);
      renderer.dispose();
    };
  }, [rawNodes, autoRotate]);

  const handleReset = () => {
    if (containerRef.current?.resetCamera) {
      containerRef.current.resetCamera();
    }
  };

  return (
    <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-gradient-to-b from-white/[0.05] via-white/[0.02] to-transparent backdrop-blur-2xl shadow-[inset_0_1px_1px_rgba(255,255,255,0.15),0_20px_50px_-12px_rgba(0,0,0,0.85)]">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/[0.06] px-5 py-3.5 bg-white/[0.015]">
        <span className="flex items-center gap-2 font-sans text-xs font-semibold uppercase tracking-wider text-white">
          <Orbit className="h-3.5 w-3.5 text-primary animate-spin" style={{ animationDuration: "14s" }} />
          3D Attack surface
        </span>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-destructive/30 bg-destructive/10 px-2.5 py-0.5 font-mono text-[10px] font-semibold text-destructive">
            <span className="h-1.5 w-1.5 rounded-full bg-destructive animate-pulse" />
            {surface?.hot ?? 0} HOT
          </span>
        </div>
      </div>

      {/* 3D Canvas Viewport */}
      <div ref={containerRef} className="relative h-64 w-full select-none overflow-hidden bg-black/40">
        <canvas ref={canvasRef} className="h-full w-full block cursor-grab active:cursor-grabbing" />

        {/* 3D HUD Telemetry Overlay (Top-Left) */}
        <div className="pointer-events-none absolute left-3 top-3 flex flex-col gap-0.5 font-mono text-[9px] uppercase tracking-wider text-zinc-400">
          <div>PITCH: <span className="text-white font-medium">{cameraTelemetry.pitch}°</span></div>
          <div>AZIMUTH: <span className="text-white font-medium">{cameraTelemetry.azimuth}°</span></div>
          <div className="text-[8px] text-primary/80">// 3D POLAR GIMBAL</div>
        </div>

        {/* 3D HUD Interactive Controls (Top-Right) */}
        <div className="absolute right-3 top-3 flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => setAutoRotate(!autoRotate)}
            title="Toggle Auto-Orbit"
            className={`rounded-lg border px-2.5 py-1 font-sans text-[10px] font-medium transition-all ${
              autoRotate
                ? "border-primary/50 bg-primary/15 text-primary shadow-[0_0_10px_rgba(56,189,248,0.2)]"
                : "border-white/10 bg-black/60 text-zinc-400 hover:text-white"
            }`}
          >
            {autoRotate ? "Orbit On" : "Orbit Paused"}
          </button>
          <button
            type="button"
            onClick={handleReset}
            title="Reset 3D Camera"
            className="flex items-center gap-1 rounded-lg border border-white/10 bg-black/60 px-2.5 py-1 font-sans text-[10px] font-medium text-zinc-400 hover:border-primary/40 hover:text-white transition-all"
          >
            <RotateCcw className="h-2.5 w-2.5" />
            Reset
          </button>
        </div>

        {/* Subnet Central Overlay Badge */}
        <div className="pointer-events-none absolute inset-x-0 bottom-2.5 flex justify-center">
          <div className="flex items-center gap-2 rounded-full border border-primary/30 bg-black/85 px-3 py-1 font-mono text-[10px] tracking-wider text-white shadow-lg backdrop-blur-md">
            <span className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
            <span className="font-semibold">{surface?.dominant_subnet || "192.168.0.0/16"}</span>
            <span className="text-white/20">//</span>
            <span className="text-[9px] text-zinc-400 font-sans">Dominant subnet</span>
          </div>
        </div>

        {/* Interactive Holographic Threat Card (Hover) */}
        <AnimatePresence>
          {activeNode && (
            <motion.div
              initial={{ opacity: 0, scale: 0.92, y: 6 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.92, y: 6 }}
              transition={{ duration: 0.15 }}
              className="pointer-events-none absolute z-20 w-56 rounded-2xl border border-primary/50 bg-black/95 p-3.5 shadow-2xl backdrop-blur-xl"
              style={{
                left: Math.min(Math.max(12, tooltipPos.x - 110), containerRef.current?.clientWidth - 236 || 80),
                top: Math.max(10, tooltipPos.y - 85),
                boxShadow: "0 12px 30px rgba(0,0,0,0.8), 0 0 0 1px rgba(56,189,248,0.35)",
              }}
            >
              <div className="flex items-center justify-between border-b border-white/10 pb-1.5">
                <div className="font-mono text-xs font-semibold text-primary truncate">
                  {activeNode.ip}
                </div>
                <span
                  className={`rounded-full border px-2 py-0.5 font-sans text-[9px] font-semibold uppercase tracking-wider ${
                    activeNode.isHot
                      ? "border-destructive/60 bg-destructive/15 text-destructive"
                      : "border-signal/60 bg-signal/15 text-signal"
                  }`}
                >
                  {activeNode.severity?.toUpperCase() || "HIGH"}
                </span>
              </div>
              <div className="mt-2 space-y-1 font-mono text-[10px] text-zinc-400">
                <div>VECTOR: <span className="text-white font-medium">{activeNode.vector || "UNKNOWN"}</span></div>
                <div>ACTIVITY: <span className="text-white font-medium">{activeNode.count || 1} EVENTS</span></div>
                <div className="text-primary/80 text-[8px] pt-0.5 font-sans">// 3D spatial vector targeted</div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Footer Metrics */}
      <div className="flex justify-between border-t border-white/[0.06] px-5 py-3 bg-white/[0.01] font-sans text-xs text-zinc-400">
        <span>{pad2(surface?.origins)} origins // {pad2(surface?.paths)} paths</span>
        <span className="text-emerald-400 font-medium font-mono">{surface ? `${surface.window_minutes}m window` : "--"}</span>
      </div>
    </div>
  );
}
