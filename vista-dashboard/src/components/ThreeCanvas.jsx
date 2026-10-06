import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';

export default function ThreeCanvas({
  scenario,
  selectedNode,
  onSelectNode,
  onSelectPacket,
  cameraPreset,
  setCameraPreset
}) {
  const containerRef = useRef(null);
  const sceneRef = useRef(null);
  const cameraRef = useRef(null);
  const controlsRef = useRef(null);
  const rendererRef = useRef(null);
  const animFrameRef = useRef(null);
  
  // Dynamic objects refs for animation loop
  const tunnelMeshRef = useRef(null);
  const tunnelOuterRef = useRef(null);
  const packetsGroupRef = useRef(null);
  const aiCoreMeshRef = useRef(null);
  const aiRingsRef = useRef([]);
  const clickableObjectsRef = useRef([]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    // --- 1. SCENE SETUP ---
    const scene = new THREE.Scene();
    sceneRef.current = scene;
    scene.background = new THREE.Color(0x070b14);
    scene.fog = new THREE.FogExp2(0x070b14, 0.025);

    // Camera
    const camera = new THREE.PerspectiveCamera(
      45,
      container.clientWidth / container.clientHeight,
      0.1,
      100
    );
    camera.position.set(0, 7.5, 13.5);
    cameraRef.current = camera;

    // Renderer
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
    renderer.setSize(container.clientWidth, container.clientHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.3;
    container.appendChild(renderer.domElement);
    rendererRef.current = renderer;

    // Orbit Controls
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.05;
    controls.maxPolarAngle = Math.PI / 2 - 0.02;
    controls.minDistance = 3.5;
    controls.maxDistance = 26;
    controls.target.set(0, 0.8, 0);
    controlsRef.current = controls;

    // --- 2. LIGHTING ---
    const ambientLight = new THREE.AmbientLight(0x1a263d, 1.8);
    scene.add(ambientLight);

    const dirLight = new THREE.DirectionalLight(0xa5c9ff, 1.2);
    dirLight.position.set(10, 20, 10);
    scene.add(dirLight);

    const pc1Light = new THREE.PointLight(0x00f0ff, 2.5, 8);
    pc1Light.position.set(-4.5, 2.5, 0);
    scene.add(pc1Light);

    const pc2Light = new THREE.PointLight(0x00ff88, 2.5, 8);
    pc2Light.position.set(4.5, 2.5, 0);
    scene.add(pc2Light);

    const ebpfLight = new THREE.PointLight(0xffaa00, 3.2, 8);
    ebpfLight.position.set(0, -1.8, 2.2);
    scene.add(ebpfLight);

    // --- 3. CYBER GRID FLOOR & DOCKER BOUNDARY ---
    const gridHelper = new THREE.GridHelper(26, 26, 0x00f0ff, 0x142038);
    gridHelper.position.y = -0.01;
    scene.add(gridHelper);

    // Concentric range circles
    const ringGeo = new THREE.RingGeometry(2.8, 2.85, 64);
    const ringMat = new THREE.MeshBasicMaterial({ color: 0x00f0ff, side: THREE.DoubleSide, transparent: true, opacity: 0.18 });
    const ringMesh1 = new THREE.Mesh(ringGeo, ringMat);
    ringMesh1.rotation.x = -Math.PI / 2;
    ringMesh1.position.set(0, 0.01, 0);
    scene.add(ringMesh1);

    const ringMesh2 = ringMesh1.clone();
    ringMesh2.scale.set(2.4, 2.4, 1);
    scene.add(ringMesh2);

    // Docker Host Holographic Bounding Box (Enclosing PC1 and PC2)
    const hostBoxGeo = new THREE.BoxGeometry(14.0, 4.0, 5.0);
    const hostBoxLines = new THREE.LineSegments(
      new THREE.EdgesGeometry(hostBoxGeo),
      new THREE.LineBasicMaterial({ color: 0x00f0ff, transparent: true, opacity: 0.22 })
    );
    hostBoxLines.position.set(0, 2.0, 0);
    scene.add(hostBoxLines);

    // --- 4. CREATE 3D PC NODES (SYMMETRIC DUPLEX) ---
    const clickables = [];

    const createPedestal = (x, z, color) => {
      const pedGeo = new THREE.CylinderGeometry(1.4, 1.6, 0.2, 32);
      const pedMat = new THREE.MeshStandardMaterial({
        color: 0x0f172a,
        roughness: 0.4,
        metalness: 0.8,
        emissive: new THREE.Color(color),
        emissiveIntensity: 0.15
      });
      const ped = new THREE.Mesh(pedGeo, pedMat);
      ped.position.set(x, 0.1, z);
      scene.add(ped);

      const glowRing = new THREE.Mesh(
        new THREE.TorusGeometry(1.45, 0.03, 16, 64),
        new THREE.MeshBasicMaterial({ color })
      );
      glowRing.rotation.x = Math.PI / 2;
      glowRing.position.set(x, 0.2, z);
      scene.add(glowRing);
    };

    const createWorkstation = (x, color, nodeId, labelText) => {
      createPedestal(x, 0, color);
      const group = new THREE.Group();
      group.position.set(x, 1.1, 0);

      // Curved / wide monitor screen
      const screenGeo = new THREE.BoxGeometry(1.6, 1.1, 0.1);
      const screenMat = new THREE.MeshStandardMaterial({
        color,
        roughness: 0.2,
        metalness: 0.85,
        emissive: color,
        emissiveIntensity: 0.35
      });
      const screen = new THREE.Mesh(screenGeo, screenMat);
      screen.position.set(0, 0.4, 0);
      group.add(screen);

      // Stand
      const stand = new THREE.Mesh(
        new THREE.BoxGeometry(0.2, 0.5, 0.15),
        new THREE.MeshStandardMaterial({ color: 0x334155, metalness: 0.8 })
      );
      stand.position.set(0, -0.3, 0);
      group.add(stand);

      // PC Tower Unit
      const tower = new THREE.Mesh(
        new THREE.BoxGeometry(0.5, 1.2, 1.0),
        new THREE.MeshStandardMaterial({
          color: 0x0f172a,
          metalness: 0.7,
          roughness: 0.3,
          emissive: color,
          emissiveIntensity: 0.12
        })
      );
      tower.position.set(x < 0 ? 1.1 : -1.1, 0.2, 0);
      group.add(tower);

      // Docker unprivileged container wireframe wrapper
      const dockerBox = new THREE.LineSegments(
        new THREE.EdgesGeometry(new THREE.BoxGeometry(2.6, 2.2, 2.0)),
        new THREE.LineBasicMaterial({ color, transparent: true, opacity: 0.55 })
      );
      dockerBox.position.set(x < 0 ? 0.4 : -0.4, 0.3, 0);
      group.add(dockerBox);

      group.userData = { nodeId };
      scene.add(group);
      clickables.push(group);
      return group;
    };

    // 🖥️ PC 1 (Workstation A)
    createWorkstation(-4.5, 0x00f0ff, 'pc1', 'PC 1 (Initiator)');

    // 🖥️ PC 2 (Workstation B)
    createWorkstation(4.5, 0x00ff88, 'pc2', 'PC 2 (Responder)');

    // 🧠 VISTA AI INFERENCE CORE (Fed by Host eBPF) - Floating Kernel Core below
    const ebpfGroup = new THREE.Group();
    ebpfGroup.position.set(0, -2.2, 2.2);

    const coreMesh = new THREE.Mesh(
      new THREE.OctahedronGeometry(1.1, 1),
      new THREE.MeshStandardMaterial({
        color: 0xffaa00,
        metalness: 0.9,
        roughness: 0.1,
        wireframe: true,
        emissive: 0xffaa00,
        emissiveIntensity: 0.6
      })
    );
    ebpfGroup.add(coreMesh);
    aiCoreMeshRef.current = coreMesh;

    // Inner glowing sphere
    ebpfGroup.add(new THREE.Mesh(
      new THREE.SphereGeometry(0.65, 16, 16),
      new THREE.MeshBasicMaterial({ color: 0xffcc00 })
    ));

    // Rotating orbital telemetry rings
    const rings = [];
    [1.5, 1.9, 2.3].forEach((radius, idx) => {
      const ring = new THREE.Mesh(
        new THREE.TorusGeometry(radius, 0.02, 16, 64),
        new THREE.MeshBasicMaterial({
          color: idx === 0 ? 0xffaa00 : (idx === 1 ? 0x00f0ff : 0x00ff88),
          transparent: true,
          opacity: 0.7
        })
      );
      ring.rotation.x = Math.PI / (idx + 2);
      ring.rotation.y = Math.PI / (idx + 3);
      ebpfGroup.add(ring);
      rings.push(ring);
    });
    aiRingsRef.current = rings;

    ebpfGroup.userData = { nodeId: 'vistaAi' };
    scene.add(ebpfGroup);
    clickables.push(ebpfGroup);

    // --- 5. DIRECT FULL-DUPLEX IPSEC / ESP TUNNEL (PC 1 ⇄ PC 2) ---
    const tunnelCurve = new THREE.LineCurve3(
      new THREE.Vector3(-3.2, 1.2, 0),
      new THREE.Vector3(3.2, 1.2, 0)
    );
    const tunnelGeo = new THREE.TubeGeometry(tunnelCurve, 24, 0.24, 16, false);
    const tunnelMat = new THREE.MeshStandardMaterial({
      color: 0x00f0ff,
      emissive: 0x00f0ff,
      emissiveIntensity: 0.8,
      transparent: true,
      opacity: 0.65,
      roughness: 0.2
    });
    const tunnelMesh = new THREE.Mesh(tunnelGeo, tunnelMat);
    scene.add(tunnelMesh);
    tunnelMeshRef.current = tunnelMesh;

    // Outer pulsating wireframe sleeve
    const tunnelOuterGeo = new THREE.TubeGeometry(tunnelCurve, 24, 0.44, 16, false);
    const tunnelOuterMat = new THREE.MeshBasicMaterial({
      color: 0x00f0ff,
      transparent: true,
      opacity: 0.22,
      wireframe: true
    });
    const tunnelOuter = new THREE.Mesh(tunnelOuterGeo, tunnelOuterMat);
    scene.add(tunnelOuter);
    tunnelOuterRef.current = tunnelOuter;

    tunnelMesh.userData = { nodeId: 'tunnel' };
    clickables.push(tunnelMesh);

    // --- 6. OPTION B HOST eBPF PASSIVE TELEMETRY BEAMS ---
    const beamsGroup = new THREE.Group();
    const beam1 = new THREE.Line(
      new THREE.BufferGeometry().setFromPoints([
        new THREE.Vector3(-3.5, 0.2, 0),
        new THREE.Vector3(0, -2.2, 2.2)
      ]),
      new THREE.LineBasicMaterial({ color: 0x00f0ff, transparent: true, opacity: 0.45 })
    );
    beamsGroup.add(beam1);

    const beam2 = new THREE.Line(
      new THREE.BufferGeometry().setFromPoints([
        new THREE.Vector3(3.5, 0.2, 0),
        new THREE.Vector3(0, -2.2, 2.2)
      ]),
      new THREE.LineBasicMaterial({ color: 0x00ff88, transparent: true, opacity: 0.45 })
    );
    beamsGroup.add(beam2);
    scene.add(beamsGroup);

    // --- 7. ANIMATED FULL-DUPLEX PACKETS SYSTEM ---
    const packetsGroup = new THREE.Group();
    const PACKET_COUNT = 36;
    const packetMeshes = [];
    const packetGeo = new THREE.SphereGeometry(0.12, 16, 16);

    for (let i = 0; i < PACKET_COUNT; i++) {
      const pMat = new THREE.MeshBasicMaterial({ color: 0x00ffcc });
      const pMesh = new THREE.Mesh(packetGeo, pMat);
      const isOutbound = i % 2 === 0; // 50% Outbound, 50% Inbound in duplex

      pMesh.userData = {
        progress: (i / PACKET_COUNT),
        speed: 0.005 + (Math.random() * 0.004),
        direction: isOutbound ? 1 : -1,
        isPacket: true,
        packetId: `ESP-PKT-${1000 + i}`,
        spi: isOutbound ? '0xb3b1799d' : '0x49c812a0',
        seq: 4800 + i * 16,
        size: Math.floor(120 + Math.random() * 1200)
      };
      packetsGroup.add(pMesh);
      packetMeshes.push(pMesh);
      clickables.push(pMesh);
    }
    scene.add(packetsGroup);
    packetsGroupRef.current = packetMeshes;

    clickableObjectsRef.current = clickables;

    // --- 8. RAYCASTING INTERACTION ---
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();

    const handlePointerMove = (e) => {
      const rect = container.getBoundingClientRect();
      mouse.x = ((e.clientX - rect.left) / container.clientWidth) * 2 - 1;
      mouse.y = -((e.clientY - rect.top) / container.clientHeight) * 2 + 1;
      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(clickableObjectsRef.current, true);
      container.style.cursor = intersects.length > 0 ? 'pointer' : 'default';
    };

    const handleClick = (e) => {
      const rect = container.getBoundingClientRect();
      mouse.x = ((e.clientX - rect.left) / container.clientWidth) * 2 - 1;
      mouse.y = -((e.clientY - rect.top) / container.clientHeight) * 2 + 1;
      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(clickableObjectsRef.current, true);

      if (intersects.length > 0) {
        let hit = intersects[0].object;
        while (hit.parent && !hit.userData.nodeId && !hit.userData.isPacket) {
          hit = hit.parent;
        }
        if (hit.userData.isPacket) {
          onSelectPacket && onSelectPacket(hit.userData);
        } else if (hit.userData.nodeId) {
          onSelectNode && onSelectNode(hit.userData.nodeId);
        }
      }
    };

    container.addEventListener('mousemove', handlePointerMove);
    container.addEventListener('click', handleClick);

    // --- 9. ANIMATION LOOP ---
    const clock = new THREE.Clock();
    const startX = -3.2;
    const endX = 3.2;
    const tunnelLength = endX - startX;

    const animate = () => {
      animFrameRef.current = requestAnimationFrame(animate);
      const delta = clock.getDelta();
      const time = clock.getElapsedTime();

      controls.update();

      // Rotate Option B eBPF Core
      if (aiCoreMeshRef.current) {
        aiCoreMeshRef.current.rotation.x += delta * 0.5;
        aiCoreMeshRef.current.rotation.y += delta * 0.7;
      }
      if (aiRingsRef.current) {
        aiRingsRef.current.forEach((ring, idx) => {
          ring.rotation.z += delta * (0.8 - idx * 0.2);
          ring.rotation.y += delta * 0.4;
        });
      }

      // Animate tunnel pulsing
      if (tunnelOuterRef.current) {
        const pulse = 0.35 + Math.sin(time * 4) * 0.12;
        tunnelOuterRef.current.scale.set(1, 1 + Math.sin(time * 6) * 0.08, 1);
        tunnelOuterRef.current.material.opacity = pulse;
      }

      // Animate full-duplex packets along IPsec tunnel
      if (packetsGroupRef.current) {
        const speedMultiplier = scenario.particleSpeed || 1.0;
        packetsGroupRef.current.forEach((pMesh) => {
          let p = pMesh.userData.progress;
          p += pMesh.userData.speed * speedMultiplier * delta * 8;
          if (p > 1) p = 0;
          pMesh.userData.progress = p;

          const currX = pMesh.userData.direction === 1
            ? startX + (p * tunnelLength)
            : endX - (p * tunnelLength);

          const angle = p * Math.PI * 6 + time * 4;
          const radius = 0.28;
          const currY = 1.2 + Math.sin(angle) * radius;
          const currZ = Math.cos(angle) * radius;

          pMesh.position.set(currX, currY, currZ);
        });
      }

      renderer.render(scene, camera);
    };

    animate();

    const handleResize = () => {
      if (!container) return;
      camera.aspect = container.clientWidth / container.clientHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(container.clientWidth, container.clientHeight);
    };
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      container.removeEventListener('mousemove', handlePointerMove);
      container.removeEventListener('click', handleClick);
      cancelAnimationFrame(animFrameRef.current);
      if (renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
      renderer.dispose();
    };
  }, []);

  // Sync color changes on scenario switch
  useEffect(() => {
    if (!tunnelMeshRef.current || !tunnelOuterRef.current) return;
    const targetColor = new THREE.Color(scenario.tunnelColor || 0x00f0ff);
    const packetColor = new THREE.Color(scenario.packetColor || 0x00ffcc);

    tunnelMeshRef.current.material.color = targetColor;
    tunnelMeshRef.current.material.emissive = targetColor;
    tunnelOuterRef.current.material.color = targetColor;

    if (packetsGroupRef.current) {
      packetsGroupRef.current.forEach((pMesh) => {
        pMesh.material.color = packetColor;
      });
    }
  }, [scenario]);

  // Handle camera presets
  useEffect(() => {
    if (!cameraRef.current || !controlsRef.current) return;
    const camera = cameraRef.current;
    const controls = controlsRef.current;

    switch (cameraPreset) {
      case 'tunnel':
        camera.position.set(0, 2.8, 5.0);
        controls.target.set(0, 1.2, 0);
        break;
      case 'pc1':
        camera.position.set(-5.5, 2.5, 3.5);
        controls.target.set(-4.5, 1.2, 0);
        break;
      case 'pc2':
        camera.position.set(5.5, 2.5, 3.5);
        controls.target.set(4.5, 1.2, 0);
        break;
      case 'aiCore':
      case 'ebpf':
        camera.position.set(0, -0.4, 5.6);
        controls.target.set(0, -2.2, 2.2);
        break;
      case 'overview':
      default:
        camera.position.set(0, 7.5, 13.5);
        controls.target.set(0, 0.8, 0);
        break;
    }
  }, [cameraPreset]);

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%' }}>
      <div ref={containerRef} style={{ width: '100%', height: '100%', outline: 'none' }} />

      {/* Floating 3D Node Labels in canvas overlay */}
      <div style={{ position: 'absolute', top: 20, left: 24, pointerEvents: 'none' }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '6px 12px',
          background: 'rgba(7, 11, 20, 0.75)',
          backdropFilter: 'blur(10px)',
          border: '1px solid rgba(0, 240, 255, 0.25)',
          borderRadius: '8px',
          fontSize: '11px',
          fontFamily: 'var(--font-mono)',
          color: 'var(--cyan)'
        }}>
          <span className="status-dot online"></span>
          <span>PC-TO-PC FULL-DUPLEX IPSEC TOPOLOGY (OPTION B eBPF MONITOR)</span>
        </div>
      </div>

      {/* Quick Camera Preset Selector in bottom-left */}
      <div style={{
        position: 'absolute',
        bottom: 24,
        left: 24,
        display: 'flex',
        gap: '6px',
        background: 'rgba(7, 11, 20, 0.75)',
        backdropFilter: 'blur(12px)',
        padding: '6px',
        borderRadius: '10px',
        border: '1px solid var(--border-subtle)',
        zIndex: 10
      }}>
        <button
          className={`cyber-btn ${cameraPreset === 'overview' ? 'active' : ''}`}
          onClick={() => setCameraPreset('overview')}
        >
          Overview
        </button>
        <button
          className={`cyber-btn ${cameraPreset === 'tunnel' ? 'active' : ''}`}
          onClick={() => setCameraPreset('tunnel')}
        >
          🔐 Duplex Tunnel
        </button>
        <button
          className={`cyber-btn ${cameraPreset === 'pc1' ? 'active' : ''}`}
          onClick={() => setCameraPreset('pc1')}
        >
          🖥️ PC 1
        </button>
        <button
          className={`cyber-btn ${cameraPreset === 'pc2' ? 'active' : ''}`}
          onClick={() => setCameraPreset('pc2')}
        >
          🖥️ PC 2
        </button>
        <button
          className={`cyber-btn ${cameraPreset === 'aiCore' ? 'active' : ''}`}
          onClick={() => setCameraPreset('aiCore')}
        >
          🧠 VISTA AI Core
        </button>
      </div>

      <div style={{
        position: 'absolute',
        bottom: 24,
        right: 24,
        fontSize: '11px',
        color: 'var(--text-dim)',
        fontFamily: 'var(--font-mono)',
        background: 'rgba(7, 11, 20, 0.65)',
        padding: '6px 12px',
        borderRadius: '6px',
        pointerEvents: 'none'
      }}>
        🖱️ Orbit: Left-Click+Drag | Zoom: Scroll | Pan: Right-Click+Drag | Click PC/Packet for Inspector
      </div>
    </div>
  );
}
