import { useEffect, useRef } from 'react';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';

const PEER_POSITIONS = {
  pc1: new THREE.Vector3(-4.2, 0.65, 0),
  pc2: new THREE.Vector3(4.2, 0.65, 0),
};

function addWorkstation(scene, x, colorHex, nodeId) {
  const group = new THREE.Group();
  group.position.set(x, 0, 0);
  group.userData.nodeId = nodeId;

  const accent = new THREE.Color(colorHex);
  const base = new THREE.Mesh(
    new THREE.BoxGeometry(2.2, 0.12, 1.5),
    new THREE.MeshStandardMaterial({ color: 0xE2DDD4, roughness: 0.9 }),
  );
  base.position.y = 0.08;
  group.add(base);

  const tower = new THREE.Mesh(
    new THREE.BoxGeometry(0.72, 1.28, 0.82),
    new THREE.MeshStandardMaterial({
      color: 0x292D2A,
      roughness: 0.6,
      metalness: 0.1,
      emissive: accent,
      emissiveIntensity: 0.06,
    }),
  );
  tower.position.set(-0.55, 0.78, 0.1);
  group.add(tower);

  const monitor = new THREE.Mesh(
    new THREE.BoxGeometry(1.25, 0.84, 0.1),
    new THREE.MeshStandardMaterial({
      color: 0x1F2320,
      roughness: 0.45,
      emissive: accent,
      emissiveIntensity: 0.08,
    }),
  );
  monitor.position.set(0.44, 1.2, -0.18);
  group.add(monitor);

  const stand = new THREE.Mesh(
    new THREE.BoxGeometry(0.1, 0.28, 0.1),
    new THREE.MeshStandardMaterial({ color: 0x9CA6A0, roughness: 0.7 }),
  );
  stand.position.set(0.44, 0.7, -0.18);
  group.add(stand);

  scene.add(group);
  return group;
}

function disposeScene(scene) {
  scene.traverse((object) => {
    object.geometry?.dispose();
    if (Array.isArray(object.material)) {
      object.material.forEach((material) => material.dispose());
    } else {
      object.material?.dispose();
    }
  });
}

export default function ThreeCanvas({
  selectedNode,
  onSelectNode,
  activity,
  tunnelState,
  isStale = false,
  telemetryError = false,
  endpoints = null,
  captureActive = false,
}) {
  const containerRef = useRef(null);
  const controlsRef = useRef(null);
  const resetCameraRef = useRef(null);
  const activityMarkerRef = useRef(null);
  const activityAnimationRef = useRef(null);
  const peerGroupsRef = useRef({});
  const tunnelMeshRef = useRef(null);
  const monitorMeshRef = useRef(null);
  const pcapMeshRef = useRef(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return undefined;

    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0xF5F2EC);
    scene.fog = new THREE.Fog(0xF5F2EC, 16, 36);

    const camera = new THREE.PerspectiveCamera(
      42,
      container.clientWidth / Math.max(container.clientHeight, 1),
      0.1,
      100,
    );
    camera.position.set(0, 7.2, 13.2);
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
    renderer.setSize(container.clientWidth, container.clientHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.75));
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    container.appendChild(renderer.domElement);

    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.08;
    controls.maxPolarAngle = Math.PI / 2 - 0.03;
    controls.minDistance = 5;
    controls.maxDistance = 22;
    controls.target.set(0, 0.35, 0);
    controlsRef.current = controls;
    resetCameraRef.current = () => {
      camera.position.set(0, 7.2, 13.2);
      controls.target.set(0, 0.35, 0);
      controls.update();
    };

    scene.add(new THREE.HemisphereLight(0xFFFFFF, 0xE5DFD5, 1.8));
    scene.add(new THREE.AmbientLight(0xEFEAE1, 0.4));
    const keyLight = new THREE.DirectionalLight(0xFFFBF2, 2.4);
    keyLight.position.set(-4, 10, 7);
    scene.add(keyLight);

    const grid = new THREE.GridHelper(22, 22, 0xD4CDC0, 0xE4DDD0);
    grid.position.y = 0.005;
    scene.add(grid);

    const pc1Running = endpoints?.pc1?.status === 'running';
    const pc2Running = endpoints?.pc2?.status === 'running';
    const pc1Color = pc1Running ? 0x4E8B72 : endpoints?.pc1?.status ? 0xE7A49A : 0x8E9692;
    const pc2Color = pc2Running ? 0x4E8B72 : endpoints?.pc2?.status ? 0xE7A49A : 0x8E9692;

    const clickTargets = [
      addWorkstation(scene, PEER_POSITIONS.pc1.x, pc1Color, 'pc1'),
      addWorkstation(scene, PEER_POSITIONS.pc2.x, pc2Color, 'pc2'),
    ];
    peerGroupsRef.current = { pc1: clickTargets[0], pc2: clickTargets[1] };

    const tunnelStatus = String(tunnelState || 'UNKNOWN').toUpperCase();
    let tunnelColor = 0x8E9692;
    let emissiveIntensity = 0.03;
    if (telemetryError) {
      tunnelColor = 0x8E9692;
      emissiveIntensity = 0.02;
    } else if (isStale) {
      tunnelColor = 0x9E6B20;
      emissiveIntensity = 0.05;
    } else if (tunnelStatus === 'ESTABLISHED') {
      tunnelColor = 0x4E8B72;
      emissiveIntensity = 0.07;
    } else if (tunnelStatus === 'DOWN') {
      tunnelColor = 0xE7A49A;
      emissiveIntensity = 0.06;
    } else if (tunnelStatus === 'NEGOTIATING') {
      tunnelColor = 0xE9C58D;
      emissiveIntensity = 0.05;
    }

    const tunnelCurve = new THREE.LineCurve3(
      new THREE.Vector3(-3.05, 1.2, 0),
      new THREE.Vector3(3.05, 1.2, 0),
    );
    const tunnelMaterial = new THREE.MeshStandardMaterial({
      color: tunnelColor,
      emissive: tunnelColor,
      emissiveIntensity,
      roughness: 0.5,
      metalness: 0.1,
    });
    const tunnel = new THREE.Mesh(
      new THREE.TubeGeometry(tunnelCurve, 32, 0.09, 10, false),
      tunnelMaterial,
    );
    tunnel.userData.nodeId = 'tunnel';
    scene.add(tunnel);
    clickTargets.push(tunnel);
    tunnelMeshRef.current = tunnel;

    // eBPF Kernel Observer Mesh - elevated above floor plane in front of tunnel
    const monitorPosition = new THREE.Vector3(0, 0.24, 2.0);
    const monitor = new THREE.Mesh(
      new THREE.BoxGeometry(1.25, 0.48, 0.6),
      new THREE.MeshStandardMaterial({
        color: 0x363D39,
        roughness: 0.7,
        emissive: 0x4E8B72,
        emissiveIntensity: 0.04,
      }),
    );
    monitor.position.copy(monitorPosition);
    monitor.userData.nodeId = 'ebpf';
    scene.add(monitor);
    clickTargets.push(monitor);
    monitorMeshRef.current = monitor;

    const collectorLinks = new THREE.Group();
    for (const peerPosition of [PEER_POSITIONS.pc1, PEER_POSITIONS.pc2]) {
      const points = [
        new THREE.Vector3(peerPosition.x * 0.78, 0.22, 0.15),
        new THREE.Vector3(0, 0.24, 2.0),
      ];
      const line = new THREE.Line(
        new THREE.BufferGeometry().setFromPoints(points),
        new THREE.LineBasicMaterial({ color: 0xACB6B0, transparent: true, opacity: 0.85 }),
      );
      collectorLinks.add(line);
    }
    scene.add(collectorLinks);

    // PCAP Observer Layer Mesh
    const pcapGroup = new THREE.Group();
    pcapGroup.position.set(0, 2.15, -0.2);
    pcapGroup.userData.nodeId = 'pcap';
    const pcapBody = new THREE.Mesh(
      new THREE.BoxGeometry(0.9, 0.38, 0.55),
      new THREE.MeshStandardMaterial({
        color: 0x2A302D,
        roughness: 0.65,
        metalness: 0.2,
        emissive: captureActive ? 0x4E8B72 : 0x8E9692,
        emissiveIntensity: captureActive ? 0.2 : 0.04,
      }),
    );
    pcapGroup.add(pcapBody);

    const pcapLens = new THREE.Mesh(
      new THREE.CylinderGeometry(0.09, 0.09, 0.06, 12),
      new THREE.MeshStandardMaterial({
        color: captureActive ? 0x4E8B72 : 0x727A77,
        emissive: captureActive ? 0x4E8B72 : 0x727A77,
        emissiveIntensity: captureActive ? 0.6 : 0.08,
      }),
    );
    pcapLens.rotation.x = Math.PI / 2;
    pcapLens.position.set(0, 0, 0.28);
    pcapGroup.add(pcapLens);

    const pcapTapPoints = [
      new THREE.Vector3(0, 1.95, -0.2),
      new THREE.Vector3(0, 1.29, 0),
    ];
    const pcapTapLine = new THREE.Line(
      new THREE.BufferGeometry().setFromPoints(pcapTapPoints),
      new THREE.LineBasicMaterial({
        color: captureActive ? 0x4E8B72 : 0xACB6B0,
        transparent: true,
        opacity: 0.85,
      }),
    );
    scene.add(pcapTapLine);
    scene.add(pcapGroup);
    clickTargets.push(pcapGroup);
    pcapMeshRef.current = pcapGroup;

    // Genuine Evidence-Driven Activity Marker
    const activityMarker = new THREE.Mesh(
      new THREE.SphereGeometry(0.16, 16, 12),
      new THREE.MeshBasicMaterial({ color: 0x4E8B72 }),
    );
    activityMarker.userData.nodeId = 'event';
    activityMarker.visible = false;
    scene.add(activityMarker);
    activityMarkerRef.current = activityMarker;
    clickTargets.push(activityMarker);

    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2();
    const handleClick = (event) => {
      const bounds = renderer.domElement.getBoundingClientRect();
      pointer.x = ((event.clientX - bounds.left) / bounds.width) * 2 - 1;
      pointer.y = -((event.clientY - bounds.top) / bounds.height) * 2 + 1;
      raycaster.setFromCamera(pointer, camera);
      const hit = raycaster.intersectObjects(clickTargets, true)[0]?.object;
      let target = hit;
      while (target && !target.userData.nodeId) target = target.parent;
      if (target?.userData.nodeId) {
        if (target.userData.nodeId === 'event') {
          onSelectNode('event', target.userData.event);
        } else {
          onSelectNode(target.userData.nodeId);
        }
      }
    };
    renderer.domElement.addEventListener('click', handleClick);

    let frameId;
    const animate = (now) => {
      frameId = window.requestAnimationFrame(animate);
      controls.update();

      const anim = activityAnimationRef.current;
      const marker = activityMarkerRef.current;
      if (anim && marker) {
        const reducedMotion = typeof window !== 'undefined'
          && window.matchMedia
          && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        const duration = reducedMotion ? 400 : 900;
        const progress = (now - anim.startedAt) / duration;
        if (progress >= 1) {
          marker.visible = false;
          activityAnimationRef.current = null;
        } else {
          marker.visible = true;
          if (reducedMotion) {
            marker.position.set(0, 1.2, 0.18);
          } else if (anim.eventType === 'XFRM_OUT') {
            marker.position.set(-3 + 6 * progress, 1.2, 0.18);
          } else if (anim.eventType === 'XFRM_IN') {
            marker.position.set(3 - 6 * progress, 1.2, 0.18);
          } else {
            marker.position.set(0, 0.35 + Math.sin(progress * Math.PI) * 0.4, 2.0);
          }
        }
      }

      renderer.render(scene, camera);
    };
    frameId = window.requestAnimationFrame(animate);

    const resizeObserver = new ResizeObserver(() => {
      if (container.clientWidth === 0 || container.clientHeight === 0) return;
      camera.aspect = container.clientWidth / container.clientHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(container.clientWidth, container.clientHeight);
    });
    resizeObserver.observe(container);

    return () => {
      resizeObserver.disconnect();
      window.cancelAnimationFrame(frameId);
      renderer.domElement.removeEventListener('click', handleClick);
      controls.dispose();
      disposeScene(scene);
      renderer.dispose();
      if (container.contains(renderer.domElement)) container.removeChild(renderer.domElement);
      controlsRef.current = null;
      resetCameraRef.current = null;
      activityMarkerRef.current = null;
      activityAnimationRef.current = null;
      peerGroupsRef.current = {};
      tunnelMeshRef.current = null;
      monitorMeshRef.current = null;
      pcapMeshRef.current = null;
    };
  }, [onSelectNode, tunnelState, isStale, telemetryError, endpoints, captureActive]);

  useEffect(() => {
    for (const [nodeId, group] of Object.entries(peerGroupsRef.current)) {
      group.scale.setScalar(nodeId === selectedNode ? 1.05 : 1);
    }
    if (tunnelMeshRef.current) {
      const isSelected = selectedNode === 'tunnel';
      tunnelMeshRef.current.scale.set(1, isSelected ? 1.3 : 1, isSelected ? 1.3 : 1);
      if (tunnelMeshRef.current.material) {
        tunnelMeshRef.current.material.emissiveIntensity = isSelected ? 0.25 : 0.06;
      }
    }
    if (monitorMeshRef.current) {
      const isSelected = selectedNode === 'ebpf';
      monitorMeshRef.current.scale.setScalar(isSelected ? 1.08 : 1);
      if (monitorMeshRef.current.material) {
        monitorMeshRef.current.material.emissiveIntensity = isSelected ? 0.25 : 0.04;
      }
    }
    if (pcapMeshRef.current) {
      const isSelected = selectedNode === 'pcap';
      pcapMeshRef.current.scale.setScalar(isSelected ? 1.08 : 1);
    }
  }, [selectedNode]);

  useEffect(() => {
    if (!activity || !activityMarkerRef.current) return;
    const eventType = activity.event?.eventType;
    if (eventType !== 'XFRM_OUT' && eventType !== 'XFRM_IN' && eventType !== 'SOCK_SEND') return;
    const markerColor = eventType === 'XFRM_OUT'
      ? 0x487291
      : eventType === 'XFRM_IN'
        ? 0x4E8B72
        : 0xE9C58D;
    activityMarkerRef.current.material.color.setHex(markerColor);
    activityMarkerRef.current.userData.event = activity.event;
    activityAnimationRef.current = {
      eventType,
      event: activity.event,
      startedAt: performance.now(),
    };
  }, [activity]);

  return (
    <div className="three-canvas">
      <div ref={containerRef} className="three-canvas-renderer" />
      <button
        className="scene-reset-button"
        type="button"
        onClick={() => resetCameraRef.current?.()}
      >
        Reset camera
      </button>
      <span className="scene-help">Drag to orbit · scroll to zoom · click PC1, PC2, Tunnel, eBPF, or PCAP Observer to inspect</span>
    </div>
  );
}
