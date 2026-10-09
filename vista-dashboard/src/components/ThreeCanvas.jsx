import { useEffect, useRef } from 'react';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';

const PEER_POSITIONS = {
  pc1: new THREE.Vector3(-4.2, 0.65, 0),
  pc2: new THREE.Vector3(4.2, 0.65, 0),
};

function addWorkstation(scene, x, color, nodeId) {
  const group = new THREE.Group();
  group.position.set(x, 0, 0);
  group.userData.nodeId = nodeId;

  const accent = new THREE.Color(color);
  const base = new THREE.Mesh(
    new THREE.BoxGeometry(2.2, 0.12, 1.5),
    new THREE.MeshStandardMaterial({ color: 0x19232d, roughness: 0.8 }),
  );
  base.position.y = 0.08;
  group.add(base);

  const tower = new THREE.Mesh(
    new THREE.BoxGeometry(0.72, 1.28, 0.82),
    new THREE.MeshStandardMaterial({
      color: 0x263440,
      roughness: 0.55,
      metalness: 0.15,
      emissive: accent,
      emissiveIntensity: 0.035,
    }),
  );
  tower.position.set(-0.55, 0.78, 0.1);
  group.add(tower);

  const monitor = new THREE.Mesh(
    new THREE.BoxGeometry(1.25, 0.84, 0.1),
    new THREE.MeshStandardMaterial({
      color: 0x17232d,
      roughness: 0.45,
      emissive: accent,
      emissiveIntensity: 0.08,
    }),
  );
  monitor.position.set(0.44, 1.2, -0.18);
  group.add(monitor);

  const stand = new THREE.Mesh(
    new THREE.BoxGeometry(0.1, 0.28, 0.1),
    new THREE.MeshStandardMaterial({ color: 0x81909e, roughness: 0.7 }),
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
}) {
  const containerRef = useRef(null);
  const controlsRef = useRef(null);
  const resetCameraRef = useRef(null);
  const activityMarkerRef = useRef(null);
  const activityAnimationRef = useRef(null);
  const peerGroupsRef = useRef({});

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return undefined;

    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x101820);
    scene.fog = new THREE.Fog(0x101820, 19, 36);

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

    scene.add(new THREE.HemisphereLight(0xdce8f1, 0x25313a, 2));
    const keyLight = new THREE.DirectionalLight(0xffffff, 2.2);
    keyLight.position.set(-3, 9, 6);
    scene.add(keyLight);

    const grid = new THREE.GridHelper(22, 22, 0x3b4d5a, 0x25313a);
    grid.position.y = 0.005;
    scene.add(grid);

    const clickTargets = [
      addWorkstation(scene, PEER_POSITIONS.pc1.x, 0x4d91ba, 'pc1'),
      addWorkstation(scene, PEER_POSITIONS.pc2.x, 0x5c9d79, 'pc2'),
    ];
    peerGroupsRef.current = { pc1: clickTargets[0], pc2: clickTargets[1] };

    const tunnelStatus = String(tunnelState || 'UNKNOWN').toUpperCase();
    const tunnelColor = tunnelStatus === 'ESTABLISHED'
      ? 0x4b9a6d
      : tunnelStatus === 'DOWN'
        ? 0xb64e4e
        : tunnelStatus === 'NEGOTIATING'
          ? 0xc0913e
          : 0x8193a1;
    const tunnelCurve = new THREE.LineCurve3(
      new THREE.Vector3(-3.05, 1.2, 0),
      new THREE.Vector3(3.05, 1.2, 0),
    );
    const tunnelMaterial = new THREE.MeshStandardMaterial({
      color: tunnelColor,
      emissive: tunnelColor,
      emissiveIntensity: 0.08,
      roughness: 0.5,
      metalness: 0.15,
    });
    const tunnel = new THREE.Mesh(
      new THREE.TubeGeometry(tunnelCurve, 32, 0.09, 10, false),
      tunnelMaterial,
    );
    tunnel.userData.nodeId = 'tunnel';
    scene.add(tunnel);
    clickTargets.push(tunnel);

    const monitorPosition = new THREE.Vector3(0, -1.45, 1.25);
    const monitor = new THREE.Mesh(
      new THREE.BoxGeometry(1.25, 0.48, 0.6),
      new THREE.MeshStandardMaterial({
        color: 0x283a46,
        roughness: 0.65,
        emissive: 0x4d91ba,
        emissiveIntensity: 0.04,
      }),
    );
    monitor.position.copy(monitorPosition);
    scene.add(monitor);

    const collectorLinks = new THREE.Group();
    for (const peerPosition of [PEER_POSITIONS.pc1, PEER_POSITIONS.pc2]) {
      const points = [
        new THREE.Vector3(peerPosition.x * 0.78, 0.22, 0.15),
        new THREE.Vector3(0, -1.15, 1.25),
      ];
      const line = new THREE.Line(
        new THREE.BufferGeometry().setFromPoints(points),
        new THREE.LineBasicMaterial({ color: 0x657b89, transparent: true, opacity: 0.75 }),
      );
      collectorLinks.add(line);
    }
    scene.add(collectorLinks);

    const activityMarker = new THREE.Mesh(
      new THREE.SphereGeometry(0.16, 16, 12),
      new THREE.MeshBasicMaterial({ color: 0x6db6db }),
    );
    activityMarker.visible = false;
    scene.add(activityMarker);
    activityMarkerRef.current = activityMarker;

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
      if (target?.userData.nodeId === 'pc1' || target?.userData.nodeId === 'pc2') {
        onSelectNode(target.userData.nodeId);
      }
    };
    renderer.domElement.addEventListener('click', handleClick);

    let frameId;
    const animate = (now) => {
      frameId = window.requestAnimationFrame(animate);
      controls.update();

      const animation = activityAnimationRef.current;
      const marker = activityMarkerRef.current;
      if (animation && marker) {
        const progress = (now - animation.startedAt) / 900;
        if (progress >= 1) {
          marker.visible = false;
          activityAnimationRef.current = null;
        } else {
          marker.visible = true;
          if (animation.eventType === 'XFRM_OUT') {
            marker.position.set(-3 + 6 * progress, 1.2, 0.18);
          } else if (animation.eventType === 'XFRM_IN') {
            marker.position.set(3 - 6 * progress, 1.2, 0.18);
          } else {
            marker.position.set(0, -1.45 + Math.sin(progress * Math.PI) * 0.6, 1.25);
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
    };
  }, [onSelectNode, tunnelState]);

  useEffect(() => {
    for (const [nodeId, group] of Object.entries(peerGroupsRef.current)) {
      group.scale.setScalar(nodeId === selectedNode ? 1.04 : 1);
    }
  }, [selectedNode]);

  useEffect(() => {
    if (!activity || !activityMarkerRef.current) return;
    const eventType = activity.event?.eventType;
    if (eventType !== 'XFRM_OUT' && eventType !== 'XFRM_IN' && eventType !== 'SOCK_SEND') return;
    const markerColor = eventType === 'XFRM_OUT'
      ? 0x75b9df
      : eventType === 'XFRM_IN'
        ? 0x83b891
        : 0xb6a16f;
    activityMarkerRef.current.material.color.setHex(markerColor);
    activityAnimationRef.current = { eventType, startedAt: performance.now() };
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
      <span className="scene-help">Drag to orbit · scroll to zoom</span>
    </div>
  );
}
