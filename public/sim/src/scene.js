/**
 * Three.js 3D Interactive Topology Scene for Sentinel-X Simulation.
 * Implements Star Topology, PBR Studio Lighting, Procedural 3D Composite Hosts,
 * Link Curves, Animated Packet Transit, and CSS2D Labels.
 */

import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { RoomEnvironment } from 'three/addons/environments/RoomEnvironment.js';

// Pre-allocated math scratchpads (Zero-GC render loop)
const _vec3 = new THREE.Vector3();
const _vec3B = new THREE.Vector3();

export class SimScene {
  constructor(canvasContainer, callbacks = {}) {
    this.container = canvasContainer;
    this.callbacks = callbacks;
    this.width = canvasContainer.clientWidth || window.innerWidth;
    this.height = canvasContainer.clientHeight || window.innerHeight;

    // Detect software WebGL
    this.isSoftwareGl = (() => {
      try {
        const gl = document.createElement('canvas').getContext('webgl2');
        if (!gl) return true;
        const ext = gl.getExtension('WEBGL_debug_renderer_info');
        const param = ext ? ext.UNMASKED_RENDERER_WEBGL : gl.RENDERER;
        const gpu = String(gl.getParameter(param));
        gl.getExtension('WEBGL_lose_context')?.loseContext();
        return /SwiftShader|llvmpipe|softpipe|Software|Basic Render/i.test(gpu);
      } catch (e) {
        return true;
      }
    })();

    // Renderer setup
    this.renderer = new THREE.WebGLRenderer({
      antialias: !this.isSoftwareGl,
      powerPreference: 'high-performance',
      alpha: false
    });
    this.renderer.setSize(this.width, this.height);
    this.renderer.setPixelRatio(this.isSoftwareGl ? 1 : Math.min(window.devicePixelRatio, 2));
    this.renderer.outputColorSpace = THREE.SRGBColorSpace;
    this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
    this.renderer.toneMappingExposure = 1.1;
    this.renderer.shadowMap.enabled = !this.isSoftwareGl;
    this.renderer.shadowMap.type = THREE.PCFSoftShadowMap;

    this.container.appendChild(this.renderer.domElement);

    // Scene & Fog
    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color(0x0a0e17);
    this.scene.fog = new THREE.FogExp2(0x0a0e17, 0.022);

    // Camera
    this.camera = new THREE.PerspectiveCamera(45, this.width / this.height, 0.5, 200);
    this.camera.position.set(0, 15, 22);

    // OrbitControls
    this.controls = new OrbitControls(this.camera, this.renderer.domElement);
    this.controls.enableDamping = !this.isSoftwareGl;
    this.controls.dampingFactor = 0.05;
    this.controls.maxPolarAngle = Math.PI / 2.05; // Don't go below floor
    this.controls.minDistance = 6;
    this.controls.maxDistance = 55;
    this.controls.target.set(0, 0, 0);

    this.presetTransitionActive = false;
    this.isUserInteracting = false;
    this.controls.addEventListener('start', () => {
      this.isUserInteracting = true;
      this.presetTransitionActive = false;
      this.callbacks.onCameraMove?.();
    });
    this.controls.addEventListener('change', () => {
      if (this.isUserInteracting) {
        this.callbacks.onCameraMove?.();
      }
    });
    this.controls.addEventListener('end', () => {
      this.isUserInteracting = false;
    });
    this.renderer.domElement.addEventListener('wheel', () => {
      this.callbacks.onCameraMove?.();
    }, { passive: true });

    // Lighting
    this.setupLighting();

    // Node Positions in 3D Space (Star topology)
    this.hostPositions = {
      switch: new THREE.Vector3(0, 0, 0),
      router: new THREE.Vector3(0, 0, -8),
      victim: new THREE.Vector3(-9, 0, 4),
      attacker: new THREE.Vector3(9, 0, 4),
      bystander: new THREE.Vector3(-8, 0, -5)
    };

    // Camera Presets
    this.cameraPresets = {
      overview: { pos: new THREE.Vector3(0, 16, 21), target: new THREE.Vector3(0, 0, -0.5) },
      victim: { pos: new THREE.Vector3(-8, 7, 11), target: new THREE.Vector3(-8, 0.8, 3.8) },
      router: { pos: new THREE.Vector3(0, 7, -1), target: new THREE.Vector3(0, 0.8, -8) },
      attacker: { pos: new THREE.Vector3(8, 7, 11), target: new THREE.Vector3(8, 0.8, 3.8) },
      log: { pos: new THREE.Vector3(-3, 11, 15), target: new THREE.Vector3(-3, 0, 3) }
    };

    this.targetCameraPos = this.cameraPresets.overview.pos.clone();
    this.targetControlsTarget = this.cameraPresets.overview.target.clone();

    // Meshes and Visual Groups
    this.nodes = {};
    this.linkLines = {};
    this.packetObjects = [];
    this.activeAnimations = [];

    this.buildFloor();
    this.buildTopology();

    // Resize Handler
    this.onWindowResize = this.onWindowResize.bind(this);
    window.addEventListener('resize', this.onWindowResize);

    // Render loop
    this.clock = new THREE.Clock();
    this.animate = this.animate.bind(this);
    this.rafId = requestAnimationFrame(this.animate);
  }

  setupLighting() {
    // Mandatory Studio Environment Reflection
    try {
      const pmrem = new THREE.PMREMGenerator(this.renderer);
      this.scene.environment = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;
      pmrem.dispose();
    } catch (e) {
      console.warn('RoomEnvironment skipped:', e);
    }

    // Hemisphere Light (Cool sky / warm ground fill)
    const hemiLight = new THREE.HemisphereLight(0x7ea0d0, 0x1f2430, 0.85);
    this.scene.add(hemiLight);

    // Directional Key Light
    const dirLight = new THREE.DirectionalLight(0xfff3e0, 1.4);
    dirLight.position.set(12, 20, 15);
    dirLight.castShadow = !this.isSoftwareGl;
    if (dirLight.castShadow) {
      dirLight.shadow.mapSize.width = 1024;
      dirLight.shadow.mapSize.height = 1024;
      dirLight.shadow.camera.near = 0.5;
      dirLight.shadow.camera.far = 60;
      const d = 16;
      dirLight.shadow.camera.left = -d;
      dirLight.shadow.camera.right = d;
      dirLight.shadow.camera.top = d;
      dirLight.shadow.camera.bottom = -d;
      dirLight.shadow.bias = -0.0005;
      dirLight.shadow.normalBias = 0.02;
    }
    this.scene.add(dirLight);

    // Subtle blue accent rim light
    const rimLight = new THREE.DirectionalLight(0x38bdf8, 0.4);
    rimLight.position.set(-15, 8, -15);
    this.scene.add(rimLight);
  }

  buildFloor() {
    // Floor Grid Plane
    const floorGeo = new THREE.PlaneGeometry(120, 120);
    const floorMat = new THREE.MeshStandardMaterial({
      color: 0x0c111d,
      roughness: 0.85,
      metalness: 0.2
    });
    const floor = new THREE.Mesh(floorGeo, floorMat);
    floor.rotation.x = -Math.PI / 2;
    floor.position.y = -0.01;
    floor.receiveShadow = !this.isSoftwareGl;
    this.scene.add(floor);

    // Procedural Grid Overlay
    const grid = new THREE.GridHelper(70, 35, 0x1e293b, 0x131d2e);
    grid.position.y = 0;
    this.scene.add(grid);
  }

  createContactShadow(radius = 1.6) {
    const geo = new THREE.CircleGeometry(radius, 32);
    const mat = new THREE.MeshBasicMaterial({
      color: 0x000000,
      transparent: true,
      opacity: 0.45,
      depthWrite: false
    });
    const shadow = new THREE.Mesh(geo, mat);
    shadow.rotation.x = -Math.PI / 2;
    shadow.position.y = 0.01;
    return shadow;
  }

  buildTopology() {
    // 1. Central Switch (Flat industrial chassis with port LEDs)
    const switchGroup = new THREE.Group();
    const switchBodyGeo = new THREE.BoxGeometry(3.6, 0.6, 2.6);
    const switchBodyMat = new THREE.MeshStandardMaterial({
      color: 0x1e293b,
      metalness: 0.7,
      roughness: 0.35
    });
    const switchMesh = new THREE.Mesh(switchBodyGeo, switchBodyMat);
    switchMesh.position.y = 0.3;
    switchMesh.castShadow = !this.isSoftwareGl;
    switchMesh.receiveShadow = !this.isSoftwareGl;
    switchGroup.add(switchMesh);

    // Switch Faceplate Accent
    const faceplateGeo = new THREE.BoxGeometry(3.62, 0.4, 0.08);
    const faceplateMat = new THREE.MeshStandardMaterial({
      color: 0x0f172a,
      roughness: 0.4
    });
    const faceplate = new THREE.Mesh(faceplateGeo, faceplateMat);
    faceplate.position.set(0, 0.3, 1.31);
    switchGroup.add(faceplate);

    // 4 Switch Port LED indicators
    this.switchPortLeds = [];
    this.switchLedPulse = 0; // set on switch transit, decays in animate()
    const ledPositions = [-1.1, -0.37, 0.37, 1.1];
    for (let i = 0; i < 4; i++) {
      const ledGeo = new THREE.CylinderGeometry(0.06, 0.06, 0.08, 12);
      const ledMat = new THREE.MeshBasicMaterial({ color: 0x10b981 });
      const led = new THREE.Mesh(ledGeo, ledMat);
      led.rotation.x = Math.PI / 2;
      led.position.set(ledPositions[i], 0.32, 1.36);
      switchGroup.add(led);
      this.switchPortLeds.push(led);
    }

    switchGroup.add(this.createContactShadow(2.2));
    switchGroup.position.copy(this.hostPositions.switch);
    this.scene.add(switchGroup);
    this.nodes.switch = switchGroup;

    // 2. Router & Internet Cloud (North)
    this.nodes.router = this.buildRouter();
    this.scene.add(this.nodes.router);

    // 3. Victim Laptop (South-West)
    this.nodes.victim = this.buildVictimLaptop();
    this.scene.add(this.nodes.victim);

    // 4. Attacker Machine (South-East)
    this.nodes.attacker = this.buildAttackerNode();
    this.scene.add(this.nodes.attacker);

    // 5. Bystander Peer (North-West)
    this.nodes.bystander = this.buildBystanderNode();
    this.scene.add(this.nodes.bystander);

    // Build Physical Cable Lines from Switch to Hosts
    this.buildCableLinks();
  }

  buildRouter() {
    const group = new THREE.Group();
    group.position.copy(this.hostPositions.router);

    // Router Base Box
    const baseGeo = new THREE.BoxGeometry(2.4, 0.5, 1.6);
    const baseMat = new THREE.MeshStandardMaterial({ color: 0x1e293b, metalness: 0.6, roughness: 0.4 });
    const base = new THREE.Mesh(baseGeo, baseMat);
    base.position.y = 0.25;
    base.castShadow = !this.isSoftwareGl;
    group.add(base);

    // Antennas
    const antGeo = new THREE.CylinderGeometry(0.04, 0.04, 1.2, 8);
    const antMat = new THREE.MeshStandardMaterial({ color: 0x334155, metalness: 0.8, roughness: 0.2 });
    const ant1 = new THREE.Mesh(antGeo, antMat);
    ant1.position.set(-0.9, 0.9, -0.6);
    ant1.rotation.z = 0.15;
    group.add(ant1);

    const ant2 = new THREE.Mesh(antGeo, antMat);
    ant2.position.set(0.9, 0.9, -0.6);
    ant2.rotation.z = -0.15;
    group.add(ant2);

    // Stylized Internet Cloud behind Router (Group of glowing translucent spheres)
    const cloudGroup = new THREE.Group();
    cloudGroup.position.set(0, 2.2, -4.5);
    const cloudMat = new THREE.MeshStandardMaterial({
      color: 0x38bdf8,
      roughness: 0.3,
      metalness: 0.1,
      transparent: true,
      opacity: 0.75
    });

    const c1 = new THREE.Mesh(new THREE.SphereGeometry(1.2, 16, 16), cloudMat);
    const c2 = new THREE.Mesh(new THREE.SphereGeometry(0.85, 16, 16), cloudMat);
    c2.position.set(-1.1, -0.2, 0);
    const c3 = new THREE.Mesh(new THREE.SphereGeometry(0.95, 16, 16), cloudMat);
    c3.position.set(1.1, -0.1, 0);
    const c4 = new THREE.Mesh(new THREE.SphereGeometry(0.7, 16, 16), cloudMat);
    c4.position.set(0, 0.6, 0.2);

    cloudGroup.add(c1, c2, c3, c4);
    group.add(cloudGroup);
    group.add(this.createContactShadow(2.0));

    return group;
  }

  buildVictimLaptop() {
    const group = new THREE.Group();
    group.position.copy(this.hostPositions.victim);

    // Laptop Base
    const baseGeo = new THREE.BoxGeometry(2.2, 0.12, 1.5);
    const metalMat = new THREE.MeshStandardMaterial({ color: 0x64748b, metalness: 0.8, roughness: 0.25 });
    const base = new THREE.Mesh(baseGeo, metalMat);
    base.position.y = 0.06;
    base.castShadow = !this.isSoftwareGl;
    group.add(base);

    // Screen (tilted up 70 degrees)
    const screenGroup = new THREE.Group();
    screenGroup.position.set(0, 0.12, -0.7);

    const lidGeo = new THREE.BoxGeometry(2.2, 1.4, 0.08);
    const lid = new THREE.Mesh(lidGeo, metalMat);
    lid.position.set(0, 0.7, 0);
    screenGroup.add(lid);

    // Display Glow
    const displayGeo = new THREE.PlaneGeometry(1.95, 1.2);
    const displayMat = new THREE.MeshBasicMaterial({ color: 0x0284c7 });
    const display = new THREE.Mesh(displayGeo, displayMat);
    display.position.set(0, 0.7, 0.045);
    screenGroup.add(display);

    screenGroup.rotation.x = -Math.PI * 0.12;
    group.add(screenGroup);

    // NIC Halo / Sniffer Ring around laptop base (glows when ARP passes)
    const ringGeo = new THREE.TorusGeometry(1.6, 0.04, 16, 32);
    this.snifferRingMat = new THREE.MeshBasicMaterial({
      color: 0x06b6d4,
      transparent: true,
      opacity: 0.25
    });
    this.snifferRing = new THREE.Mesh(ringGeo, this.snifferRingMat);
    this.snifferRing.rotation.x = Math.PI / 2;
    this.snifferRing.position.y = 0.05;
    group.add(this.snifferRing);

    // Defense Shield (for kernel permanent refusal visual bounce)
    const shieldGeo = new THREE.SphereGeometry(1.8, 16, 16, 0, Math.PI * 2, 0, Math.PI / 2);
    this.shieldMat = new THREE.MeshStandardMaterial({
      color: 0x10b981,
      transparent: true,
      opacity: 0.0,
      roughness: 0.2,
      metalness: 0.8
    });
    this.shieldMesh = new THREE.Mesh(shieldGeo, this.shieldMat);
    this.shieldMesh.position.y = 0.1;
    group.add(this.shieldMesh);

    group.add(this.createContactShadow(1.8));
    return group;
  }

  buildAttackerNode() {
    const group = new THREE.Group();
    group.position.copy(this.hostPositions.attacker);

    // Attacker Machine (Dark chassis with crimson accent LED)
    const baseGeo = new THREE.BoxGeometry(2.2, 0.12, 1.5);
    const darkMat = new THREE.MeshStandardMaterial({ color: 0x18181b, metalness: 0.85, roughness: 0.3 });
    const base = new THREE.Mesh(baseGeo, darkMat);
    base.position.y = 0.06;
    base.castShadow = !this.isSoftwareGl;
    group.add(base);

    // Screen with red hacker terminal
    const screenGroup = new THREE.Group();
    screenGroup.position.set(0, 0.12, -0.7);

    const lidGeo = new THREE.BoxGeometry(2.2, 1.4, 0.08);
    const lid = new THREE.Mesh(lidGeo, darkMat);
    lid.position.set(0, 0.7, 0);
    screenGroup.add(lid);

    const displayGeo = new THREE.PlaneGeometry(1.95, 1.2);
    const displayMat = new THREE.MeshBasicMaterial({ color: 0xdc2626 });
    const display = new THREE.Mesh(displayGeo, displayMat);
    display.position.set(0, 0.7, 0.045);
    screenGroup.add(display);

    screenGroup.rotation.x = -Math.PI * 0.12;
    group.add(screenGroup);

    // Red aura ring
    const ringGeo = new THREE.TorusGeometry(1.6, 0.04, 16, 32);
    const ringMat = new THREE.MeshBasicMaterial({ color: 0xef4444, transparent: true, opacity: 0.35 });
    const ring = new THREE.Mesh(ringGeo, ringMat);
    ring.rotation.x = Math.PI / 2;
    ring.position.y = 0.05;
    group.add(ring);

    group.add(this.createContactShadow(1.8));
    return group;
  }

  buildBystanderNode() {
    const group = new THREE.Group();
    group.position.copy(this.hostPositions.bystander);

    // Desktop Tower
    const towerGeo = new THREE.BoxGeometry(0.8, 1.8, 1.6);
    const towerMat = new THREE.MeshStandardMaterial({ color: 0x475569, metalness: 0.5, roughness: 0.4 });
    const tower = new THREE.Mesh(towerGeo, towerMat);
    tower.position.set(-1.0, 0.9, 0);
    tower.castShadow = !this.isSoftwareGl;
    group.add(tower);

    // Monitor
    const monGeo = new THREE.BoxGeometry(1.8, 1.2, 0.1);
    const monMat = new THREE.MeshStandardMaterial({ color: 0x334155, metalness: 0.4, roughness: 0.4 });
    const mon = new THREE.Mesh(monGeo, monMat);
    mon.position.set(0.4, 1.0, 0);
    group.add(mon);

    const screenGeo = new THREE.PlaneGeometry(1.65, 1.05);
    const screenMat = new THREE.MeshBasicMaterial({ color: 0x3b82f6 });
    const screen = new THREE.Mesh(screenGeo, screenMat);
    screen.position.set(0.4, 1.0, 0.06);
    group.add(screen);

    // Stand
    const standGeo = new THREE.CylinderGeometry(0.08, 0.08, 0.6, 8);
    const stand = new THREE.Mesh(standGeo, monMat);
    stand.position.set(0.4, 0.3, 0);
    group.add(stand);

    group.add(this.createContactShadow(2.0));
    return group;
  }

  buildCableLinks() {
    const swPos = this.hostPositions.switch;
    const targets = ['router', 'victim', 'attacker', 'bystander'];
    const cableMat = new THREE.MeshBasicMaterial({ color: 0x334155 });

    targets.forEach(targetKey => {
      const targetPos = this.hostPositions[targetKey];
      // Create tube along line
      const curve = new THREE.LineCurve3(
        new THREE.Vector3(swPos.x, 0.15, swPos.z),
        new THREE.Vector3(targetPos.x, 0.15, targetPos.z)
      );
      const tubeGeo = new THREE.TubeGeometry(curve, 20, 0.04, 8, false);
      const tube = new THREE.Mesh(tubeGeo, cableMat);
      this.scene.add(tube);
      this.linkLines[targetKey] = tube;
    });
  }

  /**
   * Spawn animated packet envelope / sphere along path
   */
  spawnPacketAnimation(packetData) {
    const { type, from, to, viaSwitch, isBroadcast, tag, summary, fields, hijacked } = packetData;

    let color = 0x10b981; // legitimate ARP (green)
    if (type === 'forged_arp') color = 0xef4444; // forged ARP (red)
    else if (type === 'probe') color = 0xf59e0b; // probe TOFU (amber)
    else if (type === 'corrective_arp') color = 0x14b8a6; // corrective ARP (teal)
    else if (type === 'data') color = 0x38bdf8; // data packet (blue)

    const fromPos = this.hostPositions[from] || this.hostPositions.switch;
    const toPos = this.hostPositions[to] || this.hostPositions.switch;

    const group = new THREE.Group();
    group.position.copy(fromPos).add(new THREE.Vector3(0, 0.6, 0));

    if (type === 'data') {
      // Small glowing sphere
      const sphereGeo = new THREE.SphereGeometry(0.32, 16, 16);
      const sphereMat = new THREE.MeshBasicMaterial({ color });
      const mesh = new THREE.Mesh(sphereGeo, sphereMat);
      group.add(mesh);
    } else {
      // Envelope shape (flat box with slight edge)
      const envGeo = new THREE.BoxGeometry(0.8, 0.1, 0.55);
      const envMat = new THREE.MeshStandardMaterial({
        color,
        roughness: 0.3,
        metalness: 0.2
      });
      const env = new THREE.Mesh(envGeo, envMat);
      group.add(env);

      // Flap crease
      const flapGeo = new THREE.BoxGeometry(0.72, 0.03, 0.25);
      const flapMat = new THREE.MeshBasicMaterial({ color: 0xffffff });
      const flap = new THREE.Mesh(flapGeo, flapMat);
      flap.position.set(0, 0.06, -0.1);
      group.add(flap);
    }

    this.scene.add(group);
    this.packetObjects.push(group);

    // Build Waypoints
    const waypoints = [fromPos.clone().add(new THREE.Vector3(0, 0.5, 0))];

    if (isBroadcast) {
      // Moves to switch then branches
      waypoints.push(this.hostPositions.switch.clone().add(new THREE.Vector3(0, 0.5, 0)));
    } else if (viaSwitch && from !== 'switch' && to !== 'switch') {
      waypoints.push(this.hostPositions.switch.clone().add(new THREE.Vector3(0, 0.5, 0)));
      waypoints.push(toPos.clone().add(new THREE.Vector3(0, 0.5, 0)));
    } else {
      waypoints.push(toPos.clone().add(new THREE.Vector3(0, 0.5, 0)));
    }

    const anim = {
      group,
      waypoints,
      progress: 0,
      speed: 0.022,
      tag,
      fields,
      type,
      hijacked
    };

    this.activeAnimations.push(anim);

    // Port LEDs blink while traffic transits the switch
    if (waypoints.length === 3) {
      this.switchLedPulse = 1.2;
    }

    // If packet passes through victim, glow the sniffer ring
    if (to === 'victim' || from === 'victim') {
      this.pulseSnifferRing();
    }
  }

  pulseSnifferRing() {
    if (this.snifferRingMat) {
      this.snifferRingMat.opacity = 0.9;
    }
  }

  triggerShieldBounce() {
    if (this.shieldMat) {
      this.shieldMat.opacity = 0.65;
      setTimeout(() => {
        if (this.shieldMat) this.shieldMat.opacity = 0.0;
      }, 700);
    }
  }

  clearPackets() {
    for (const p of this.packetObjects) {
      this.scene.remove(p);
      this.disposeObject(p);
    }
    this.packetObjects = [];
    this.activeAnimations = [];
  }

  /** Recursively free GPU resources of a mesh tree (geometry + materials). */
  disposeObject(root) {
    root.traverse(child => {
      if (child.geometry) child.geometry.dispose();
      const mats = Array.isArray(child.material) ? child.material : (child.material ? [child.material] : []);
      for (const m of mats) {
        if (m.map) m.map.dispose();
        m.dispose();
      }
    });
  }

  setCameraPreset(name) {
    const preset = this.cameraPresets[name] || this.cameraPresets.overview;
    this.targetCameraPos.copy(preset.pos);
    this.targetControlsTarget.copy(preset.target);
    this.presetTransitionActive = true;
    this.callbacks.onCameraMove?.();
  }

  onWindowResize() {
    this.width = this.container.clientWidth || window.innerWidth;
    this.height = this.container.clientHeight || window.innerHeight;
    this.camera.aspect = this.width / this.height;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(this.width, this.height);
  }

  animate() {
    const delta = this.clock.getDelta();

    // Smooth camera damping to preset
    if (this.presetTransitionActive) {
      const k = 1 - Math.exp(-4.5 * Math.min(delta, 0.1));
      this.camera.position.lerp(this.targetCameraPos, k);
      this.controls.target.lerp(this.targetControlsTarget, k);
      if (
        this.camera.position.distanceToSquared(this.targetCameraPos) < 0.01 &&
        this.controls.target.distanceToSquared(this.targetControlsTarget) < 0.01
      ) {
        this.presetTransitionActive = false;
      }
    }
    this.controls.update();

    // Sniffer ring decay
    if (this.snifferRingMat && this.snifferRingMat.opacity > 0.25) {
      this.snifferRingMat.opacity = Math.max(0.25, this.snifferRingMat.opacity - delta * 0.8);
    }

    // Shield decay
    if (this.shieldMat && this.shieldMat.opacity > 0) {
      this.shieldMat.opacity = Math.max(0, this.shieldMat.opacity - delta * 1.2);
    }

    // Animate in-flight packets
    for (let i = this.activeAnimations.length - 1; i >= 0; i--) {
      const anim = this.activeAnimations[i];
      anim.progress += anim.speed;

      if (anim.waypoints.length === 2) {
        anim.group.position.lerpVectors(anim.waypoints[0], anim.waypoints[1], Math.min(1, anim.progress));
      } else if (anim.waypoints.length === 3) {
        if (anim.progress <= 0.5) {
          const t = anim.progress * 2;
          anim.group.position.lerpVectors(anim.waypoints[0], anim.waypoints[1], t);
        } else {
          const t = (anim.progress - 0.5) * 2;
          anim.group.position.lerpVectors(anim.waypoints[1], anim.waypoints[2], Math.min(1, t));
        }
      }

      if (anim.progress >= 1.0) {
        // Animation finished
        this.scene.remove(anim.group);
        this.disposeObject(anim.group);
        const pi = this.packetObjects.indexOf(anim.group);
        if (pi !== -1) this.packetObjects.splice(pi, 1);
        this.activeAnimations.splice(i, 1);
      }
    }

    // Switch port LED activity blink (decays when traffic stops)
    if (this.switchLedPulse > 0) {
      this.switchLedPulse = Math.max(0, this.switchLedPulse - delta);
      const on = (this.clock.elapsedTime % 0.22) < 0.13;
      for (const led of this.switchPortLeds) {
        led.material.color.setHex(on ? 0x34d399 : 0x065f46);
      }
    } else {
      for (const led of this.switchPortLeds) {
        led.material.color.setHex(0x10b981);
      }
    }

    this.renderer.render(this.scene, this.camera);
    this.rafId = requestAnimationFrame(this.animate);
  }

  dispose() {
    cancelAnimationFrame(this.rafId);
    window.removeEventListener('resize', this.onWindowResize);
    this.clearPackets();
    if (this.controls) this.controls.dispose();
    this.disposeObject(this.scene);
    this.renderer.dispose();
  }
}
