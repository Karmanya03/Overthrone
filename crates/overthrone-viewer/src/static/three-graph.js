(() => {
  const THREE = window.THREE;
  if (!THREE) {
    window.bootViewer = function bootViewerFallback() {
      if (typeof window.init === 'function') {
        window.init();
        return;
      }
      setEmptyMessage('Three.js unavailable', 'The graph renderer could not load the WebGL library.');
    };
    return;
  }

  const MAX_LABELS = 600;
  const MAX_EDGE_LABELS = 420;
  const MAX_HIGHLIGHT_EDGES = 3500;
  const MAX_HIGHLIGHT_NODES = 2500;
  const NODE_Z = 0;
  const LABEL_Z = 2;
  const OVERLAY_Z = 4;
  const LABEL_BG = 'rgba(13, 13, 15, 0.82)';
  const LABEL_BORDER = 'rgba(69, 69, 78, 0.94)';
  const LABEL_TEXT = '#f0f0f2';
  const EDGE_LABEL_BG = 'rgba(11, 11, 16, 0.88)';
  const EDGE_LABEL_TEXT = '#b5b5bc';

  let graphRenderer = null;
  let controlsInstalled = false;

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function clearObject(object3d) {
    if (!object3d) return;
    while (object3d.children.length) {
      const child = object3d.children.pop();
      clearObject(child);
    }
    if (object3d.geometry) object3d.geometry.dispose();
    if (object3d.material) {
      if (Array.isArray(object3d.material)) {
        object3d.material.forEach(material => material.dispose());
      } else {
        object3d.material.dispose();
      }
    }
    if (object3d.texture) object3d.texture.dispose();
  }

  function colorForNode(node) {
    return NODE_COLORS[node.type] || NODE_COLORS.Unknown;
  }

  function colorForEdge(relationship) {
    return EDGE_COLORS[relationship] || '#4d4d55';
  }

  function makeSpriteTexture(text, options = {}) {
    const {
      fontSize = 12,
      fontFamily = 'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif',
      color = LABEL_TEXT,
      background = LABEL_BG,
      border = LABEL_BORDER,
      paddingX = 8,
      paddingY = 4,
      stroke = '#030303',
      strokeWidth = 3,
      weight = '700',
      maxWidth = 520,
    } = options;
    const cacheKey = [text, fontSize, fontFamily, color, background, border, paddingX, paddingY, stroke, strokeWidth, weight, maxWidth].join('|');
    if (!makeSpriteTexture.cache) {
      makeSpriteTexture.cache = new Map();
    }
    const cache = makeSpriteTexture.cache;
    if (cache.has(cacheKey)) {
      return cache.get(cacheKey);
    }

    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.font = `${weight} ${fontSize}px ${fontFamily}`;
    const measuredWidth = Math.ceil(ctx.measureText(text).width);
    const rawWidth = Math.min(maxWidth, measuredWidth + paddingX * 2);
    const width = Math.max(32, rawWidth);
    const height = Math.max(18, Math.ceil(fontSize + paddingY * 2 + 4));
    canvas.width = width;
    canvas.height = height;

    ctx.font = `${weight} ${fontSize}px ${fontFamily}`;
    ctx.textBaseline = 'middle';
    ctx.textAlign = 'left';
    ctx.clearRect(0, 0, width, height);

    if (background) {
      ctx.fillStyle = background;
      ctx.fillRect(0, 0, width, height);
    }
    if (border) {
      ctx.strokeStyle = border;
      ctx.lineWidth = 1;
      ctx.strokeRect(0.5, 0.5, width - 1, height - 1);
    }
    if (strokeWidth > 0) {
      ctx.lineWidth = strokeWidth;
      ctx.strokeStyle = stroke;
      ctx.strokeText(text, paddingX, height / 2);
    }
    ctx.fillStyle = color;
    ctx.fillText(text, paddingX, height / 2);

    const texture = new THREE.CanvasTexture(canvas);
    texture.minFilter = THREE.LinearFilter;
    texture.magFilter = THREE.LinearFilter;
    texture.generateMipmaps = false;
    texture.needsUpdate = true;

    const entry = {
      texture,
      width,
      height,
      dispose() {
        texture.dispose();
      },
    };
    cache.set(cacheKey, entry);
    return entry;
  }

  function makeSprite(text, options = {}) {
    const textureEntry = makeSpriteTexture(text, options);
    const material = new THREE.SpriteMaterial({
      map: textureEntry.texture,
      transparent: true,
      depthTest: false,
      depthWrite: false,
      fog: false,
    });
    const sprite = new THREE.Sprite(material);
    sprite.userData.textureEntry = textureEntry;
    sprite.userData.text = text;
    sprite.scale.set(textureEntry.width, textureEntry.height, 1);
    return sprite;
  }

  function disposeSprite(sprite) {
    if (!sprite) return;
    if (sprite.material) {
      sprite.material.dispose();
    }
    if (sprite.userData && sprite.userData.textureEntry) {
      sprite.userData.textureEntry.dispose();
    }
  }

  function updateTransform(camera) {
    currentTransform.k = camera.zoom;
    currentTransform.x = camera.position.x;
    currentTransform.y = camera.position.y;
  }

  class ThreeGraphRenderer {
    constructor(canvas) {
      this.canvas = canvas;
      this.container = canvas.parentElement;
      this.selectionBox = document.getElementById('selection-box');
      this.renderer = new THREE.WebGLRenderer({
        canvas,
        antialias: false,
        alpha: true,
        powerPreference: 'high-performance',
        precision: 'highp',
        preserveDrawingBuffer: false,
        depth: true,
        stencil: false,
      });
      this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.75));
      this.renderer.setClearColor(0x0b0b10, 1);

      this.scene = new THREE.Scene();
      this.camera = new THREE.OrthographicCamera(0, 1, 1, 0, -5000, 5000);
      this.camera.position.set(0, 0, 10);
      this.camera.zoom = 1;
      this.scene.add(this.camera);

      this.root = new THREE.Group();
      this.scene.add(this.root);
      this.baseEdgeGroup = new THREE.Group();
      this.baseNodeGroup = new THREE.Group();
      this.overlayEdgeGroup = new THREE.Group();
      this.overlayNodeGroup = new THREE.Group();
      this.labelGroup = new THREE.Group();
      this.root.add(this.baseEdgeGroup);
      this.root.add(this.baseNodeGroup);
      this.root.add(this.overlayEdgeGroup);
      this.root.add(this.overlayNodeGroup);
      this.root.add(this.labelGroup);

      this.baseNodeGeometry = new THREE.CircleGeometry(1, 24);
      this.highlightNodeGeometry = new THREE.RingGeometry(1.04, 1.5, 24);
      this.selectionGeometry = new THREE.RingGeometry(1.06, 1.72, 28);
      this.baseNodeMaterial = new THREE.MeshBasicMaterial({
        transparent: true,
        opacity: 0.95,
        vertexColors: true,
        depthWrite: false,
      });
      this.highlightNodeMaterial = new THREE.MeshBasicMaterial({
        transparent: true,
        opacity: 0.95,
        vertexColors: true,
        depthWrite: false,
        side: THREE.DoubleSide,
        blending: THREE.AdditiveBlending,
      });
      this.selectionMaterial = new THREE.MeshBasicMaterial({
        color: 0xffffff,
        transparent: true,
        opacity: 0.95,
        depthWrite: false,
        side: THREE.DoubleSide,
      });
      this.hoverMaterial = new THREE.MeshBasicMaterial({
        color: 0x49e4d6,
        transparent: true,
        opacity: 0.9,
        depthWrite: false,
        side: THREE.DoubleSide,
      });
      this.baseLineMaterial = new THREE.LineBasicMaterial({
        vertexColors: true,
        transparent: true,
        opacity: 0.52,
        depthWrite: false,
      });
      this.baseDashMaterial = new THREE.LineDashedMaterial({
        vertexColors: true,
        transparent: true,
        opacity: 0.45,
        depthWrite: false,
        dashSize: 8,
        gapSize: 5,
      });
      this.highlightLineMaterial = new THREE.LineBasicMaterial({
        vertexColors: true,
        transparent: true,
        opacity: 0.95,
        depthWrite: false,
      });

      this.baseNodeMesh = null;
      this.highlightNodeMesh = null;
      this.selectionRing = new THREE.Mesh(this.selectionGeometry, this.selectionMaterial);
      this.hoverRing = new THREE.Mesh(this.selectionGeometry, this.hoverMaterial);
      this.selectionRing.visible = false;
      this.hoverRing.visible = false;
      this.overlayNodeGroup.add(this.selectionRing);
      this.overlayNodeGroup.add(this.hoverRing);

      this.baseEdgeMeshes = [];
      this.highlightEdgeMeshes = [];
      this.labelSprites = [];
      this.edgeLabelSprites = [];

      this.nodeArray = [];
      this.edgeArray = [];
      this.nodeById = new Map();
      this.edgeByKey = new Map();
      this.connectedNodeSet = new Set();
      this.connectedEdgeSet = new Set();
      this.pathNodeSet = new Set();
      this.pathEdgeSet = new Set();
      this.selectedNodeIds = new Set();
      this.selectedNodeId = null;
      this.hoveredNodeId = null;
      this.pendingRender = false;
      this.dragState = null;
      this.marqueeState = null;
      this.lastPointer = { x: 0, y: 0 };
      this.lastHoverNodeId = null;

      this.raycaster = new THREE.Raycaster();
      this.pointer = new THREE.Vector2();

      this.boundPointerDown = this.onPointerDown.bind(this);
      this.boundPointerMove = this.onPointerMove.bind(this);
      this.boundPointerUp = this.onPointerUp.bind(this);
      this.boundPointerLeave = this.onPointerLeave.bind(this);
      this.boundWheel = this.onWheel.bind(this);
      this.boundResize = this.resize.bind(this);
      this.boundContextMenu = event => event.preventDefault();

      this.canvas.style.touchAction = 'none';
      this.canvas.style.cursor = 'grab';
      this.canvas.addEventListener('pointerdown', this.boundPointerDown);
      this.canvas.addEventListener('pointermove', this.boundPointerMove);
      this.canvas.addEventListener('pointerup', this.boundPointerUp);
      this.canvas.addEventListener('pointerleave', this.boundPointerLeave);
      this.canvas.addEventListener('wheel', this.boundWheel, { passive: false });
      this.canvas.addEventListener('contextmenu', this.boundContextMenu);
      window.addEventListener('resize', this.boundResize);

      this.resize();
    }

    dispose() {
      this.canvas.removeEventListener('pointerdown', this.boundPointerDown);
      this.canvas.removeEventListener('pointermove', this.boundPointerMove);
      this.canvas.removeEventListener('pointerup', this.boundPointerUp);
      this.canvas.removeEventListener('pointerleave', this.boundPointerLeave);
      this.canvas.removeEventListener('wheel', this.boundWheel);
      this.canvas.removeEventListener('contextmenu', this.boundContextMenu);
      window.removeEventListener('resize', this.boundResize);
      this.clearGraph();
      this.renderer.dispose();
    }

    resize() {
      const rect = this.container.getBoundingClientRect();
      const width = Math.max(1, rect.width);
      const height = Math.max(1, rect.height);
      this.width = width;
      this.height = height;
      this.renderer.setSize(width, height, false);
      this.camera.left = 0;
      this.camera.right = width;
      this.camera.top = 0;
      this.camera.bottom = height;
      this.camera.updateProjectionMatrix();
      this.render();
    }

    clearGraph() {
      this.nodeArray = [];
      this.edgeArray = [];
      this.nodeById.clear();
      this.edgeByKey.clear();
      this.connectedNodeSet.clear();
      this.connectedEdgeSet.clear();
      this.pathNodeSet.clear();
      this.pathEdgeSet.clear();
      this.selectedNodeIds.clear();
      this.selectedNodeId = null;
      this.hoveredNodeId = null;
      this.lastHoverNodeId = null;
      this.hideSelectionBox();
      this.selectionRing.visible = false;
      this.hoverRing.visible = false;
      this.disposeScene();
      this.render();
    }

    disposeScene() {
      clearObject(this.baseEdgeGroup);
      clearObject(this.baseNodeGroup);
      clearObject(this.overlayEdgeGroup);
      clearObject(this.overlayNodeGroup);
      clearObject(this.labelGroup);
      this.baseEdgeMeshes = [];
      this.highlightEdgeMeshes = [];
      this.labelSprites = [];
      this.edgeLabelSprites = [];
      this.baseNodeMesh = null;
      this.highlightNodeMesh = null;
      this.selectionGeometry = new THREE.RingGeometry(1.06, 1.72, 28);
      this.selectionMaterial = new THREE.MeshBasicMaterial({
        color: 0xffffff,
        transparent: true,
        opacity: 0.95,
        depthWrite: false,
        side: THREE.DoubleSide,
      });
      this.hoverMaterial = new THREE.MeshBasicMaterial({
        color: 0x49e4d6,
        transparent: true,
        opacity: 0.9,
        depthWrite: false,
        side: THREE.DoubleSide,
      });
      this.selectionRing = new THREE.Mesh(this.selectionGeometry, this.selectionMaterial);
      this.hoverRing = new THREE.Mesh(this.selectionGeometry, this.hoverMaterial);
      this.selectionRing.visible = false;
      this.hoverRing.visible = false;
      this.overlayNodeGroup.add(this.selectionRing);
      this.overlayNodeGroup.add(this.hoverRing);
      if (makeSpriteTexture.cache) {
        makeSpriteTexture.cache.forEach(entry => entry.dispose());
        makeSpriteTexture.cache.clear();
      }
    }

    setGraphData({ nodes, edges, width, height, graphData }) {
      this.clearGraph();
      this.nodeArray = nodes;
      this.edgeArray = edges;
      this.graphData = graphData;
      this.width = width;
      this.height = height;
      this.nodeById.clear();
      this.edgeByKey.clear();
      nodes.forEach((node, index) => {
        node._index = index;
        this.nodeById.set(node.id, node);
      });
      edges.forEach(edge => {
        this.edgeByKey.set(edge.key, edge);
      });
      this.buildNodeMesh();
      this.buildEdgeMeshes();
      this.fitToGraph();
    }

    buildNodeMesh() {
      if (!this.nodeArray.length) return;
      const mesh = new THREE.InstancedMesh(this.baseNodeGeometry, this.baseNodeMaterial, this.nodeArray.length);
      mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
      const dummy = new THREE.Object3D();
      const color = new THREE.Color();
      this.nodeArray.forEach((node, index) => {
        dummy.position.set(node.x, node.y, NODE_Z);
        dummy.scale.setScalar(Math.max(3, node.radius));
        dummy.updateMatrix();
        mesh.setMatrixAt(index, dummy.matrix);
        color.set(colorForNode(node));
        mesh.setColorAt(index, color);
      });
      mesh.instanceMatrix.needsUpdate = true;
      if (mesh.instanceColor) mesh.instanceColor.needsUpdate = true;
      this.baseNodeMesh = mesh;
      this.baseNodeGroup.add(mesh);

      const specialNodes = this.nodeArray.filter(node => node.high_value || node.owned);
      if (specialNodes.length) {
        const specialMesh = new THREE.InstancedMesh(this.highlightNodeGeometry, this.highlightNodeMaterial, specialNodes.length);
        specialMesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
        const specialDummy = new THREE.Object3D();
        const specialColor = new THREE.Color();
        specialNodes.forEach((node, index) => {
          specialDummy.position.set(node.x, node.y, OVERLAY_Z);
          specialDummy.scale.setScalar(Math.max(3, node.radius * 1.26));
          specialDummy.updateMatrix();
          specialMesh.setMatrixAt(index, specialDummy.matrix);
          specialColor.set(node.owned ? '#5bea8c' : '#f4c95d');
          specialMesh.setColorAt(index, specialColor);
        });
        specialMesh.instanceMatrix.needsUpdate = true;
        if (specialMesh.instanceColor) specialMesh.instanceColor.needsUpdate = true;
        this.baseNodeGroup.add(specialMesh);
      }
    }

    buildEdgeMeshes() {
      const solidEdges = [];
      const dashedEdges = [];
      this.edgeArray.forEach(edge => {
        const target = edge.target;
        const source = edge.source;
        if (!source || !target) return;
        if (edge.relationship === 'MemberOf' || edge.relationship === 'Contains') {
          dashedEdges.push(edge);
        } else {
          solidEdges.push(edge);
        }
      });
      this.baseEdgeMeshes = [
        this.buildLineMesh(solidEdges, false, this.baseLineMaterial),
        this.buildLineMesh(dashedEdges, true, this.baseDashMaterial),
      ].filter(Boolean);
      this.baseEdgeMeshes.forEach(mesh => this.baseEdgeGroup.add(mesh));
    }

    buildLineMesh(edges, dashed, material) {
      if (!edges.length) return null;
      const positions = new Float32Array(edges.length * 2 * 3);
      const colors = new Float32Array(edges.length * 2 * 3);
      const color = new THREE.Color();
      edges.forEach((edge, index) => {
        const offset = index * 6;
        positions[offset] = edge.source.x;
        positions[offset + 1] = edge.source.y;
        positions[offset + 2] = 0;
        positions[offset + 3] = edge.target.x;
        positions[offset + 4] = edge.target.y;
        positions[offset + 5] = 0;
        const baseColor = colorForEdge(edge.relationship);
        color.set(baseColor);
        const intensity = importantEdge(edge.relationship) ? 1 : 0.78;
        color.multiplyScalar(intensity);
        colors[offset] = color.r;
        colors[offset + 1] = color.g;
        colors[offset + 2] = color.b;
        colors[offset + 3] = color.r;
        colors[offset + 4] = color.g;
        colors[offset + 5] = color.b;
      });
      const geometry = new THREE.BufferGeometry();
      geometry.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
      geometry.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));
      geometry.computeBoundingSphere();
      const mesh = new THREE.LineSegments(geometry, material.clone());
      if (dashed) {
        mesh.computeLineDistances();
      }
      return mesh;
    }

    fitToGraph() {
      if (!this.nodeArray.length) return;
      const xs = this.nodeArray.map(node => node.x || 0);
      const ys = this.nodeArray.map(node => node.y || 0);
      const minX = Math.min(...xs);
      const maxX = Math.max(...xs);
      const minY = Math.min(...ys);
      const maxY = Math.max(...ys);
      const graphWidth = Math.max(1, maxX - minX);
      const graphHeight = Math.max(1, maxY - minY);
      const fillRatio = this.nodeArray.length > 5000 ? 0.9 : this.nodeArray.length > 2000 ? 0.86 : 0.82;
      const scale = clamp(fillRatio / Math.max(graphWidth / this.width, graphHeight / this.height), 0.08, 1.7);
      this.camera.zoom = scale;
      this.camera.position.x = (minX + maxX) / 2 - this.width / (2 * this.camera.zoom);
      this.camera.position.y = (minY + maxY) / 2 - this.height / (2 * this.camera.zoom);
      this.camera.updateProjectionMatrix();
      updateTransform(this.camera);
      this.refreshLabels();
      this.render();
    }

    zoomBy(factor, focusX, focusY) {
      const rect = this.canvas.getBoundingClientRect();
      const clientX = focusX ?? rect.left + rect.width / 2;
      const clientY = focusY ?? rect.top + rect.height / 2;
      const before = this.screenToWorld(clientX, clientY);
      this.camera.zoom = clamp(this.camera.zoom * factor, 0.04, 12);
      this.camera.updateProjectionMatrix();
      const after = this.screenToWorld(clientX, clientY);
      this.camera.position.x += before.x - after.x;
      this.camera.position.y += before.y - after.y;
      this.camera.updateProjectionMatrix();
      updateTransform(this.camera);
      this.refreshLabels();
      this.render();
    }

    zoomToNode(node) {
      if (!node) return;
      this.camera.zoom = clamp(Math.max(this.camera.zoom, this.nodeArray.length > 2000 ? 1.7 : 2.0), 0.08, 12);
      this.camera.position.x = node.x - this.width / (2 * this.camera.zoom);
      this.camera.position.y = node.y - this.height / (2 * this.camera.zoom);
      this.camera.updateProjectionMatrix();
      updateTransform(this.camera);
      this.refreshLabels();
      this.render();
    }

    setHighlightSet(nodeIds, edgeKeys, mode = 'selection') {
      this.connectedNodeSet = new Set(nodeIds || []);
      this.connectedEdgeSet = new Set(edgeKeys || []);
      this.highlightMode = mode;
      this.rebuildHighlightOverlay();
      this.refreshLabels();
      this.render();
    }

    clearHighlightSet() {
      this.connectedNodeSet.clear();
      this.connectedEdgeSet.clear();
      this.pathNodeSet.clear();
      this.pathEdgeSet.clear();
      this.highlightMode = null;
      this.rebuildHighlightOverlay();
      this.refreshLabels();
      this.render();
    }

    rebuildHighlightOverlay() {
      clearObject(this.overlayEdgeGroup);
      this.overlayEdgeGroup.add(new THREE.Group());
      const overlayNodeLayer = new THREE.Group();
      this.overlayNodeGroup.add(this.selectionRing);
      this.overlayNodeGroup.add(this.hoverRing);
      this.overlayNodeGroup.add(overlayNodeLayer);
      this.overlayNodeLayer = overlayNodeLayer;

      const hasNodes = this.connectedNodeSet.size > 0 || this.pathNodeSet.size > 0;
      const hasEdges = this.connectedEdgeSet.size > 0 || this.pathEdgeSet.size > 0;
      this.baseNodeMaterial.opacity = hasNodes ? 0.16 : 0.95;
      this.baseLineMaterial.opacity = hasEdges ? 0.12 : 0.52;
      this.baseDashMaterial.opacity = hasEdges ? 0.11 : 0.45;

      const highlightNodeIds = new Set([...this.connectedNodeSet, ...this.pathNodeSet]);
      this.selectedNodeIds.forEach(id => highlightNodeIds.add(id));
      if (this.selectedNodeId) {
        highlightNodeIds.add(this.selectedNodeId);
      }
      if (this.hoveredNodeId && !this.selectedNodeId && !this.selectedNodeIds.size) {
        highlightNodeIds.add(this.hoveredNodeId);
      }

      const ringNodes = [...highlightNodeIds]
        .map(id => this.nodeById.get(id))
        .filter(Boolean)
        .slice(0, MAX_HIGHLIGHT_NODES);
      if (ringNodes.length) {
        const ringMesh = new THREE.InstancedMesh(this.highlightNodeGeometry, this.highlightNodeMaterial.clone(), ringNodes.length);
        ringMesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
        const dummy = new THREE.Object3D();
        const color = new THREE.Color();
        ringNodes.forEach((node, index) => {
          dummy.position.set(node.x, node.y, OVERLAY_Z);
          dummy.scale.setScalar(Math.max(3, node.radius * 1.38));
          dummy.updateMatrix();
          ringMesh.setMatrixAt(index, dummy.matrix);
          if (this.selectedNodeIds.has(node.id) || node.id === this.selectedNodeId) {
            color.set('#ffffff');
          } else if (this.pathNodeSet.has(node.id)) {
            color.set('#49e4d6');
          } else {
            color.set(colorForNode(node));
          }
          ringMesh.setColorAt(index, color);
        });
        ringMesh.instanceMatrix.needsUpdate = true;
        if (ringMesh.instanceColor) ringMesh.instanceColor.needsUpdate = true;
        this.overlayNodeGroup.add(ringMesh);
      }

      const highlightEdges = [...this.connectedEdgeSet, ...this.pathEdgeSet]
        .map(key => this.edgeByKey.get(key))
        .filter(Boolean)
        .slice(0, MAX_HIGHLIGHT_EDGES);
      if (highlightEdges.length) {
        const positions = new Float32Array(highlightEdges.length * 2 * 3);
        const colors = new Float32Array(highlightEdges.length * 2 * 3);
        const color = new THREE.Color();
        highlightEdges.forEach((edge, index) => {
          const offset = index * 6;
          positions[offset] = edge.source.x;
          positions[offset + 1] = edge.source.y;
          positions[offset + 2] = 0;
          positions[offset + 3] = edge.target.x;
          positions[offset + 4] = edge.target.y;
          positions[offset + 5] = 0;
          color.set(this.pathEdgeSet.has(edge.key) ? '#49e4d6' : '#ffffff');
          colors[offset] = color.r;
          colors[offset + 1] = color.g;
          colors[offset + 2] = color.b;
          colors[offset + 3] = color.r;
          colors[offset + 4] = color.g;
          colors[offset + 5] = color.b;
        });
        const geometry = new THREE.BufferGeometry();
        geometry.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
        geometry.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));
        const mesh = new THREE.LineSegments(geometry, this.highlightLineMaterial.clone());
        this.overlayEdgeGroup.add(mesh);
        this.highlightEdgeMeshes = [mesh];
      } else {
        this.highlightEdgeMeshes = [];
      }

      if (this.selectedNodeId) {
        const node = this.nodeById.get(this.selectedNodeId);
        if (node) {
          this.selectionRing.visible = true;
          this.selectionRing.position.set(node.x, node.y, OVERLAY_Z);
          this.selectionRing.scale.setScalar(Math.max(3, node.radius * 1.45));
        }
      } else {
        this.selectionRing.visible = false;
      }

      if (this.hoveredNodeId && !this.selectedNodeId && !this.selectedNodeIds.size) {
        const node = this.nodeById.get(this.hoveredNodeId);
        if (node) {
          this.hoverRing.visible = true;
          this.hoverRing.position.set(node.x, node.y, OVERLAY_Z);
          this.hoverRing.scale.setScalar(Math.max(3, node.radius * 1.32));
        }
      } else {
        this.hoverRing.visible = false;
      }
    }

    selectNode(node) {
      if (!node) return;
      this.selectNodes([node], 'replace');
    }

    selectNodes(nodes, mode = 'replace') {
      const picked = (nodes || []).filter(Boolean);
      if (mode === 'replace') {
        this.selectedNodeIds.clear();
      }
      picked.forEach(node => {
        if (mode === 'toggle' && this.selectedNodeIds.has(node.id)) {
          this.selectedNodeIds.delete(node.id);
        } else {
          this.selectedNodeIds.add(node.id);
        }
      });

      const ids = [...this.selectedNodeIds];
      this.selectedNodeId = ids.length ? ids[ids.length - 1] : null;
      const connectedNodes = new Set(ids);
      const connectedEdges = new Set();
      this.edgeArray.forEach(edge => {
        if (this.selectedNodeIds.has(edge.source.id) || this.selectedNodeIds.has(edge.target.id)) {
          connectedNodes.add(edge.source.id);
          connectedNodes.add(edge.target.id);
          connectedEdges.add(edge.key);
        }
      });
      this.connectedNodeSet = connectedNodes;
      this.connectedEdgeSet = connectedEdges;
      this.hoveredNodeId = null;
      this.rebuildHighlightOverlay();
      this.refreshLabels();
      this.render();
    }

    clearSelection() {
      this.selectedNodeId = null;
      this.selectedNodeIds.clear();
      this.connectedNodeSet.clear();
      this.connectedEdgeSet.clear();
      this.hoveredNodeId = null;
      this.rebuildHighlightOverlay();
      this.refreshLabels();
      this.render();
    }

    highlightPath(hops) {
      const pathNodeIds = new Set();
      const pathEdgeKeys = new Set();
      hops.forEach(hop => {
        pathNodeIds.add(hop.source_id);
        pathNodeIds.add(hop.target_id);
        pathEdgeKeys.add(edgeKey(hop.source_id, hop.target_id, hop.relationship));
      });
      this.pathNodeSet = pathNodeIds;
      this.pathEdgeSet = pathEdgeKeys;
      this.connectedNodeSet = new Set(pathNodeIds);
      this.connectedEdgeSet = new Set(pathEdgeKeys);
      this.selectedNodeId = null;
      this.selectedNodeIds.clear();
      this.hoveredNodeId = null;
      this.rebuildHighlightOverlay();
      this.refreshLabels();
      this.render();
    }

    refreshLabels() {
      clearObject(this.labelGroup);
      this.labelSprites = [];
      this.edgeLabelSprites = [];
      if (!this.nodeArray.length) return;

      const zoom = this.camera.zoom;
      let labelNodes = this.nodeArray.filter(node =>
        shouldShowLabel(node, zoom) ||
        node.id === this.selectedNodeId ||
        node.id === this.hoveredNodeId ||
        this.connectedNodeSet.has(node.id) ||
        this.pathNodeSet.has(node.id)
      );
      if (labelNodes.length > MAX_LABELS) {
        const important = labelNodes.filter(node => node.high_value || node.owned || node.type === 'Domain');
        const ranked = [...labelNodes].sort((a, b) => (b.degree || 0) - (a.degree || 0));
        const merged = new Map();
        important.concat(ranked).forEach(node => merged.set(node.id, node));
        labelNodes = [...merged.values()].slice(0, MAX_LABELS);
      }

      labelNodes.forEach(node => {
        if (shouldCreateGlyph(node, this.nodeArray.length)) {
          const glyph = makeSprite(nodeGlyph(node), {
            fontSize: 16,
            color: colorForNode(node),
            background: 'rgba(0,0,0,0)',
            border: 'rgba(0,0,0,0)',
            stroke: '#030303',
            strokeWidth: 0,
            paddingX: 2,
            paddingY: 2,
            weight: '900',
          });
          glyph.position.set(node.x, node.y, LABEL_Z);
          glyph.scale.set(glyph.userData.textureEntry.width * 0.72, glyph.userData.textureEntry.height * 0.72, 1);
          this.labelGroup.add(glyph);
          this.labelSprites.push(glyph);
        }

        const text = nodeDisplayName(node);
        const label = makeSprite(text, {
          fontSize: node.type === 'Domain' ? 14 : 12,
          color: LABEL_TEXT,
          background: LABEL_BG,
          border: LABEL_BORDER,
          stroke: '#030303',
          strokeWidth: 3,
          paddingX: 8,
          paddingY: 4,
          weight: node.high_value || node.owned ? '800' : '700',
        });
        label.position.set(node.x, node.y + node.radius + 14, LABEL_Z);
        label.scale.set(label.userData.textureEntry.width, label.userData.textureEntry.height, 1);
        this.labelGroup.add(label);
        this.labelSprites.push(label);
      });

      const labelableEdges = this.edgeArray.filter(edge =>
        shouldCreateEdgeLabel(edge, this.edgeArray.length, this.nodeArray.length) ||
        this.connectedEdgeSet.has(edge.key) ||
        this.pathEdgeSet.has(edge.key)
      );
      labelableEdges.slice(0, MAX_EDGE_LABELS).forEach(edge => {
        const text = edge.relationship;
        const edgeLabel = makeSprite(text, {
          fontSize: 10,
          color: EDGE_LABEL_TEXT,
          background: EDGE_LABEL_BG,
          border: 'rgba(69,69,78,0.88)',
          stroke: '#030303',
          strokeWidth: 2,
          paddingX: 6,
          paddingY: 3,
          weight: '700',
        });
        edgeLabel.position.set((edge.source.x + edge.target.x) / 2, (edge.source.y + edge.target.y) / 2 - 10, LABEL_Z);
        edgeLabel.scale.set(edgeLabel.userData.textureEntry.width, edgeLabel.userData.textureEntry.height, 1);
        this.labelGroup.add(edgeLabel);
        this.edgeLabelSprites.push(edgeLabel);
      });
    }

    updateHover(nodeId, event) {
      if (nodeId === this.lastHoverNodeId) {
        if (nodeId) {
          const node = this.nodeById.get(nodeId);
          if (node) {
            this.canvas.style.cursor = 'pointer';
            showTooltip({
              pageX: event.pageX,
              pageY: event.pageY,
              clientX: event.clientX,
              clientY: event.clientY,
            }, node);
          }
        }
        return;
      }
      this.lastHoverNodeId = nodeId;
      this.hoveredNodeId = nodeId;
      if (!this.selectedNodeId) {
        this.rebuildHighlightOverlay();
      }
      if (nodeId) {
        const node = this.nodeById.get(nodeId);
        if (node) {
          this.canvas.style.cursor = 'pointer';
          showTooltip({
            pageX: event.pageX,
            pageY: event.pageY,
            clientX: event.clientX,
            clientY: event.clientY,
          }, node);
          if (!this.selectedNodeId) {
            this.hoverRing.visible = true;
            this.hoverRing.position.set(node.x, node.y, OVERLAY_Z);
            this.hoverRing.scale.setScalar(Math.max(3, node.radius * 1.32));
          }
        }
      } else {
        this.canvas.style.cursor = this.dragState ? 'grabbing' : 'grab';
        hideTooltip();
        this.hoverRing.visible = false;
      }
      this.render();
    }

    hitTest(clientX, clientY) {
      if (!this.baseNodeMesh) return null;
      const rect = this.canvas.getBoundingClientRect();
      const x = ((clientX - rect.left) / rect.width) * 2 - 1;
      const y = -(((clientY - rect.top) / rect.height) * 2 - 1);
      this.pointer.set(x, y);
      this.raycaster.setFromCamera(this.pointer, this.camera);
      const intersects = this.raycaster.intersectObject(this.baseNodeMesh, false);
      if (!intersects.length) return null;
      const hit = intersects[0];
      if (hit.instanceId === undefined || hit.instanceId === null) return null;
      return this.nodeArray[hit.instanceId] || null;
    }

    nodeScreenPosition(node) {
      const rect = this.canvas.getBoundingClientRect();
      return {
        x: rect.left + (node.x - this.camera.position.x) * this.camera.zoom,
        y: rect.top + (node.y - this.camera.position.y) * this.camera.zoom,
      };
    }

    nodesInClientRect(left, top, right, bottom) {
      const minX = Math.min(left, right);
      const maxX = Math.max(left, right);
      const minY = Math.min(top, bottom);
      const maxY = Math.max(top, bottom);
      return this.nodeArray.filter(node => {
        const pos = this.nodeScreenPosition(node);
        return pos.x >= minX && pos.x <= maxX && pos.y >= minY && pos.y <= maxY;
      });
    }

    updateSelectionBox(clientX, clientY) {
      if (!this.marqueeState || !this.selectionBox) return;
      const rect = this.container.getBoundingClientRect();
      const x1 = this.marqueeState.startX - rect.left;
      const y1 = this.marqueeState.startY - rect.top;
      const x2 = clientX - rect.left;
      const y2 = clientY - rect.top;
      this.selectionBox.style.display = 'block';
      this.selectionBox.style.left = `${Math.min(x1, x2)}px`;
      this.selectionBox.style.top = `${Math.min(y1, y2)}px`;
      this.selectionBox.style.width = `${Math.abs(x2 - x1)}px`;
      this.selectionBox.style.height = `${Math.abs(y2 - y1)}px`;
    }

    hideSelectionBox() {
      if (this.selectionBox) {
        this.selectionBox.style.display = 'none';
        this.selectionBox.style.width = '0px';
        this.selectionBox.style.height = '0px';
      }
    }

    screenToWorld(clientX, clientY) {
      const rect = this.canvas.getBoundingClientRect();
      const ndc = new THREE.Vector3(
        ((clientX - rect.left) / rect.width) * 2 - 1,
        -(((clientY - rect.top) / rect.height) * 2 - 1),
        0
      );
      return ndc.unproject(this.camera);
    }

    onPointerDown(event) {
      if (event.button !== 0) return;
      if (event.shiftKey) {
        this.marqueeState = {
          startX: event.clientX,
          startY: event.clientY,
          additive: true,
          toggle: event.ctrlKey || event.metaKey,
        };
        this.lastPointer = { x: event.clientX, y: event.clientY };
        this.canvas.setPointerCapture(event.pointerId);
        this.canvas.style.cursor = 'crosshair';
        this.updateSelectionBox(event.clientX, event.clientY);
        return;
      }
      this.dragState = {
        startX: event.clientX,
        startY: event.clientY,
        cameraX: this.camera.position.x,
        cameraY: this.camera.position.y,
        dragging: false,
      };
      this.lastPointer = { x: event.clientX, y: event.clientY };
      this.canvas.setPointerCapture(event.pointerId);
      this.canvas.style.cursor = 'grabbing';
    }

    onPointerMove(event) {
      this.lastPointer = { x: event.clientX, y: event.clientY };
      if (this.marqueeState) {
        this.updateSelectionBox(event.clientX, event.clientY);
        return;
      }
      if (this.dragState) {
        const dx = event.clientX - this.dragState.startX;
        const dy = event.clientY - this.dragState.startY;
        if (!this.dragState.dragging && Math.hypot(dx, dy) > 3) {
          this.dragState.dragging = true;
        }
        if (this.dragState.dragging) {
          this.hoveredNodeId = null;
          hideTooltip();
          this.canvas.style.cursor = 'grabbing';
          this.camera.position.x = this.dragState.cameraX - dx / this.camera.zoom;
          this.camera.position.y = this.dragState.cameraY - dy / this.camera.zoom;
          this.camera.updateProjectionMatrix();
          updateTransform(this.camera);
          this.render();
          return;
        }
      }
      const hit = this.hitTest(event.clientX, event.clientY);
      this.updateHover(hit ? hit.id : null, event);
    }

    onPointerUp(event) {
      if (this.marqueeState) {
        const state = this.marqueeState;
        let picked = this.nodesInClientRect(state.startX, state.startY, event.clientX, event.clientY);
        if (!picked.length && Math.hypot(event.clientX - state.startX, event.clientY - state.startY) < 4) {
          const hit = this.hitTest(event.clientX, event.clientY);
          picked = hit ? [hit] : [];
        }
        this.marqueeState = null;
        this.hideSelectionBox();
        this.canvas.style.cursor = 'grab';
        if (this.canvas.hasPointerCapture(event.pointerId)) {
          this.canvas.releasePointerCapture(event.pointerId);
        }
        if (picked.length && typeof window.selectNodes === 'function') {
          window.selectNodes(picked, state.toggle ? 'toggle' : 'add');
        }
        return;
      }
      if (this.dragState && this.dragState.dragging) {
        this.dragState = null;
        this.canvas.style.cursor = 'grab';
        if (this.canvas.hasPointerCapture(event.pointerId)) {
          this.canvas.releasePointerCapture(event.pointerId);
        }
        return;
      }
      const hit = this.hitTest(event.clientX, event.clientY);
      this.dragState = null;
      this.canvas.style.cursor = 'grab';
      if (this.canvas.hasPointerCapture(event.pointerId)) {
        this.canvas.releasePointerCapture(event.pointerId);
      }
      if (hit) {
        if ((event.ctrlKey || event.metaKey || event.shiftKey) && typeof window.toggleNodeSelection === 'function') {
          window.toggleNodeSelection(hit, event.shiftKey ? 'add' : 'toggle');
        } else if (typeof window.selectNode === 'function') {
          window.selectNode(hit);
        }
      } else if (typeof window.deselectAll === 'function') {
        window.deselectAll();
      }
    }

    onPointerLeave() {
      this.dragState = null;
      this.marqueeState = null;
      this.hideSelectionBox();
      this.hoveredNodeId = null;
      this.lastHoverNodeId = null;
      this.hoverRing.visible = false;
      hideTooltip();
      this.canvas.style.cursor = 'grab';
      this.render();
    }

    onWheel(event) {
      event.preventDefault();
      const zoomFactor = event.deltaY > 0 ? 0.9 : 1.1;
      const before = this.screenToWorld(event.clientX, event.clientY);
      this.camera.zoom = clamp(this.camera.zoom * zoomFactor, 0.04, 12);
      this.camera.updateProjectionMatrix();
      const after = this.screenToWorld(event.clientX, event.clientY);
      this.camera.position.x += before.x - after.x;
      this.camera.position.y += before.y - after.y;
      this.camera.updateProjectionMatrix();
      updateTransform(this.camera);
      this.refreshLabels();
      this.render();
    }

    render() {
      this.renderer.render(this.scene, this.camera);
      updateTransform(this.camera);
      this.pendingRender = false;
    }
  }

  function ensureRenderer() {
    if (!graphRenderer) {
      const canvas = document.getElementById('graph-canvas');
      graphRenderer = new ThreeGraphRenderer(canvas);
      window._threeGraphRenderer = graphRenderer;
    }
    return graphRenderer;
  }

  function installControls() {
    if (controlsInstalled) return;
    controlsInstalled = true;
    document.getElementById('zoom-in').addEventListener('click', zoomIn);
    document.getElementById('zoom-out').addEventListener('click', zoomOut);
    document.getElementById('zoom-fit').addEventListener('click', fitGraph);
    document.getElementById('render-button').addEventListener('click', () => renderSelectedChunk());
    document.getElementById('path-button').addEventListener('click', findAttackPath);
    document.getElementById('upload-btn').addEventListener('click', () => {
      document.getElementById('json-upload').click();
    });
    document.getElementById('json-upload').addEventListener('change', async (event) => {
      const file = event.target.files[0];
      if (!file) return;
      if (file.type !== 'application/json' && !file.name.endsWith('.json')) {
        alert('Only JSON files are allowed');
        return;
      }
      document.getElementById('graph-badge').textContent = 'Uploading...';
      try {
        const resp = await fetch('/api/upload', { method: 'POST', body: file });
        if (!resp.ok) throw new Error(await resp.text());
        const newGraph = await resp.json();
        await loadGraphList();
        document.getElementById('graph-select').value = newGraph.id;
        loadGraph(newGraph.id);
      } catch (e) {
        alert('Upload failed: ' + e.message);
        document.getElementById('graph-badge').textContent = 'Upload failed';
      }
      event.target.value = '';
    });
    document.getElementById('path-from').addEventListener('keydown', submitPathOnEnter);
    document.getElementById('path-to').addEventListener('keydown', submitPathOnEnter);
    bindSuggest('search-input', 'search-results', item => {
      document.getElementById('search-input').value = item.display_name;
      hideSearchResults();
      loadFocusedNode(item.id);
    });
    bindSuggest('path-from', 'from-results', item => {
      pathFromId = item.id;
      document.getElementById('path-from').value = item.display_name;
      hideSearchResults();
    });
    bindSuggest('path-to', 'to-results', item => {
      pathToId = item.id;
      document.getElementById('path-to').value = item.display_name;
      hideSearchResults();
    });
    document.getElementById('path-from').addEventListener('input', () => { pathFromId = ''; });
    document.getElementById('path-to').addEventListener('input', () => { pathToId = ''; });
    document.getElementById('render-select').addEventListener('change', event => {
      renderLimit = currentRenderLimit();
      renderOffset = 0;
      updateRenderLimitControls();
      updateChunkControls(graphData);
    });
    document.getElementById('render-custom').addEventListener('input', () => {
      renderLimit = currentRenderLimit();
      renderOffset = 0;
      updateChunkControls(graphData);
    });
    document.getElementById('prev-chunk').addEventListener('click', () => cycleChunk(-1));
    document.getElementById('next-chunk').addEventListener('click', () => cycleChunk(1));
    document.querySelectorAll('#type-filters input').forEach(input => {
      input.addEventListener('change', () => {
        hideSearchResults();
        renderOffset = 0;
        updateChunkControls(graphData);
        if (currentGraphId && graphData && graphData.nodes && graphData.nodes.length) {
          if (currentRenderLimit() === 'all') {
            document.getElementById('render-badge').textContent = 'ALL selected; press Render to confirm';
            return;
          }
          renderSelectedChunk({ warnAll: false });
        }
      });
    });
    document.addEventListener('keydown', event => {
      if (event.key === 'F3') {
        event.preventDefault();
        perfHudVisible = !perfHudVisible;
        document.getElementById('perf-hud').classList.toggle('active', perfHudVisible);
        updatePerfHud(graphData);
        return;
      }
      if (event.key === 'Escape') {
        hideSearchResults();
        deselectAll();
      }
    });
    document.getElementById('sidebar-close').addEventListener('click', () => {
      document.getElementById('app').classList.add('sidebar-collapsed');
    });
    document.getElementById('sidebar-toggle').addEventListener('click', () => {
      document.getElementById('app').classList.remove('sidebar-collapsed');
    });
  }

  function updateSelectionFromNode(node) {
    selectedNode = node;
    const renderer = ensureRenderer();
    renderer.selectNode(node);
    showNodeDetail(node.id);
  }

  function renderGraph(data) {
    const renderStarted = performance.now();
    const renderer = ensureRenderer();
    const container = document.getElementById('graph-container');
    const width = Math.max(640, container.clientWidth);
    const height = Math.max(480, container.clientHeight);
    const nodeCount = data.nodes.length;
    const nodesMap = {};

    if (!nodeCount) {
      setEmptyMessage('No nodes rendered', 'No nodes matched the current filter or chunk selection.');
      document.getElementById('empty-state').classList.remove('hidden');
      renderer.clearGraph();
      return;
    }
    document.getElementById('empty-state').classList.add('hidden');

    const nodes = data.nodes.map(raw => {
      const display = nodeDisplayName(raw);
      const node = {
        ...raw,
        display,
        degree: 0,
        radius: nodeRadius(raw, nodeCount),
      };
      nodesMap[node.id] = node;
      return node;
    });

    const links = data.edges
      .filter(edge => nodesMap[edge.source] && nodesMap[edge.target])
      .map(edge => {
        const source = nodesMap[edge.source];
        const target = nodesMap[edge.target];
        source.degree += 1;
        target.degree += 1;
        return {
          source,
          target,
          relationship: edge.relationship,
          cost: edge.cost,
          severity: edge.severity,
          guidance: edge.guidance,
          ovt_command: edge.ovt_command,
          ovt_command_desc: edge.ovt_command_desc,
          ace_details: edge.ace_details,
          key: edgeKey(edge.source, edge.target, edge.relationship),
        };
      });

    computeHierarchicalLayout(nodes, links, width, height, data.hops || []);
    window._nodesMap = nodesMap;
    graphData = data;
    renderer.setGraphData({ nodes, edges: links, width, height, graphData: data });
    fitGraph();
    data.render_time_ms = Math.max(0, Math.round(performance.now() - renderStarted));
    data.client_render_ms = data.render_time_ms;
    updateRenderBadge(data);
    updateChunkControls(data);
  }

  function teardownGraph() {
    selectedNode = null;
    if (graphRenderer) {
      graphRenderer.clearGraph();
    }
    window._nodesMap = {};
  }

  function refreshLabelVisibility() {
    if (!graphRenderer) return;
    graphRenderer.refreshLabels();
    graphRenderer.render();
  }

  function selectNode(node) {
    if (!graphData || !node) return;
    selectedNode = node;
    graphRenderer.selectNode(node);
    showNodeDetail(node.id);
  }

  function selectNodes(nodes, mode = 'replace') {
    if (!graphData || !graphRenderer) return;
    const picked = (nodes || []).filter(Boolean);
    if (!picked.length) return;
    graphRenderer.selectNodes(picked, mode);
    selectedNode = picked[picked.length - 1];
    showNodeDetail(selectedNode.id);
    const count = graphRenderer.selectedNodeIds ? graphRenderer.selectedNodeIds.size : picked.length;
    if (count > 1) {
      document.getElementById('render-badge').textContent = `${count} nodes selected`;
    }
  }

  function toggleNodeSelection(node, mode = 'toggle') {
    selectNodes([node], mode);
  }

  function deselectAll() {
    selectedNode = null;
    if (graphRenderer) {
      graphRenderer.clearSelection();
    }
    if (graphData) {
      clearNodeDetail();
    }
  }

  async function highlightNode(nodeId) {
    const node = window._nodesMap ? window._nodesMap[nodeId] : null;
    if (!node) {
      if (currentGraphId) {
        await loadFocusedNode(nodeId);
        return;
      }
      if (graphData && graphData.truncated) {
        document.getElementById('render-badge').textContent = 'Node not rendered — increase Render Budget';
      }
      return;
    }
    selectNode(node);
    zoomToNode(node);
  }

  function highlightPath(hops) {
    if (!graphRenderer || !graphData) return;
    graphRenderer.highlightPath(hops);
  }

  function zoomIn() {
    if (!graphRenderer) return;
    graphRenderer.zoomBy(1.35);
  }

  function zoomOut() {
    if (!graphRenderer) return;
    graphRenderer.zoomBy(0.74);
  }

  function fitGraph() {
    if (!graphRenderer) return;
    graphRenderer.fitToGraph();
  }

  function zoomToNode(node) {
    if (!graphRenderer || !node) return;
    graphRenderer.zoomToNode(node);
  }

  function renderEmptyStateOverride() {
    teardownGraph();
    if (typeof window.renderEmptyState === 'function') {
      window.renderEmptyState();
    }
  }

  function bootViewer() {
    if (booted) return;
    booted = true;
    ensureRenderer();
    installControls();
    renderStats(emptyStats());
    renderEmptyState();
    loadGraphList();
  }

  window.bootViewer = bootViewer;
  window.renderGraph = renderGraph;
  window.teardownGraph = teardownGraph;
  window.refreshLabelVisibility = refreshLabelVisibility;
  window.selectNode = selectNode;
  window.selectNodes = selectNodes;
  window.toggleNodeSelection = toggleNodeSelection;
  window.deselectAll = deselectAll;
  window.highlightNode = highlightNode;
  window.highlightPath = highlightPath;
  window.zoomIn = zoomIn;
  window.zoomOut = zoomOut;
  window.fitGraph = fitGraph;
  window.zoomToNode = zoomToNode;
})();
