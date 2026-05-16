/**
 * three-graph.js — BloodHound CE-style Three.js Graph Renderer
 * Refactored: perpendicular-offset bezier curves, dot-grid background,
 * crisp 2× DPR labels, glow halos, visible edge colors, clean arrows.
 */
(() => {
  const THREE = window.THREE;
  if (!THREE) {
    window.bootViewer = function bootViewerFallback() {
      const canInitD3 = typeof window.init === 'function' && typeof window.d3 !== 'undefined';
      if (canInitD3) { window.init(); return; }
      const empty = typeof window.emptyStats === 'function'
        ? window.emptyStats()
        : { users:0, computers:0, groups:0, domains:0, gpos:0, ous:0,
            cert_templates:0, high_value:0, owned:0, total_nodes:0, total_edges:0 };
      if (typeof window.renderStats === 'function') window.renderStats(empty);
      if (typeof window.renderEmptyState === 'function') window.renderEmptyState();
      if (typeof window.loadGraphList === 'function') window.loadGraphList();
      if (typeof window.setEmptyMessage === 'function') {
        window.setEmptyMessage('Three.js unavailable',
          'WebGL could not be loaded. Graph stats and sources are still available.');
      }
      try {
        const p = document.getElementById('panel-stats');
        if (p) p.classList.remove('collapsed');
      } catch (_) {}
    };
    return;
  }

  // ============================================================================
  // CONSTANTS — BloodHound CE palette
  // ============================================================================
  const MAX_LABELS            = 800;
  const MAX_EDGE_LABELS       = 400;
  const MAX_HIGHLIGHT_EDGES   = 5000;
  const MAX_HIGHLIGHT_NODES   = 3500;
  const MAX_LIVE_DRAG_NODES   = 300;

  const NODE_Z    = 0;
  const GLOW_Z    = -0.5;
  const LABEL_Z   = 2;
  const OVERLAY_Z = 4;

  // Visual config
  const NODE_SEGMENTS  = 36;
  const ARROW_SIZE     = 22;
  const NODE_BASE_RADIUS = 38;
  const GRAPH_X_SPREAD  = 3.5;

  // Color tokens
  const BG_HEX         = 0x0d1117;
  const BG_CSS         = '#0d1117';
  const GRID_DOT_CSS   = 'rgba(148,163,184,0.13)';
  const GRID_SIZE_PX   = 32;

  const LABEL_BG       = 'rgba(13,17,23,0.93)';
  const LABEL_BORDER   = 'rgba(71,85,105,0.55)';
  const LABEL_TEXT     = '#e2e8f0';
  const EDGE_LABEL_BG  = 'rgba(13,17,23,0.90)';
  const EDGE_LABEL_TXT = '#94a3b8';

  // Node type colors — BloodHound CE exact
  const NODE_COLORS = {
    User:         '#17E625',
    Computer:     '#E67873',
    Group:        '#DBE617',
    Domain:       '#17E6B9',
    OU:           '#FFAA00',
    GPO:          '#998EFD',
    CertTemplate: '#B153F3',
    Unknown:      '#94a3b8',
  };

  // Edge relationship colors
  const EDGE_COLORS = {
    Owns:             '#ef4444',
    AdminTo:          '#ef4444',
    CanBeAdminTo:     '#f97316',
    AllExtendedRights:'#ef4444',
    GenericAll:       '#ef4444',
    WriteDacl:        '#f97316',
    WriteOwner:       '#f97316',
    GenericWrite:     '#eab308',
    ForceChangePassword:'#f97316',
    DCSync:           '#ef4444',
    GetChanges:       '#f97316',
    GetChangesAll:    '#ef4444',
    MemberOf:         '#64748b',
    Contains:         '#64748b',
    GpLink:           '#64748b',
    HasSession:       '#6366f1',
    AllowedToDelegate:'#8b5cf6',
    AllowedToAct:     '#8b5cf6',
    TrustedBy:        '#0ea5e9',
    SyncLAPSPassword: '#f97316',
  };
  const NORMAL_EDGE = '#4e7ab5';

  const CRITICAL_RELS = new Set([
    'Owns','AdminTo','GenericAll','AllExtendedRights','WriteDacl','WriteOwner','CanBeAdminTo',
    'DCSync','GetChangesAll','SyncLAPSPassword',
  ]);

  let graphRenderer    = null;
  let controlsInstalled = false;
  let booted           = false;
  let graphData        = null;
  let selectedNode     = null;

  // ============================================================================
  // UTILITY
  // ============================================================================

  function clamp(v, lo, hi) { return v < lo ? lo : v > hi ? hi : v; }

  function clearObject(obj, preserveMaterials = false) {
    if (!obj) return;
    while (obj.children.length) { const c = obj.children.pop(); clearObject(c); }
    obj.geometry && obj.geometry.dispose();
    if (!preserveMaterials && obj.material) {
      (Array.isArray(obj.material) ? obj.material : [obj.material])
        .forEach(m => m.dispose());
    }
  }

  function colorForNode(node) { return NODE_COLORS[node.type] || NODE_COLORS.Unknown; }

  function colorForEdge(rel) { return EDGE_COLORS[rel] || NORMAL_EDGE; }

  function importantEdge(rel) { return CRITICAL_RELS.has(rel); }

  function edgeLineIntensity(rel) { return importantEdge(rel) ? 1.35 : 0.95; }

  function edgeKey(src, tgt, rel) { return `${src}|${tgt}|${rel}`; }

  function curveSegsFor(edges, nodes) {
    if (edges > 50000 || nodes > 15000) return 4;
    if (edges > 30000 || nodes > 10000) return 6;
    if (edges > 10000 || nodes >  5000) return 8;
    if (edges >  3000 || nodes >  1600) return 10;
    return 16;
  }

  function nodeDisplayName(node) {
    if (node.display_name) return node.display_name;
    if (node.name)         return node.name;
    return (node.id || '').split('@')[0] || node.id || '?';
  }

  function nodeRadius(node, nodeCount) {
    // Keep the visible node circle uniform across all types.
    return NODE_BASE_RADIUS;
  }

  function spreadGraphNodes(nodes, xFactor = GRAPH_X_SPREAD, yFactor = 1.14) {
    if (!nodes.length) return;

    const xs = nodes.map(node => node.x || 0);
    const ys = nodes.map(node => node.y || 0);
    const minX = Math.min(...xs);
    const maxX = Math.max(...xs);
    const minY = Math.min(...ys);
    const maxY = Math.max(...ys);
    const centerX = (minX + maxX) / 2;
    const centerY = (minY + maxY) / 2;

    nodes.forEach(node => {
      node.x = centerX + ((node.x || 0) - centerX) * xFactor;
      node.y = centerY + ((node.y || 0) - centerY) * yFactor;
    });
  }

  function shouldShowLabel(node, zoom) {
    // Always show labels — BloodHound CE style shows them at all practical zoom levels
    return zoom > 0.04;
  }

  // ============================================================================
  // EDGE CURVE — perpendicular-offset bezier (KEY FIX vs original)
  // ============================================================================

  /**
   * Build cubic bezier control points using a perpendicular offset.
   * This eliminates the horizontal-axis bias of the old code, producing
   * smooth arcs that stay near the actual edge endpoints.
   *
   * For parallel edges between the same pair of nodes, pass edgeIndex / totalEdges
   * to fan them out perpendicular to the edge direction.
   */
  function edgeCurveControl(edge, edgeIndex = 0, parallelCount = 1) {
    const sx = edge.source.x, sy = edge.source.y;
    const tx = edge.target.x, ty = edge.target.y;
    const dx = tx - sx, dy = ty - sy;
    const dist = Math.sqrt(dx * dx + dy * dy);

    if (dist < 2) return { sx, sy, c1x:sx, c1y:sy, c2x:tx, c2y:ty, tx, ty };

    // Unit perpendicular (always same side → consistent, clean look)
    const px = -dy / dist;
    const py =  dx / dist;

    // Curvature: 18% of edge length, max 80px world units
    const base  = Math.min(dist * 0.18, 80);
    // Fan offset for parallel edges
    const fan   = parallelCount > 1
      ? (edgeIndex - (parallelCount - 1) / 2) * 35
      : 0;
    const curve = base + fan;

    return {
      sx, sy,
      c1x: sx + dx * 0.28 + px * curve,
      c1y: sy + dy * 0.28 + py * curve,
      c2x: tx - dx * 0.28 + px * curve,
      c2y: ty - dy * 0.28 + py * curve,
      tx, ty,
    };
  }

  function cubicAt(a, b, c, d, t) {
    const m = 1 - t;
    return m*m*m*a + 3*m*m*t*b + 3*m*t*t*c + t*t*t*d;
  }
  function cubicTanAt(a, b, c, d, t) {
    const m = 1 - t;
    return 3*m*m*(b-a) + 6*m*t*(c-b) + 3*t*t*(d-c);
  }
  function edgeCurvePoint(edge, t) {
    const p = edgeCurveControl(edge);
    return { x: cubicAt(p.sx,p.c1x,p.c2x,p.tx,t), y: cubicAt(p.sy,p.c1y,p.c2y,p.ty,t) };
  }
  function edgeCurveAngle(edge, t) {
    const p = edgeCurveControl(edge);
    return Math.atan2(cubicTanAt(p.sy,p.c1y,p.c2y,p.ty,t), cubicTanAt(p.sx,p.c1x,p.c2x,p.tx,t));
  }

  function writeCurveSegs(edge, pos, col, ei, segs, color) {
    for (let s = 0; s < segs; s++) {
      const a = edgeCurvePoint(edge, s / segs);
      const b = edgeCurvePoint(edge, (s + 1) / segs);
      const off = (ei * segs + s) * 6;
      pos[off]=a.x; pos[off+1]=a.y; pos[off+2]=0;
      pos[off+3]=b.x; pos[off+4]=b.y; pos[off+5]=0;
      col[off]=color.r; col[off+1]=color.g; col[off+2]=color.b;
      col[off+3]=color.r; col[off+4]=color.g; col[off+5]=color.b;
    }
  }

  // ============================================================================
  // SPRITE / LABEL TEXTURE — 2× DPR for crisp text
  // ============================================================================

  function makeSpriteTexture(text, opts = {}) {
    const {
      fontSize     = 12,
      fontFamily   = '"Inter","Segoe UI","Helvetica Neue",Arial,sans-serif',
      color        = LABEL_TEXT,
      background   = LABEL_BG,
      border       = LABEL_BORDER,
      paddingX     = 10,
      paddingY     = 5,
      strokeColor  = 'rgba(0,0,0,0.75)',
      strokeWidth  = 2.5,
      weight       = '500',
      maxWidth     = 560,
      borderRadius = 5,
    } = opts;

    const DPR = 2;
    const key = [text, fontSize, color, background, border, paddingX, paddingY, strokeWidth, weight].join('|');
    if (!makeSpriteTexture._cache) makeSpriteTexture._cache = new Map();
    const cache = makeSpriteTexture._cache;
    if (cache.has(key)) return cache.get(key);

    const probe = document.createElement('canvas').getContext('2d');
    probe.font = `${weight} ${fontSize}px ${fontFamily}`;
    const measured = Math.ceil(probe.measureText(text).width);
    const lw = Math.max(40, Math.min(maxWidth, measured + paddingX * 2));
    const lh = Math.max(20, Math.ceil(fontSize + paddingY * 2 + 2));

    const canvas = document.createElement('canvas');
    canvas.width  = lw * DPR;
    canvas.height = lh * DPR;
    const ctx = canvas.getContext('2d');
    ctx.scale(DPR, DPR);
    ctx.font          = `${weight} ${fontSize}px ${fontFamily}`;
    ctx.textBaseline  = 'middle';
    ctx.textAlign     = 'left';
    ctx.clearRect(0, 0, lw, lh);

    function rr(x, y, w, h, r) {
      ctx.beginPath();
      ctx.moveTo(x+r,y); ctx.lineTo(x+w-r,y); ctx.quadraticCurveTo(x+w,y,x+w,y+r);
      ctx.lineTo(x+w,y+h-r); ctx.quadraticCurveTo(x+w,y+h,x+w-r,y+h);
      ctx.lineTo(x+r,y+h); ctx.quadraticCurveTo(x,y+h,x,y+h-r);
      ctx.lineTo(x,y+r); ctx.quadraticCurveTo(x,y,x+r,y);
      ctx.closePath();
    }

    if (background) {
      ctx.fillStyle = background;
      rr(0, 0, lw, lh, borderRadius);
      ctx.fill();
    }
    if (border) {
      ctx.strokeStyle = border;
      ctx.lineWidth = 1;
      rr(0.5, 0.5, lw-1, lh-1, borderRadius - 0.5);
      ctx.stroke();
    }
    if (strokeWidth > 0) {
      ctx.lineWidth   = strokeWidth;
      ctx.strokeStyle = strokeColor;
      ctx.lineJoin    = 'round';
      ctx.strokeText(text, paddingX, lh / 2);
    }
    ctx.fillStyle = color;
    ctx.fillText(text, paddingX, lh / 2);

    const tex = new THREE.CanvasTexture(canvas);
    // When used on PlaneGeometry the canvas texture can appear vertically flipped;
    // ensure it's not flipped so text is upright for Mesh-based labels.
    tex.flipY = false;
    tex.minFilter        = THREE.LinearFilter;
    tex.magFilter        = THREE.LinearFilter;
    tex.generateMipmaps  = false;
    tex.needsUpdate      = true;

    const entry = { texture: tex, width: lw, height: lh, dispose() { tex.dispose(); } };
    cache.set(key, entry);
    return entry;
  }

  function makeSprite(text, opts = {}) {
    const te  = makeSpriteTexture(text, opts);
    const mat = new THREE.SpriteMaterial({
      map: te.texture, transparent: true,
      depthTest: false, depthWrite: false, fog: false,
      renderOrder: 1000,
    });
    const spr      = new THREE.Sprite(mat);
    spr.userData.textureEntry = te;
    spr.scale.set(te.width, te.height, 1);
    spr.renderOrder = 1000;
    return spr;
  }

  // ============================================================================
  // NODE ICON DRAWING — BloodHound CE style icons inside colored circles
  // ============================================================================

  function drawNodeIcon(ctx, type, cx, cy, r) {
    ctx.fillStyle   = 'rgba(255,255,255,0.20)';
    ctx.strokeStyle = 'rgba(255,255,255,0.20)';

    const drawPerson = (pcx, pcy, pr) => {
      // Head
      ctx.beginPath();
      ctx.arc(pcx, pcy - pr * 0.30, pr * 0.27, 0, Math.PI * 2);
      ctx.fill();
      // Shoulders arc (clipped to upper half)
      ctx.beginPath();
      ctx.arc(pcx, pcy + pr * 0.68, pr * 0.52, Math.PI, 0);
      ctx.fill();
    };

    switch (type) {
      case 'User': {
        drawPerson(cx, cy + r * 0.04, r);
        break;
      }
      case 'Computer': {
        // Monitor screen
        const mw = r * 1.05, mh = r * 0.76;
        const mx = cx - mw / 2, my = cy - mh / 2 - r * 0.08;
        ctx.beginPath();
        ctx.roundRect(mx, my, mw, mh, r * 0.07);
        ctx.fill();
        // Screen inner (highlight cutout)
        ctx.fillStyle = 'rgba(255,255,255,0.18)';
        ctx.beginPath();
        ctx.roundRect(mx + r * 0.07, my + r * 0.06, mw - r * 0.14, mh - r * 0.14, r * 0.04);
        ctx.fill();
        // Draw icon details in light (white) so the underlying node color remains visible
        ctx.fillStyle = 'rgba(255,255,255,0.88)';
        // Stand
        ctx.fillRect(cx - r * 0.07, my + mh, r * 0.14, r * 0.20);
        // Base
        ctx.fillRect(cx - r * 0.28, my + mh + r * 0.20, r * 0.56, r * 0.09);
        break;
      }
      case 'Group': {
        // Center person
        drawPerson(cx, cy + r * 0.06, r * 0.66);
        // Left person (behind)
        ctx.globalAlpha = 0.65;
        drawPerson(cx - r * 0.46, cy + r * 0.14, r * 0.50);
        // Right person (behind)
        drawPerson(cx + r * 0.46, cy + r * 0.14, r * 0.50);
        ctx.globalAlpha = 1.0;
        break;
      }
      case 'Domain': {
        // Globe outline
        ctx.lineWidth = r * 0.10;
        ctx.beginPath();
        ctx.arc(cx, cy, r * 0.60, 0, Math.PI * 2);
        ctx.stroke();
        // Horizontal equator
        ctx.beginPath();
        ctx.moveTo(cx - r * 0.60, cy);
        ctx.lineTo(cx + r * 0.60, cy);
        ctx.stroke();
        // Vertical meridian
        ctx.beginPath();
        ctx.moveTo(cx, cy - r * 0.60);
        ctx.lineTo(cx, cy + r * 0.60);
        ctx.stroke();
        // Longitude ellipse
        ctx.beginPath();
        ctx.ellipse(cx, cy, r * 0.26, r * 0.60, 0, 0, Math.PI * 2);
        ctx.stroke();
        break;
      }
      case 'GPO': {
        // Outer gear ring
        const teeth = 8, innerR = r * 0.38, outerR = r * 0.60, toothW = r * 0.14;
        ctx.lineWidth = toothW;
        ctx.lineCap = 'round';
        for (let i = 0; i < teeth; i++) {
          const a = (i / teeth) * Math.PI * 2;
          ctx.beginPath();
          ctx.moveTo(cx + Math.cos(a) * innerR, cy + Math.sin(a) * innerR);
          ctx.lineTo(cx + Math.cos(a) * outerR, cy + Math.sin(a) * outerR);
          ctx.stroke();
        }
        ctx.lineCap = 'butt';
        // Gear body ring
        ctx.lineWidth = r * 0.11;
        ctx.beginPath();
        ctx.arc(cx, cy, innerR, 0, Math.PI * 2);
        ctx.stroke();
        // Center dot
        ctx.beginPath();
        ctx.arc(cx, cy, r * 0.18, 0, Math.PI * 2);
        ctx.fill();
        break;
      }
      case 'OU': {
        // Folder shape
        const fw = r * 1.14, fh = r * 0.84;
        const fx = cx - fw / 2, fy = cy - fh / 2 + r * 0.05;
        ctx.beginPath();
        ctx.moveTo(fx, fy + fh * 0.28);
        ctx.lineTo(fx, fy + fh);
        ctx.lineTo(fx + fw, fy + fh);
        ctx.lineTo(fx + fw, fy + fh * 0.28);
        ctx.lineTo(fx + fw * 0.55, fy + fh * 0.28);
        ctx.lineTo(fx + fw * 0.42, fy);
        ctx.lineTo(fx + fw * 0.1, fy);
        ctx.closePath();
        ctx.fill();
        break;
      }
      case 'CertTemplate': {
        // Key shape
        const kr = r * 0.30;
        // Key head (circle)
        ctx.lineWidth = r * 0.11;
        ctx.beginPath();
        ctx.arc(cx - r * 0.20, cy + r * 0.04, kr, 0, Math.PI * 2);
        ctx.stroke();
        // Key hole
        ctx.fillStyle = colorForNode({ type: 'CertTemplate' });
        ctx.beginPath();
        ctx.arc(cx - r * 0.20, cy + r * 0.04, kr * 0.42, 0, Math.PI * 2);
        ctx.fill();
        // Use light strokes/fills for key shaft/teeth so icons don't mask node color
        ctx.fillStyle = 'rgba(255,255,255,0.88)';
        // Shaft
        ctx.fillRect(cx + r * 0.10, cy + r * 0.04 - r * 0.09, r * 0.52, r * 0.18);
        // Teeth
        ctx.fillRect(cx + r * 0.36, cy + r * 0.13, r * 0.10, r * 0.16);
        ctx.fillRect(cx + r * 0.50, cy + r * 0.13, r * 0.08, r * 0.12);
        break;
      }
      default: {
        ctx.lineWidth = r * 0.12;
        ctx.beginPath();
        ctx.arc(cx, cy, r * 0.55, 0, Math.PI * 2);
        ctx.stroke();
        ctx.beginPath();
        ctx.arc(cx, cy, r * 0.18, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  }

  // Cache: one texture per node type (icons are type-only, not color-specific)
  const _iconCache = new Map();
  function makeNodeIconTexture(type) {
    if (_iconCache.has(type)) return _iconCache.get(type);
    const SIZE = 128;
    const canvas = document.createElement('canvas');
    canvas.width = SIZE; canvas.height = SIZE;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, SIZE, SIZE);
    const cx = SIZE / 2, cy = SIZE / 2, r = SIZE / 2 * 0.72;
    drawNodeIcon(ctx, type, cx, cy, r);
    const tex = new THREE.CanvasTexture(canvas);
    tex.minFilter = THREE.LinearFilter;
    tex.magFilter = THREE.LinearFilter;
    tex.generateMipmaps = false;
    tex.needsUpdate = true;
    const entry = { texture: tex, size: SIZE };
    _iconCache.set(type, entry);
    return entry;
  }

  const currentTransform = { x: 0, y: 0, k: 1 };
  function updateTransform(cam) {
    currentTransform.k = cam.zoom;
    currentTransform.x = cam.position.x;
    currentTransform.y = cam.position.y;
  }

  // ============================================================================
  // RENDERER CLASS
  // ============================================================================

  class ThreeGraphRenderer {
    constructor(canvas) {
      this.canvas    = canvas;
      this.container = canvas.parentElement;
      this.selectionBox = document.getElementById('selection-box');

      this._applyContainerStyles();

      this.renderer = new THREE.WebGLRenderer({
        canvas,
        antialias:          true,
        alpha:              true,       // transparent so CSS grid shows
        powerPreference:    'high-performance',
        precision:          'mediump',
        preserveDrawingBuffer: false,
        depth:              true,
        stencil:            false,
      });
      this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      this.renderer.setClearColor(0x000000, 0);  // fully transparent
      this.renderer.sortObjects = true;

      this.scene  = new THREE.Scene();
      this.camera = new THREE.OrthographicCamera(0, 1, 1, 0, 0.1, 10000);
      this.camera.position.set(0, 0, 1000);
      this.camera.zoom = 1;
      this.scene.add(this.camera);

      this.root = new THREE.Group();
      this.scene.add(this.root);

      this.baseEdgeGroup    = new THREE.Group();
      this.baseNodeGroup    = new THREE.Group();
      this.overlayEdgeGroup = new THREE.Group();
      this.overlayNodeGroup = new THREE.Group();
      this.labelGroup       = new THREE.Group();
      this.labelGroup.renderOrder = 1000;

      this.root.add(this.baseEdgeGroup);
      this.root.add(this.baseNodeGroup);
      this.root.add(this.overlayEdgeGroup);
      this.root.add(this.overlayNodeGroup);
      this.root.add(this.labelGroup);

      // ── Shared geometries ──────────────────────────────────────────────────
      this.baseNodeGeometry      = new THREE.CircleGeometry(1, NODE_SEGMENTS);
      this.highlightNodeGeometry = new THREE.RingGeometry(1.05, 1.75, NODE_SEGMENTS);
      this.selectionGeometry     = new THREE.RingGeometry(1.12, 1.95, NODE_SEGMENTS);
      this.nodeBorderGeometry    = new THREE.RingGeometry(0.83, 1.08, NODE_SEGMENTS);
      this.glowGeometry          = new THREE.CircleGeometry(1, NODE_SEGMENTS);

      const arrowPts = new Float32Array([
        0, 0, 0,
        -ARROW_SIZE, ARROW_SIZE * 0.44, 0,
        -ARROW_SIZE, -ARROW_SIZE * 0.44, 0,
      ]);
      this.arrowGeometry = new THREE.BufferGeometry();
      this.arrowGeometry.setAttribute('position', new THREE.BufferAttribute(arrowPts, 3));

      // ── Materials ──────────────────────────────────────────────────────────
      this.baseNodeMaterial = new THREE.MeshBasicMaterial({
        color: 0xffffff, depthWrite: false, side: THREE.DoubleSide,
        toneMapped: false,
      });
      this.glowMaterial = new THREE.MeshBasicMaterial({
        transparent: true, opacity: 0.22, vertexColors: true,
        depthWrite: false, side: THREE.DoubleSide,
        blending: THREE.AdditiveBlending,
      });
      this.highlightNodeMaterial = new THREE.MeshBasicMaterial({
        transparent: true, opacity: 1.0, vertexColors: true,
        depthWrite: false, side: THREE.DoubleSide,
        blending: THREE.AdditiveBlending,
      });
      this.nodeBorderMaterial = new THREE.MeshBasicMaterial({
        color: 0x000000, transparent: true, opacity: 0.5,
        depthWrite: false, side: THREE.DoubleSide,
      });
      this.selectionMaterial = new THREE.MeshBasicMaterial({
        color: 0xffffff, transparent: true, opacity: 0.95,
        depthWrite: false, side: THREE.DoubleSide,
      });
      this.hoverMaterial = new THREE.MeshBasicMaterial({
        color: 0x60a5fa, transparent: true, opacity: 0.88,
        depthWrite: false, side: THREE.DoubleSide,
      });
      this.arrowMaterial = new THREE.MeshBasicMaterial({
        color: 0xffffff, transparent: true, opacity: 0.92,
        depthWrite: false, side: THREE.DoubleSide, renderOrder: 2,
      });
      this.baseLineMaterial = new THREE.LineBasicMaterial({
        vertexColors: true, transparent: true, opacity: 0.85,
        depthWrite: false, linewidth: 1,
      });
      this.baseDashMaterial = new THREE.LineDashedMaterial({
        vertexColors: true, transparent: true, opacity: 0.6,
        depthWrite: false, dashSize: 12, gapSize: 8, linewidth: 1,
      });
      this.highlightLineMaterial = new THREE.LineBasicMaterial({
        vertexColors: true, transparent: true, opacity: 1.0,
        depthWrite: false, linewidth: 2,
      });

      // ── Overlay singles ────────────────────────────────────────────────────
      this.selectionRing = new THREE.Mesh(this.selectionGeometry, this.selectionMaterial.clone());
      this.hoverRing     = new THREE.Mesh(this.selectionGeometry, this.hoverMaterial.clone());
      this.selectionRing.visible = false;
      this.hoverRing.visible     = false;
      this.overlayNodeGroup.add(this.selectionRing);
      this.overlayNodeGroup.add(this.hoverRing);

      // ── State ──────────────────────────────────────────────────────────────
      this.baseNodeMesh    = null;
      this.baseNodeMeshes  = [];
      this.nodeBorderMesh  = null;
      this.glowNodeMesh    = null;
      this.specialNodeMesh = null;
      this.specialNodeArray = [];
      this.overlayNodeLayer = null;

      this.baseEdgeMeshes     = [];
      this.baseArrowMesh      = null;
      this.baseArrowMeshes    = [];
      this.highlightEdgeMeshes = [];
      this.labelSprites       = [];
      this.edgeLabelSprites   = [];
      this.nodeIconSprites    = [];

      this.nodeArray = []; this.edgeArray = [];
      this.nodeById  = new Map(); this.edgeByKey = new Map();
      this.connectedNodeSet = new Set(); this.connectedEdgeSet = new Set();
      this.pathNodeSet      = new Set(); this.pathEdgeSet      = new Set();
      this.selectedNodeIds  = new Set();
      this.selectedNodeId   = null;
      this.hoveredNodeId    = null;
      this.lastHoverNodeId  = null;
      this.highlightMode    = null;
      this.pendingRender    = false;
      this.dragState        = null;
      this.nodeDragState    = null;
      this.marqueeState     = null;
      this.lastPointer      = { x: 0, y: 0 };

      this.raycaster = new THREE.Raycaster();
      this.pointer   = new THREE.Vector2();

      // ── Events ─────────────────────────────────────────────────────────────
      this.boundPointerDown  = this.onPointerDown.bind(this);
      this.boundPointerMove  = this.onPointerMove.bind(this);
      this.boundPointerUp    = this.onPointerUp.bind(this);
      this.boundPointerLeave = this.onPointerLeave.bind(this);
      this.boundWheel        = this.onWheel.bind(this);
      this.boundResize       = this.resize.bind(this);
      this.boundContextMenu  = e => e.preventDefault();

      this.canvas.style.touchAction = 'none';
      this.canvas.style.cursor      = 'grab';
      this.canvas.addEventListener('pointerdown',  this.boundPointerDown);
      this.canvas.addEventListener('pointermove',  this.boundPointerMove);
      this.canvas.addEventListener('pointerup',    this.boundPointerUp);
      this.canvas.addEventListener('pointerleave', this.boundPointerLeave);
      this.canvas.addEventListener('wheel',        this.boundWheel, { passive: false });
      this.canvas.addEventListener('contextmenu',  this.boundContextMenu);
      window.addEventListener('resize', this.boundResize);

      this.resize();
    }

    // ── Container CSS — BloodHound CE dot-grid background ───────────────────
    _applyContainerStyles() {
      if (!this.container) return;
      this.container.style.backgroundColor  = BG_CSS;
      this.container.style.backgroundImage  =
        `radial-gradient(circle, ${GRID_DOT_CSS} 1.5px, transparent 1.5px)`;
      this.container.style.backgroundSize   = `${GRID_SIZE_PX}px ${GRID_SIZE_PX}px`;
      // Canvas itself must be transparent
      this.canvas && (this.canvas.style.background = 'transparent');
    }

    dispose() {
      this.canvas.removeEventListener('pointerdown',  this.boundPointerDown);
      this.canvas.removeEventListener('pointermove',  this.boundPointerMove);
      this.canvas.removeEventListener('pointerup',    this.boundPointerUp);
      this.canvas.removeEventListener('pointerleave', this.boundPointerLeave);
      this.canvas.removeEventListener('wheel',        this.boundWheel);
      this.canvas.removeEventListener('contextmenu',  this.boundContextMenu);
      window.removeEventListener('resize', this.boundResize);
      this.clearGraph();
      this.renderer.dispose();
    }

    resize() {
      const rect = this.container.getBoundingClientRect();
      this.width  = Math.max(1, rect.width);
      this.height = Math.max(1, rect.height);
      this.renderer.setSize(this.width, this.height, false);
      this.camera.left   = 0;
      this.camera.right  = this.width;
      this.camera.top    = 0;
      this.camera.bottom = this.height;
      this.camera.updateProjectionMatrix();
      this.render();
    }

    // ── Graph data ────────────────────────────────────────────────────────────

    setGraphData({ nodes, edges, width, height, graphData: gd }) {
      this.clearGraph();
      this.nodeArray = nodes; this.edgeArray = edges;
      this.graphData = gd;
      this.width     = width; this.height = height;
      this.nodeById.clear(); this.edgeByKey.clear();
      nodes.forEach((n, i) => { n._index = i; this.nodeById.set(n.id, n); });
      edges.forEach(e => this.edgeByKey.set(e.key, e));

      this.buildNodeMesh();
      this.buildEdgeMeshes();
      const arrowMeshes = this.buildArrowMesh(this.edgeArray) || [];
      arrowMeshes.forEach(mesh => this.baseEdgeGroup.add(mesh));

      this.fitToGraph();
      this.refreshLabels();
      this.render();
    }

    clearGraph() {
      this.nodeArray = []; this.edgeArray = [];
      this.nodeById.clear(); this.edgeByKey.clear();
      this.connectedNodeSet.clear(); this.connectedEdgeSet.clear();
      this.pathNodeSet.clear(); this.pathEdgeSet.clear();
      this.selectedNodeIds.clear();
      this.selectedNodeId = null; this.hoveredNodeId = null; this.lastHoverNodeId = null;
      this._hideSelectionBox();
      this.selectionRing.visible = false; this.hoverRing.visible = false;
      this._disposeScene();
      this.render();
    }

    _disposeScene() {
      clearObject(this.baseEdgeGroup);
      clearObject(this.baseNodeGroup);
      clearObject(this.overlayEdgeGroup);
      clearObject(this.overlayNodeGroup);
      clearObject(this.labelGroup);
      this.baseEdgeMeshes     = []; this.baseArrowMesh = null; this.baseArrowMeshes = [];
      this.highlightEdgeMeshes = [];
      this.labelSprites       = []; this.edgeLabelSprites = [];
      this.nodeIconSprites    = [];
      this.baseNodeMesh       = null; this.baseNodeMeshes = []; this.nodeBorderMesh = null;
      this.glowNodeMesh       = null;
      this.specialNodeMesh    = null; this.specialNodeArray = [];
      this.overlayNodeLayer   = null;

      // Recreate overlay singles
      this.selectionRing = new THREE.Mesh(this.selectionGeometry, this.selectionMaterial.clone());
      this.hoverRing     = new THREE.Mesh(this.selectionGeometry, this.hoverMaterial.clone());
      this.selectionRing.visible = false; this.hoverRing.visible = false;
      this.overlayNodeGroup.add(this.selectionRing);
      this.overlayNodeGroup.add(this.hoverRing);

      if (makeSpriteTexture._cache) {
        makeSpriteTexture._cache.forEach(e => e.dispose());
        makeSpriteTexture._cache.clear();
      }
    }

    // ── Node mesh ─────────────────────────────────────────────────────────────

    buildNodeMesh() {
      if (!this.nodeArray.length) return;
      const dummy = new THREE.Object3D();
      const color = new THREE.Color();

      // Glow for high-value / owned / domain nodes (additive bloom effect)
      const glowNodes = this.nodeArray.filter(n => n.high_value || n.owned || n.type === 'Domain');
      if (glowNodes.length) {
        const gm = new THREE.InstancedMesh(this.glowGeometry, this.glowMaterial.clone(), glowNodes.length);
        gm.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
        glowNodes.forEach((n, i) => {
          dummy.position.set(n.x, n.y, GLOW_Z);
          dummy.scale.setScalar(Math.max(4, n.radius * 2.2));
          dummy.updateMatrix();
          gm.setMatrixAt(i, dummy.matrix);
          color.set(n.owned ? '#00d084' : n.type === 'Domain' ? '#17E6B9' : '#f4c95d');
          gm.setColorAt(i, color);
        });
        gm.instanceMatrix.needsUpdate = true;
        if (gm.instanceColor) gm.instanceColor.needsUpdate = true;
        this.glowNodeMesh = gm;
        this.glowNodeArray = glowNodes;
        this.baseNodeGroup.add(gm);
      }

      // Main circle meshes grouped by node type so the fill color comes from the material.
      const nodeGroups = new Map();
      this.nodeArray.forEach(node => {
        const key = node.type || 'Unknown';
        if (!nodeGroups.has(key)) nodeGroups.set(key, []);
        nodeGroups.get(key).push(node);
      });
      nodeGroups.forEach((groupNodes, type) => {
        const meshMaterial = this.baseNodeMaterial.clone();
        meshMaterial.vertexColors = false;
        meshMaterial.color.set(colorForNode({ type }));
        const mesh = new THREE.InstancedMesh(this.baseNodeGeometry, meshMaterial, groupNodes.length);
        mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
        mesh.userData.nodes = groupNodes;
        groupNodes.forEach((n, i) => {
          dummy.position.set(n.x, n.y, NODE_Z);
          dummy.scale.setScalar(Math.max(4, n.radius));
          dummy.updateMatrix();
          mesh.setMatrixAt(i, dummy.matrix);
        });
        mesh.instanceMatrix.needsUpdate = true;
        this.baseNodeMeshes.push(mesh);
        this.baseNodeGroup.add(mesh);
      });
      this.baseNodeMesh = this.baseNodeMeshes[0] || null;

      // Subtle dark border ring
      const bm = new THREE.InstancedMesh(this.nodeBorderGeometry, this.nodeBorderMaterial.clone(), this.nodeArray.length);
      bm.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
      this.nodeArray.forEach((n, i) => {
        dummy.position.set(n.x, n.y, NODE_Z + 0.05);
        dummy.scale.setScalar(Math.max(4, n.radius));
        dummy.updateMatrix();
        bm.setMatrixAt(i, dummy.matrix);
      });
      bm.instanceMatrix.needsUpdate = true;
      this.nodeBorderMesh = bm;
      this.baseNodeGroup.add(bm);

      // Special ring (high_value = gold, owned = green)
      const specNodes = this.nodeArray.filter(n => n.high_value || n.owned);
      if (specNodes.length) {
        const sm = new THREE.InstancedMesh(this.highlightNodeGeometry, this.highlightNodeMaterial.clone(), specNodes.length);
        sm.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
        specNodes.forEach((n, i) => {
          dummy.position.set(n.x, n.y, NODE_Z - 0.3);
          dummy.scale.setScalar(Math.max(4, n.radius * 1.08));
          dummy.updateMatrix();
          sm.setMatrixAt(i, dummy.matrix);
          color.set(n.owned ? '#00d084' : '#f4c95d');
          sm.setColorAt(i, color);
        });
        sm.instanceMatrix.needsUpdate = true;
        if (sm.instanceColor) sm.instanceColor.needsUpdate = true;
        this.specialNodeMesh  = sm;
        this.specialNodeArray = specNodes;
        this.baseNodeGroup.add(sm);
      }

      // Icon layer — BloodHound CE style icons inside each node circle
      this.buildNodeIconLayer();
    }

    buildNodeIconLayer() {
      this.nodeIconSprites = [];
      // Skip for very large graphs (performance)
      if (!this.nodeArray.length || this.nodeArray.length > 3000) return;

      this.nodeArray.forEach(node => {
        const te  = makeNodeIconTexture(node.type);
        const mat = new THREE.SpriteMaterial({
          map:         te.texture,
          transparent: true,
          depthTest:   false,
          depthWrite:  false,
          opacity:     0.72,
        });
        const sprite = new THREE.Sprite(mat);
        // Size: match the node circle diameter (radius * 2), slightly inset
        const sz = Math.max(4, node.radius) * 1.35;
        sprite.position.set(node.x, node.y, NODE_Z + 0.15);
        sprite.scale.set(sz, sz, 1);
        sprite.renderOrder = 15;
        sprite.userData.node = node;
        this.baseNodeGroup.add(sprite);
        this.nodeIconSprites.push(sprite);
      });
    }

    // ── Edge meshes ───────────────────────────────────────────────────────────

    buildEdgeMeshes() {
      const solid = [], dashed = [];
      this.edgeArray.forEach(e => {
        if (!e.source || !e.target) return;
        (e.relationship === 'MemberOf' || e.relationship === 'Contains'
          ? dashed : solid).push(e);
      });
      this.baseEdgeMeshes = [
        this._buildThickLineMesh(solid, 1.8),
        this._buildLineMesh(dashed, true, this.baseDashMaterial),
      ].filter(Boolean);
      this.baseEdgeMeshes.forEach(m => this.baseEdgeGroup.add(m));
    }

    _buildLineMesh(edges, dashed, material) {
      if (!edges.length) return null;
      const segs = curveSegsFor(edges.length, this.nodeArray.length);
      const pos  = new Float32Array(edges.length * segs * 2 * 3);
      const col  = new Float32Array(edges.length * segs * 2 * 3);
      const c    = new THREE.Color();
      edges.forEach((e, i) => {
        c.set(colorForEdge(e.relationship)).multiplyScalar(edgeLineIntensity(e.relationship));
        writeCurveSegs(e, pos, col, i, segs, c);
      });
      const geo = new THREE.BufferGeometry();
      geo.setAttribute('position', new THREE.Float32BufferAttribute(pos, 3));
      geo.setAttribute('color',    new THREE.Float32BufferAttribute(col, 3));
      geo.computeBoundingSphere();
      const mesh = new THREE.LineSegments(geo, material.clone());
      mesh.userData.edges = edges; mesh.userData.segments = segs;
      if (dashed) mesh.computeLineDistances();
      mesh.frustumCulled = false;
      return mesh;
    }

    _buildThickLineMesh(edges, baseWidth) {
      if (!edges.length) return null;
      const segs  = curveSegsFor(edges.length, this.nodeArray.length);
      const zoom  = this.camera.zoom;
      const ww    = baseWidth / Math.max(0.04, zoom);
      const vpe   = segs * 6;
      const pos   = new Float32Array(edges.length * vpe * 3);
      const col   = new Float32Array(edges.length * vpe * 3);
      const c     = new THREE.Color();
      let vi = 0, ci = 0;

      edges.forEach(e => {
        c.set(colorForEdge(e.relationship)).multiplyScalar(edgeLineIntensity(e.relationship));
        const w = ww * (importantEdge(e.relationship) ? 1.6 : 1.0);
        for (let s = 0; s < segs; s++) {
          const a = edgeCurvePoint(e, s / segs);
          const b = edgeCurvePoint(e, (s+1) / segs);
          const dx = b.x-a.x, dy = b.y-a.y;
          const len = Math.sqrt(dx*dx+dy*dy) || 1;
          const nx = -dy/len*w/2, ny = dx/len*w/2;
          const pts = [a.x-nx,a.y-ny,0, a.x+nx,a.y+ny,0, b.x+nx,b.y+ny,0,
                       a.x-nx,a.y-ny,0, b.x+nx,b.y+ny,0, b.x-nx,b.y-ny,0];
          for (let p = 0; p < 18; p+=3) {
            pos[vi+p]=pts[p]; pos[vi+p+1]=pts[p+1]; pos[vi+p+2]=pts[p+2];
            col[ci+p]=c.r; col[ci+p+1]=c.g; col[ci+p+2]=c.b;
            col[ci+p+3]=c.r; col[ci+p+4]=c.g; col[ci+p+5]=c.b;
          }
          vi+=18; ci+=18;
        }
      });

      const geo = new THREE.BufferGeometry();
      geo.setAttribute('position', new THREE.Float32BufferAttribute(pos, 3));
      geo.setAttribute('color',    new THREE.Float32BufferAttribute(col, 3));
      geo.computeBoundingSphere();
      const mat  = new THREE.MeshBasicMaterial({
        vertexColors: true, transparent: true, opacity: 0.88,
        depthWrite: false, side: THREE.DoubleSide,
      });
      const mesh = new THREE.Mesh(geo, mat);
      mesh.userData.edges     = edges;
      mesh.userData.segments  = segs;
      mesh.userData.baseWidth = baseWidth;
      mesh.userData.isThick   = true;
      mesh.frustumCulled      = false;
      return mesh;
    }

    buildArrowMesh(edges) {
      const ae = edges.filter(e => e.source && e.target);
      if (!ae.length) return null;
      const dummy = new THREE.Object3D();
      const grouped = new Map();
      ae.forEach(edge => {
        const key = edge.relationship || 'Unknown';
        if (!grouped.has(key)) grouped.set(key, []);
        grouped.get(key).push(edge);
      });
      const meshes = [];
      grouped.forEach((groupEdges, relationship) => {
        const material = this.arrowMaterial.clone();
        material.vertexColors = false;
        material.color.set(colorForEdge(relationship)).multiplyScalar(edgeLineIntensity(relationship));
        const mesh = new THREE.InstancedMesh(this.arrowGeometry, material, groupEdges.length);
        mesh.renderOrder = 2;
        mesh.userData.edges = groupEdges;
        groupEdges.forEach((e, i) => this._setArrowMatrix(mesh, dummy, e, i));
        mesh.instanceMatrix.needsUpdate = true;
        meshes.push(mesh);
      });
      this.baseArrowMeshes = meshes;
      this.baseArrowMesh = meshes[0] || null;
      return meshes;
    }

    _setArrowMatrix(mesh, dummy, edge, idx) {
      const dx   = edge.target.x - edge.source.x;
      const dy   = edge.target.y - edge.source.y;
      const dist = Math.sqrt(dx*dx + dy*dy);
      const trim = clamp((edge.target.radius + 10) / Math.max(1, dist), 0.06, 0.25);
      const t    = 1 - trim;
      if (dist < 5) {
        dummy.position.set(0, 0, -9999); dummy.scale.setScalar(0.001);
      } else {
        const tip = edgeCurvePoint(edge, t);
        dummy.position.set(tip.x, tip.y, NODE_Z + 0.5);
        dummy.rotation.z = edgeCurveAngle(edge, t);
        dummy.scale.setScalar(importantEdge(edge.relationship) ? 1.7 : 1.1);
      }
      dummy.updateMatrix();
      mesh.setMatrixAt(idx, dummy.matrix);
    }

    // ── Geometry update (zoom / drag) ─────────────────────────────────────────

    _updateThickMesh(mesh) {
      if (!mesh || !mesh.userData.isThick) return;
      const edges = mesh.userData.edges, segs = mesh.userData.segments;
      const bw    = mesh.userData.baseWidth || 1.8;
      const ww    = bw / Math.max(0.04, this.camera.zoom);
      const pos   = mesh.geometry.getAttribute('position');
      const col   = mesh.geometry.getAttribute('color');
      const c     = new THREE.Color();
      let vi = 0, ci = 0;
      edges.forEach(e => {
        c.set(colorForEdge(e.relationship)).multiplyScalar(edgeLineIntensity(e.relationship));
        const w = ww * (importantEdge(e.relationship) ? 1.6 : 1.0);
        for (let s = 0; s < segs; s++) {
          const a = edgeCurvePoint(e, s/segs), b = edgeCurvePoint(e, (s+1)/segs);
          const dx=b.x-a.x, dy=b.y-a.y, len=Math.sqrt(dx*dx+dy*dy)||1;
          const nx=-dy/len*w/2, ny=dx/len*w/2;
          const pts=[a.x-nx,a.y-ny,0, a.x+nx,a.y+ny,0, b.x+nx,b.y+ny,0,
                     a.x-nx,a.y-ny,0, b.x+nx,b.y+ny,0, b.x-nx,b.y-ny,0];
          for (let p=0;p<18;p+=3){
            pos.array[vi+p]=pts[p]; pos.array[vi+p+1]=pts[p+1]; pos.array[vi+p+2]=pts[p+2];
            col.array[ci+p]=c.r; col.array[ci+p+1]=c.g; col.array[ci+p+2]=c.b;
            col.array[ci+p+3]=c.r; col.array[ci+p+4]=c.g; col.array[ci+p+5]=c.b;
          }
          vi+=18; ci+=18;
        }
      });
      pos.needsUpdate = true; col.needsUpdate = true;
      mesh.geometry.computeBoundingSphere();
    }

    _updateLineMesh(mesh) {
      if (!mesh || !mesh.userData.edges) return;
      const edges = mesh.userData.edges;
      const segs  = mesh.userData.segments || curveSegsFor(edges.length, this.nodeArray.length);
      const pos   = mesh.geometry.getAttribute('position');
      const col   = mesh.geometry.getAttribute('color');
      const c     = new THREE.Color();
      edges.forEach((e, i) => {
        c.set(colorForEdge(e.relationship)).multiplyScalar(edgeLineIntensity(e.relationship));
        writeCurveSegs(e, pos.array, col.array, i, segs, c);
      });
      pos.needsUpdate = true; col.needsUpdate = true;
      mesh.geometry.computeBoundingSphere();
      if (mesh.isLineSegments && mesh.material?.isLineDashedMaterial) mesh.computeLineDistances();
    }

    _updateEdgeGeometries() {
      this.baseEdgeMeshes.forEach(m => m.userData.isThick ? this._updateThickMesh(m) : this._updateLineMesh(m));
    }

    _updateArrowMesh(mesh = this.baseArrowMesh) {
      const dummy = new THREE.Object3D();
      const meshes = this.baseArrowMeshes.length ? this.baseArrowMeshes : (mesh ? [mesh] : []);
      meshes.forEach(currentMesh => {
        if (!currentMesh?.userData.edges) return;
        currentMesh.userData.edges.forEach((e, i) => this._setArrowMatrix(currentMesh, dummy, e, i));
        currentMesh.instanceMatrix.needsUpdate = true;
      });
    }

    _updateNodeMeshMatrices() {
      const dummy = new THREE.Object3D();
      const writeCircles = (mesh, arr, z, scaleMulti = 1) => {
        if (!mesh || !arr) return;
        arr.forEach((n, i) => {
          dummy.position.set(n.x, n.y, z);
          dummy.rotation.set(0, 0, 0);
          dummy.scale.setScalar(Math.max(4, n.radius * scaleMulti));
          dummy.updateMatrix();
          mesh.setMatrixAt(i, dummy.matrix);
        });
        mesh.instanceMatrix.needsUpdate = true;
      };
      if (this.baseNodeMeshes.length) {
        this.baseNodeMeshes.forEach(mesh => writeCircles(mesh, mesh.userData.nodes || [], NODE_Z, 1));
      } else {
        writeCircles(this.baseNodeMesh,   this.nodeArray,      NODE_Z,      1);
      }
      writeCircles(this.nodeBorderMesh, this.nodeArray,      NODE_Z+0.05, 1);
      writeCircles(this.glowNodeMesh,   this.glowNodeArray,  GLOW_Z,      2.2);
      writeCircles(this.specialNodeMesh,this.specialNodeArray,NODE_Z-0.3, 1.35);

      // Update icon sprite positions when nodes are dragged
      if (this.nodeIconSprites.length) {
        this.nodeIconSprites.forEach(sprite => {
          const n = sprite.userData.node;
          if (n) sprite.position.set(n.x, n.y, NODE_Z + 0.15);
        });
      }
    }

    _updateGraphGeometry({ liveLabels = false } = {}) {
      this._updateNodeMeshMatrices();
      this._updateEdgeGeometries();
      this._updateArrowMesh();
      this.rebuildHighlightOverlay();
      if (liveLabels && this.nodeArray.length <= MAX_LIVE_DRAG_NODES) this.refreshLabels();
      this.render();
    }

    // ── Camera / zoom ─────────────────────────────────────────────────────────

    fitToGraph() {
      if (!this.nodeArray.length) return;
      const xs = this.nodeArray.map(n => n.x || 0);
      const ys = this.nodeArray.map(n => n.y || 0);
      const minX = Math.min(...xs), maxX = Math.max(...xs);
      const minY = Math.min(...ys), maxY = Math.max(...ys);
      const gw = Math.max(1, maxX - minX), gh = Math.max(1, maxY - minY);
      const fill = this.nodeArray.length > 5000 ? 0.90 : this.nodeArray.length > 2000 ? 0.93 : 0.96;
      const minZ = 0.06, maxZ = this.nodeArray.length <= 50 ? 2.6 : 2.0;
      const scale = clamp(fill / Math.max(gw / this.width, gh / this.height), minZ, maxZ);
      this.camera.zoom       = scale;
      this.camera.position.x = (minX + maxX) / 2 - this.width  / (2 * scale);
      this.camera.position.y = (minY + maxY) / 2 - this.height / (2 * scale);
      this.camera.updateProjectionMatrix();
      updateTransform(this.camera);
      this._updateEdgeGeometries();
      this._updateArrowMesh();
      this.refreshLabels();
      this.render();
    }

    zoomBy(factor, focusX, focusY) {
      const rect = this.canvas.getBoundingClientRect();
      const cx = focusX ?? rect.left + rect.width  / 2;
      const cy = focusY ?? rect.top  + rect.height / 2;
      const before = this.screenToWorld(cx, cy);
      this.camera.zoom = clamp(this.camera.zoom * factor, 0.04, 14);
      this.camera.updateProjectionMatrix();
      const after = this.screenToWorld(cx, cy);
      this.camera.position.x += before.x - after.x;
      this.camera.position.y += before.y - after.y;
      this.camera.updateProjectionMatrix();
      updateTransform(this.camera);
      this._updateEdgeGeometries();
      this._updateArrowMesh();
      this.refreshLabels();
      this.render();
    }

    zoomToNode(node) {
      if (!node) return;
      const z = clamp(Math.max(this.camera.zoom, this.nodeArray.length > 2000 ? 1.4 : 1.8), 0.08, 14);
      this.camera.zoom       = z;
      this.camera.position.x = node.x - this.width  / (2 * z);
      this.camera.position.y = node.y - this.height / (2 * z);
      this.camera.updateProjectionMatrix();
      updateTransform(this.camera);
      this._updateEdgeGeometries();
      this._updateArrowMesh();
      this.refreshLabels();
      this.render();
    }

    // ── Highlight / selection overlay ─────────────────────────────────────────

    rebuildHighlightOverlay() {
      clearObject(this.overlayEdgeGroup);
      this.overlayEdgeGroup.add(new THREE.Group());
      if (this.overlayNodeLayer) {
        this.overlayNodeGroup.remove(this.overlayNodeLayer);
        clearObject(this.overlayNodeLayer);
        this.overlayNodeLayer = null;
      }
      const onl = new THREE.Group();
      if (this.selectionRing.parent !== this.overlayNodeGroup) this.overlayNodeGroup.add(this.selectionRing);
      if (this.hoverRing.parent     !== this.overlayNodeGroup) this.overlayNodeGroup.add(this.hoverRing);
      this.overlayNodeGroup.add(onl);
      this.overlayNodeLayer = onl;

      const hasEdges = this.connectedEdgeSet.size > 0 || this.pathEdgeSet.size > 0;
      const hasNodes = this.connectedNodeSet.size > 0 || this.pathNodeSet.size > 0;

      // Dim non-highlighted edges
      this.baseEdgeMeshes.forEach(m => {
        if (m.material) m.material.opacity = hasEdges ? 0.18 : 0.85;
      });

      // Keep the base node fill colors visible; use rings/labels for emphasis.
      this.baseNodeMeshes.forEach(mesh => {
        if (mesh.material) mesh.material.opacity = 1;
      });

      // Highlight rings for connected nodes
      const ringIds  = new Set([...this.connectedNodeSet, ...this.pathNodeSet, ...this.selectedNodeIds]);
      if (this.selectedNodeId)  ringIds.add(this.selectedNodeId);
      if (this.hoveredNodeId && !this.selectedNodeId && !this.selectedNodeIds.size)
        ringIds.add(this.hoveredNodeId);

      const ringNodes = [...ringIds].map(id => this.nodeById.get(id)).filter(Boolean)
        .slice(0, MAX_HIGHLIGHT_NODES);

      if (ringNodes.length) {
        const rm    = new THREE.InstancedMesh(this.highlightNodeGeometry, this.highlightNodeMaterial.clone(), ringNodes.length);
        rm.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
        const dummy = new THREE.Object3D(); const c = new THREE.Color();
        ringNodes.forEach((n, i) => {
          dummy.position.set(n.x, n.y, OVERLAY_Z);
          dummy.scale.setScalar(Math.max(4, n.radius * 1.55));
          dummy.updateMatrix(); rm.setMatrixAt(i, dummy.matrix);
          if (this.selectedNodeIds.has(n.id) || n.id === this.selectedNodeId) c.set('#ffffff');
          else if (this.pathNodeSet.has(n.id)) c.set('#60a5fa');
          else c.set(colorForNode(n));
          rm.setColorAt(i, c);
        });
        rm.instanceMatrix.needsUpdate = true;
        if (rm.instanceColor) rm.instanceColor.needsUpdate = true;
        onl.add(rm);
      }

      // Highlight edges
      const hEdges = [...this.connectedEdgeSet, ...this.pathEdgeSet]
        .map(k => this.edgeByKey.get(k)).filter(Boolean).slice(0, MAX_HIGHLIGHT_EDGES);
      if (hEdges.length) {
        const segs = curveSegsFor(hEdges.length, this.nodeArray.length);
        const pos  = new Float32Array(hEdges.length * segs * 2 * 3);
        const col  = new Float32Array(hEdges.length * segs * 2 * 3);
        const c    = new THREE.Color();
        hEdges.forEach((e, i) => {
          c.set(this.pathEdgeSet.has(e.key) ? '#60a5fa' : '#ffffff');
          writeCurveSegs(e, pos, col, i, segs, c);
        });
        const geo = new THREE.BufferGeometry();
        geo.setAttribute('position', new THREE.Float32BufferAttribute(pos, 3));
        geo.setAttribute('color',    new THREE.Float32BufferAttribute(col, 3));
        const lm = new THREE.LineSegments(geo, this.highlightLineMaterial.clone());
        lm.frustumCulled = false;
        this.overlayEdgeGroup.add(lm);
        this.highlightEdgeMeshes = [lm];
      } else { this.highlightEdgeMeshes = []; }

      // Selection / hover rings
      if (this.selectedNodeId) {
        const n = this.nodeById.get(this.selectedNodeId);
        if (n) {
          this.selectionRing.visible = true;
          this.selectionRing.position.set(n.x, n.y, OVERLAY_Z);
          this.selectionRing.scale.setScalar(Math.max(4, n.radius * 1.6));
        }
      } else { this.selectionRing.visible = false; }

      if (this.hoveredNodeId && !this.selectedNodeId && !this.selectedNodeIds.size) {
        const n = this.nodeById.get(this.hoveredNodeId);
        if (n) {
          this.hoverRing.visible = true;
          this.hoverRing.position.set(n.x, n.y, OVERLAY_Z);
          this.hoverRing.scale.setScalar(Math.max(4, n.radius * 1.45));
        }
      } else { this.hoverRing.visible = false; }
    }

    // ── Selection API ─────────────────────────────────────────────────────────

    selectNode(node) { if (node) this.selectNodes([node], 'replace'); }

    selectNodes(nodes, mode = 'replace') {
      const picked = (nodes || []).filter(Boolean);
      if (mode === 'replace') this.selectedNodeIds.clear();
      picked.forEach(n => {
        if (mode === 'toggle' && this.selectedNodeIds.has(n.id)) this.selectedNodeIds.delete(n.id);
        else this.selectedNodeIds.add(n.id);
      });
      const ids = [...this.selectedNodeIds];
      this.selectedNodeId = ids.length ? ids[ids.length - 1] : null;
      const cNodes = new Set(ids), cEdges = new Set();
      this.edgeArray.forEach(e => {
        if (this.selectedNodeIds.has(e.source.id) || this.selectedNodeIds.has(e.target.id)) {
          cNodes.add(e.source.id); cNodes.add(e.target.id); cEdges.add(e.key);
        }
      });
      this.connectedNodeSet = cNodes; this.connectedEdgeSet = cEdges;
      this.hoveredNodeId = null;
      this.rebuildHighlightOverlay(); this.refreshLabels(); this.render();
    }

    clearSelection() {
      this.selectedNodeId = null; this.selectedNodeIds.clear();
      this.connectedNodeSet.clear(); this.connectedEdgeSet.clear();
      this.hoveredNodeId = null;
      this.rebuildHighlightOverlay(); this.refreshLabels(); this.render();
    }

    highlightPath(hops) {
      const pn = new Set(), pe = new Set();
      hops.forEach(h => {
        pn.add(h.source_id); pn.add(h.target_id);
        pe.add(edgeKey(h.source_id, h.target_id, h.relationship));
      });
      this.pathNodeSet = pn; this.pathEdgeSet = pe;
      this.connectedNodeSet = new Set(pn); this.connectedEdgeSet = new Set(pe);
      this.selectedNodeId = null; this.selectedNodeIds.clear(); this.hoveredNodeId = null;
      this.rebuildHighlightOverlay(); this.refreshLabels(); this.render();
    }

    setHighlightSet(nodeIds, edgeKeys, mode = 'selection') {
      this.connectedNodeSet = new Set(nodeIds || []);
      this.connectedEdgeSet = new Set(edgeKeys || []);
      this.highlightMode = mode;
      this.rebuildHighlightOverlay(); this.refreshLabels(); this.render();
    }

    clearHighlightSet() {
      this.connectedNodeSet.clear(); this.connectedEdgeSet.clear();
      this.pathNodeSet.clear(); this.pathEdgeSet.clear();
      this.highlightMode = null;
      this.rebuildHighlightOverlay(); this.refreshLabels(); this.render();
    }

    // ── Labels ────────────────────────────────────────────────────────────────

    refreshLabels() {
      clearObject(this.labelGroup);
      this.labelSprites = []; this.edgeLabelSprites = [];
      if (!this.nodeArray.length) return;

      const zoom = this.camera.zoom;
      const placedLabelBoxes = [];

      const boxesOverlap = (a, b) =>
        !(a.left > b.right || a.right < b.left || a.top < b.bottom || a.bottom > b.top);

      const placeLabelY = (x, startY, width, height, direction = 1, maxAttempts = 4) => {
        const halfW = width / 2;
        const halfH = height / 2;
        const step = height * 0.9 + 10 / zoom;
        let currentY = startY;
        let finalBox = null;

        for (let attempt = 0; attempt < maxAttempts; attempt++) {
          finalBox = {
            left: x - halfW,
            right: x + halfW,
            top: currentY + halfH,
            bottom: currentY - halfH,
          };
          if (!placedLabelBoxes.some(box => boxesOverlap(box, finalBox))) {
            placedLabelBoxes.push(finalBox);
            return currentY;
          }
          currentY += step * direction;
        }

        if (finalBox) placedLabelBoxes.push(finalBox);
        return currentY;
      };

      // ── Node labels ──────────────────────────────────────────────────────────
      let labelNodes = this.nodeArray.filter(n =>
        shouldShowLabel(n, zoom) ||
        n.id === this.selectedNodeId ||
        n.id === this.hoveredNodeId  ||
        this.connectedNodeSet.has(n.id) ||
        this.pathNodeSet.has(n.id)
      );

      if (labelNodes.length > MAX_LABELS) {
        const imp    = labelNodes.filter(n => n.high_value || n.owned || n.type === 'Domain');
        const ranked = [...labelNodes].sort((a, b) => (b.degree||0) - (a.degree||0));
        const merged = new Map();
        [...imp, ...ranked].forEach(n => merged.set(n.id, n));
        labelNodes = [...merged.values()].slice(0, MAX_LABELS);
      }

      labelNodes.forEach(node => {
        const text  = nodeDisplayName(node);
        const isDom = node.type === 'Domain';
        const isHV  = node.high_value || node.owned;

        const te = makeSpriteTexture(text, {
          fontSize:    isDom ? 13 : isHV ? 12 : 11,
          color:       isDom ? '#67e8f9' : isHV ? '#fde68a' : LABEL_TEXT,
          background:  LABEL_BG,
          border:      isDom ? 'rgba(103,232,249,0.45)' : isHV ? 'rgba(253,230,138,0.4)' : LABEL_BORDER,
          strokeWidth: 2,
          strokeColor: 'rgba(0,0,0,0.85)',
          weight:      isHV || isDom ? '600' : '500',
          paddingX:    10,
          paddingY:    5,
        });

        // Use PlaneGeometry (not Sprite) — more reliable with inverted-Y orthographic camera
        const geo  = new THREE.PlaneGeometry(te.width, te.height);
        const mat  = new THREE.MeshBasicMaterial({
          map:         te.texture,
          transparent: true,
          depthTest:   false,
          depthWrite:  false,
          side:        THREE.DoubleSide,
        });
        const label = new THREE.Mesh(geo, mat);
        label.userData.textureEntry = te;
        label.renderOrder = 9999;

        const gap  = (isDom ? 18 : 14) / zoom;
        const yOff = (node.radius + gap + te.height / (2 * zoom));
        const labelX = node.x;
        const labelY = placeLabelY(labelX, node.y + yOff, te.width / zoom, te.height / zoom, 1);
        label.position.set(labelX, labelY, LABEL_Z);
        label.scale.set(1 / zoom, 1 / zoom, 1);
        this.labelGroup.add(label);
        this.labelSprites.push(label);
      });

      // ── Edge relationship labels — always show all edges ──────────────────
      // Show all edges when zoom is reasonable; for very zoomed out graphs cap it
      const showAllEdgeLabels = zoom > 0.06;
      const edgeLabelKeys = new Set();
      const edgesToLabel = (showAllEdgeLabels
        ? this.edgeArray
        : this.edgeArray.filter(e =>
            this.connectedEdgeSet.has(e.key) ||
            this.pathEdgeSet.has(e.key) ||
            importantEdge(e.relationship)
          ))
        .filter(e => {
          if (edgeLabelKeys.has(e.key)) return false;
          edgeLabelKeys.add(e.key);
          return true;
        });

      edgesToLabel.slice(0, MAX_EDGE_LABELS).forEach(e => {
        const isCrit = importantEdge(e.relationship);
        const isConn = this.connectedEdgeSet.has(e.key) || this.pathEdgeSet.has(e.key);
        const edgeColor = colorForEdge(e.relationship);

        const te = makeSpriteTexture(e.relationship, {
          fontSize:    10,
          color:       isCrit ? '#fca5a5' : isConn ? '#93c5fd' : EDGE_LABEL_TXT,
          background:  isCrit ? 'rgba(30,0,0,0.88)' : EDGE_LABEL_BG,
          border:      isCrit ? `rgba(239,68,68,0.55)` : isConn ? 'rgba(96,165,250,0.4)' : LABEL_BORDER,
          strokeWidth: 1.5,
          strokeColor: 'rgba(0,0,0,0.8)',
          weight:      isCrit ? '700' : '500',
          paddingX:    8,
          paddingY:    4,
          borderRadius: 4,
        });

        const geo = new THREE.PlaneGeometry(te.width, te.height);
        const mat = new THREE.MeshBasicMaterial({
          map:         te.texture,
          transparent: true,
          depthTest:   false,
          depthWrite:  false,
          side:        THREE.DoubleSide,
        });
        const el = new THREE.Mesh(geo, mat);
        el.userData.textureEntry = te;
        el.renderOrder = 9999;

        const mid = edgeCurvePoint(e, 0.5);
        // Place label slightly offset from edge midpoint (to not sit on the line)
        const offY = -20 / zoom;
        const edgeY = placeLabelY(mid.x, mid.y + offY, te.width / zoom, te.height / zoom, -1);
        el.position.set(mid.x, edgeY, LABEL_Z);
        el.scale.set(1 / zoom, 1 / zoom, 1);
        this.labelGroup.add(el);
        this.edgeLabelSprites.push(el);
      });
    }

    // ── Hover / hit-test ──────────────────────────────────────────────────────

    hitTest(cx, cy) {
      if (!this.baseNodeMeshes.length) return null;
      const rect = this.canvas.getBoundingClientRect();
      const x = ((cx - rect.left) / rect.width)  * 2 - 1;
      const y = -(((cy - rect.top)  / rect.height) * 2 - 1);
      this.pointer.set(x, y);
      this.raycaster.setFromCamera(this.pointer, this.camera);
      const hits = this.raycaster.intersectObjects(this.baseNodeMeshes, false);
      if (!hits.length || hits[0].instanceId == null) return null;
      const mesh = hits[0].object;
      const nodes = mesh?.userData?.nodes || this.nodeArray;
      return nodes[hits[0].instanceId] || null;
    }

    updateHover(nodeId, event) {
      if (nodeId === this.lastHoverNodeId) {
        if (nodeId) {
          const n = this.nodeById.get(nodeId);
          if (n) { this.canvas.style.cursor = 'pointer'; _showTooltip(event, n); }
        }
        return;
      }
      this.lastHoverNodeId = nodeId;
      this.hoveredNodeId   = nodeId;
      if (!this.selectedNodeId) this.rebuildHighlightOverlay();

      if (nodeId) {
        const n = this.nodeById.get(nodeId);
        if (n) {
          this.canvas.style.cursor = 'pointer';
          _showTooltip(event, n);
          if (!this.selectedNodeId) {
            this.hoverRing.visible = true;
            this.hoverRing.position.set(n.x, n.y, OVERLAY_Z);
            this.hoverRing.scale.setScalar(Math.max(4, n.radius * 1.45));
          }
        }
      } else {
        this.canvas.style.cursor = this.dragState ? 'grabbing' : 'grab';
        _hideTooltip();
        this.hoverRing.visible = false;
      }
      this.render();
    }

    screenToWorld(cx, cy) {
      const rect = this.canvas.getBoundingClientRect();
      const v = new THREE.Vector3(
        ((cx - rect.left) / rect.width)  * 2 - 1,
        -(((cy - rect.top) / rect.height) * 2 - 1),
        0
      );
      v.unproject(this.camera);
      return { x: v.x, y: v.y };
    }

    nodeScreenPosition(node) {
      const rect = this.canvas.getBoundingClientRect();
      return {
        x: rect.left + (node.x - this.camera.position.x) * this.camera.zoom,
        y: rect.top  + (node.y - this.camera.position.y) * this.camera.zoom,
      };
    }

    nodesInClientRect(l, t, r, b) {
      const minX=Math.min(l,r), maxX=Math.max(l,r);
      const minY=Math.min(t,b), maxY=Math.max(t,b);
      return this.nodeArray.filter(n => {
        const p = this.nodeScreenPosition(n);
        return p.x >= minX && p.x <= maxX && p.y >= minY && p.y <= maxY;
      });
    }

    // ── Marquee selection box ─────────────────────────────────────────────────

    _updateSelectionBox(cx, cy) {
      if (!this.marqueeState || !this.selectionBox) return;
      const rect = this.container.getBoundingClientRect();
      const x1=this.marqueeState.startX-rect.left, y1=this.marqueeState.startY-rect.top;
      const x2=cx-rect.left, y2=cy-rect.top;
      Object.assign(this.selectionBox.style, {
        display: 'block',
        left:    `${Math.min(x1,x2)}px`,
        top:     `${Math.min(y1,y2)}px`,
        width:   `${Math.abs(x2-x1)}px`,
        height:  `${Math.abs(y2-y1)}px`,
      });
    }

    _hideSelectionBox() {
      if (this.selectionBox) {
        Object.assign(this.selectionBox.style, { display:'none', width:'0px', height:'0px' });
      }
    }

    // ── Pointer events ────────────────────────────────────────────────────────

    onPointerDown(event) {
      if (event.button !== 0) return;
      const hit = this.hitTest(event.clientX, event.clientY);

      if ((event.shiftKey || event.ctrlKey || event.metaKey) && !hit) {
        this.marqueeState = {
          startX: event.clientX, startY: event.clientY,
          additive: true, toggle: event.ctrlKey || event.metaKey,
        };
        this.lastPointer = { x: event.clientX, y: event.clientY };
        this.canvas.setPointerCapture(event.pointerId);
        this.canvas.style.cursor = 'crosshair';
        this._updateSelectionBox(event.clientX, event.clientY);
        return;
      }

      if (hit) {
        const selIds   = this.selectedNodeIds.has(hit.id) ? [...this.selectedNodeIds] : [hit.id];
        const dragNodes = selIds.map(id => this.nodeById.get(id)).filter(Boolean);
        this.nodeDragState = {
          startX: event.clientX, startY: event.clientY,
          lastX: event.clientX, lastY: event.clientY,
          hit, nodes: dragNodes.length ? dragNodes : [hit],
          dragging: false,
          additive: event.shiftKey, toggle: event.ctrlKey || event.metaKey,
        };
        this.lastPointer = { x: event.clientX, y: event.clientY };
        this.canvas.setPointerCapture(event.pointerId);
        return;
      }

      this.dragState = {
        startX: event.clientX, startY: event.clientY,
        cameraX: this.camera.position.x, cameraY: this.camera.position.y,
        dragging: false,
      };
      this.lastPointer = { x: event.clientX, y: event.clientY };
      this.canvas.setPointerCapture(event.pointerId);
      this.canvas.style.cursor = 'grabbing';
    }

    onPointerMove(event) {
      this.lastPointer = { x: event.clientX, y: event.clientY };

      if (this.marqueeState) {
        this._updateSelectionBox(event.clientX, event.clientY);
        return;
      }

      if (this.nodeDragState) {
        const s  = this.nodeDragState;
        const dx = event.clientX - s.lastX;
        const dy = event.clientY - s.lastY;
        const td = Math.abs(event.clientX-s.startX)+Math.abs(event.clientY-s.startY);
        if (td > 4) s.dragging = true;
        if (s.dragging) {
          const wdx = dx / this.camera.zoom;
          const wdy = dy / this.camera.zoom;
          s.nodes.forEach(n => { n.x += wdx; n.y += wdy; });
          s.lastX = event.clientX; s.lastY = event.clientY;
          this._updateGraphGeometry({ liveLabels: true });
        }
        return;
      }

      if (this.dragState) {
        const s = this.dragState;
        const dx = event.clientX - s.startX;
        const dy = event.clientY - s.startY;
        if (Math.abs(dx)+Math.abs(dy) > 4) s.dragging = true;
        if (s.dragging) {
          this.camera.position.x = s.cameraX - dx / this.camera.zoom;
          this.camera.position.y = s.cameraY - dy / this.camera.zoom;
          this.camera.updateProjectionMatrix();
          updateTransform(this.camera);
          this.render();
        }
        return;
      }

      const hit = this.hitTest(event.clientX, event.clientY);
      this.updateHover(hit ? hit.id : null, event);
    }

    onPointerUp(event) {
      if (this.canvas.hasPointerCapture(event.pointerId))
        this.canvas.releasePointerCapture(event.pointerId);

      if (this.marqueeState) {
        const state = this.marqueeState;
        this.marqueeState = null;
        this._hideSelectionBox();
        this.canvas.style.cursor = 'grab';
        const picked = this.nodesInClientRect(
          state.startX, state.startY, event.clientX, event.clientY);
        if (picked.length && typeof window.selectNodes === 'function')
          window.selectNodes(picked, state.toggle ? 'toggle' : 'add');
        return;
      }

      if (this.nodeDragState) {
        const state = this.nodeDragState;
        this.nodeDragState = null;
        this.canvas.style.cursor = 'grab';
        if (state.dragging) { this.refreshLabels(); this.render(); return; }
        const hit = state.hit || this.hitTest(event.clientX, event.clientY);
        if (hit) {
          if ((event.ctrlKey || event.metaKey || event.shiftKey) && typeof window.toggleNodeSelection === 'function')
            window.toggleNodeSelection(hit, event.shiftKey ? 'add' : 'toggle');
          else if (typeof window.selectNode === 'function')
            window.selectNode(hit);
        }
        return;
      }

      if (this.dragState?.dragging) {
        this.dragState = null; this.canvas.style.cursor = 'grab'; return;
      }

      const hit = this.hitTest(event.clientX, event.clientY);
      this.dragState = null; this.canvas.style.cursor = 'grab';
      if (hit) {
        if ((event.ctrlKey || event.metaKey || event.shiftKey) && typeof window.toggleNodeSelection === 'function')
          window.toggleNodeSelection(hit, event.shiftKey ? 'add' : 'toggle');
        else if (typeof window.selectNode === 'function')
          window.selectNode(hit);
      } else if (typeof window.deselectAll === 'function') {
        window.deselectAll();
      }
    }

    onPointerLeave() {
      this.dragState = null; this.nodeDragState = null; this.marqueeState = null;
      this._hideSelectionBox();
      this.hoveredNodeId = null; this.lastHoverNodeId = null;
      this.hoverRing.visible = false;
      _hideTooltip();
      this.canvas.style.cursor = 'grab';
      this.render();
    }

    onWheel(event) {
      event.preventDefault();
      const factor = event.deltaY > 0 ? 0.88 : 1.14;
      this.zoomBy(factor, event.clientX, event.clientY);
    }

    render() {
      this.renderer.render(this.scene, this.camera);
      updateTransform(this.camera);
      this.pendingRender = false;
    }
  }

  // ============================================================================
  // TOOLTIP HELPERS — thin wrappers so the renderer doesn't need to know the UI
  // ============================================================================

  function _showTooltip(event, node) {
    if (typeof showTooltip === 'function') {
      showTooltip({
        pageX: event.pageX, pageY: event.pageY,
        clientX: event.clientX, clientY: event.clientY,
      }, node);
    }
  }
  function _hideTooltip() {
    if (typeof hideTooltip === 'function') hideTooltip();
  }

  // ============================================================================
  // GLOBAL API
  // ============================================================================

  function ensureRenderer() {
    if (!graphRenderer) {
      const canvas = document.getElementById('graph-canvas');
      graphRenderer = new ThreeGraphRenderer(canvas);
      window._threeGraphRenderer = graphRenderer;
      window.graphRenderer = graphRenderer;
    }
    return graphRenderer;
  }

  function installControls() {
    if (controlsInstalled) return;
    controlsInstalled = true;

    const $  = id => document.getElementById(id);
    const on = (id, ev, fn) => { const el = $(id); if (el) el.addEventListener(ev, fn); };

    on('zoom-in',  'click', zoomIn);
    on('zoom-out', 'click', zoomOut);
    on('zoom-fit', 'click', fitGraph);
    on('render-button', 'click', () => typeof renderSelectedChunk === 'function' && renderSelectedChunk());
    on('path-button',   'click', () => typeof findAttackPath     === 'function' && findAttackPath());

    if ($('upload-btn')) {
      on('upload-btn', 'click', () => $('json-upload').click());
      on('json-upload', 'change', async event => {
        const file = event.target.files[0];
        if (!file) return;
        if (file.type !== 'application/json' && !file.name.endsWith('.json')) {
          alert('Only JSON files are allowed'); return;
        }
        $('graph-badge') && ($('graph-badge').textContent = 'Uploading…');
        try {
          const resp = await fetch('/api/upload', { method: 'POST', body: file });
          if (!resp.ok) throw new Error(await resp.text());
          const g = await resp.json();
          if (typeof loadGraphList === 'function') await loadGraphList();
          $('graph-select').value = g.id;
          if (typeof loadGraph === 'function') loadGraph(g.id);
        } catch (e) {
          alert('Upload failed: ' + e.message);
          $('graph-badge') && ($('graph-badge').textContent = 'Upload failed');
        }
        event.target.value = '';
      });
    }

    if ($('path-from')) {
      const submit = e => { if (e.key === 'Enter' && typeof findAttackPath === 'function') findAttackPath(); };
      on('path-from', 'keydown', submit);
      on('path-to',   'keydown', submit);
    }

    if (typeof window.installQueryPanelControls === 'function')
      window.installQueryPanelControls();

    on('render-select', 'change', () => {
      if (typeof renderLimit !== 'undefined') {
        renderLimit = typeof currentRenderLimit === 'function' ? currentRenderLimit() : renderLimit;
        renderOffset = 0;
        typeof updateRenderLimitControls === 'function' && updateRenderLimitControls();
        typeof updateChunkControls       === 'function' && updateChunkControls(graphData);
      }
    });

    on('render-custom', 'input', () => {
      if (typeof renderLimit !== 'undefined') {
        renderLimit  = typeof currentRenderLimit === 'function' ? currentRenderLimit() : renderLimit;
        renderOffset = 0;
        typeof updateChunkControls === 'function' && updateChunkControls(graphData);
      }
    });

    on('prev-chunk', 'click', () => typeof cycleChunk === 'function' && cycleChunk(-1));
    on('next-chunk', 'click', () => typeof cycleChunk === 'function' && cycleChunk(1));

    document.querySelectorAll('#type-filters input').forEach(inp => {
      inp.addEventListener('change', () => {
        if (typeof hideSearchResults === 'function') hideSearchResults();
        if (typeof renderOffset !== 'undefined') renderOffset = 0;
        if (typeof updateChunkControls === 'function') updateChunkControls(graphData);
        if (currentGraphId && graphData?.nodes?.length) {
          if (typeof currentRenderLimit === 'function' && currentRenderLimit() === 'all') {
            const rb = document.getElementById('render-badge');
            if (rb) rb.textContent = 'ALL selected; press Render to confirm';
            return;
          }
          if (typeof renderSelectedChunk === 'function') renderSelectedChunk({ warnAll: false });
        }
      });
    });

    document.addEventListener('keydown', event => {
      if (event.key === 'F3') {
        event.preventDefault();
        if (typeof perfHudVisible !== 'undefined') {
          perfHudVisible = !perfHudVisible;
          const hud = document.getElementById('perf-hud');
          if (hud) hud.classList.toggle('active', perfHudVisible);
          if (typeof updatePerfHud === 'function') updatePerfHud(graphData);
        }
      }
      if (event.key === 'Escape') {
        if (typeof hideSearchResults === 'function') hideSearchResults();
        deselectAll();
      }
    });

    on('sidebar-close',  'click', () => document.getElementById('app')?.classList.add('sidebar-collapsed'));
    on('sidebar-toggle', 'click', () => document.getElementById('app')?.classList.remove('sidebar-collapsed'));
  }

  // ── Public surface ──────────────────────────────────────────────────────────

  function renderGraph(data) {
    const t0 = performance.now();
    const renderer  = ensureRenderer();
    const container = document.getElementById('graph-container');
    const width     = Math.max(640, container.clientWidth);
    const height    = Math.max(480, container.clientHeight);
    const nodeCount = data.nodes.length;
    const nodesMap  = {};

    if (!nodeCount) {
      if (typeof setEmptyMessage === 'function')
        setEmptyMessage('No nodes rendered', 'No nodes matched the current filter or chunk selection.');
      document.getElementById('empty-state')?.classList.remove('hidden');
      renderer.clearGraph();
      return;
    }
    document.getElementById('empty-state')?.classList.add('hidden');

    const nodes = data.nodes.map(raw => {
      const node = { ...raw, display: nodeDisplayName(raw), degree: 0, radius: nodeRadius(raw, nodeCount) };
      nodesMap[node.id] = node;
      return node;
    });

    const links = data.edges
      .filter(e => nodesMap[e.source] && nodesMap[e.target])
      .map(e => {
        const src = nodesMap[e.source], tgt = nodesMap[e.target];
        src.degree++; tgt.degree++;
        return {
          source: src, target: tgt,
          relationship: e.relationship, cost: e.cost, severity: e.severity,
          guidance: e.guidance, ovt_command: e.ovt_command,
          ovt_command_desc: e.ovt_command_desc,
          ace_details: e.ace_details,
          key: edgeKey(e.source, e.target, e.relationship),
        };
      });

    if (typeof computeHierarchicalLayout === 'function') {
      computeHierarchicalLayout(nodes, links, width, height, data.hops || []);
    } else if (typeof d3 !== 'undefined') {
      const sim = d3.forceSimulation(nodes)
        .force('link',   d3.forceLink(links).id(d => d.id).distance(80))
        .force('charge', d3.forceManyBody().strength(-400))
        .force('x',      d3.forceX(width  / 2).strength(0.03))
        .force('y',      d3.forceY(height / 2).strength(0.08));
      for (let i = 0; i < 300; i++) sim.tick();
    }

    const nodeSpread = nodes.length > 300 ? { x: 25.0, y: 1.08 }
      : { x: 3.5, y: 1.10 };
    spreadGraphNodes(nodes, nodeSpread.x, nodeSpread.y);

    window._nodesMap = nodesMap;
    graphData = data;
    renderer.setGraphData({ nodes, edges: links, width, height, graphData: data });
    fitGraph();

    data.render_time_ms = data.client_render_ms = Math.max(0, Math.round(performance.now() - t0));
    if (typeof updateRenderBadge  === 'function') updateRenderBadge(data);
    if (typeof updateChunkControls === 'function') updateChunkControls(data);
  }

  function teardownGraph() {
    selectedNode = null;
    if (graphRenderer) graphRenderer.clearGraph();
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
    if (typeof showNodeDetail === 'function') showNodeDetail(node.id);
  }

  function selectNodes(nodes, mode = 'replace') {
    if (!graphData || !graphRenderer) return;
    const picked = (nodes || []).filter(Boolean);
    if (!picked.length) return;
    graphRenderer.selectNodes(picked, mode);
    selectedNode = picked[picked.length - 1];
    if (typeof showNodeDetail === 'function') showNodeDetail(selectedNode.id);
    const count = graphRenderer.selectedNodeIds?.size ?? picked.length;
    if (count > 1) {
      const rb = document.getElementById('render-badge');
      if (rb) rb.textContent = `${count} nodes selected`;
    }
  }

  function toggleNodeSelection(node, mode = 'toggle') { selectNodes([node], mode); }

  function deselectAll() {
    selectedNode = null;
    if (graphRenderer) graphRenderer.clearSelection();
    if (graphData && typeof clearNodeDetail === 'function') clearNodeDetail();
  }

  async function highlightNode(nodeId) {
    const node = window._nodesMap?.[nodeId];
    if (!node) {
      if (typeof currentGraphId !== 'undefined' && currentGraphId && typeof loadFocusedNode === 'function') {
        await loadFocusedNode(nodeId); return;
      }
      if (graphData?.truncated) {
        const rb = document.getElementById('render-badge');
        if (rb) rb.textContent = 'Node not rendered — increase Render Budget';
      }
      return;
    }
    selectNode(node);
    zoomToNode(node);
  }

  function highlightPath(hops) { if (graphRenderer && graphData) graphRenderer.highlightPath(hops); }

  function zoomIn()  { graphRenderer?.zoomBy(1.35); }
  function zoomOut() { graphRenderer?.zoomBy(0.74); }
  function fitGraph() { graphRenderer?.fitToGraph(); }
  function zoomToNode(node) { graphRenderer?.zoomToNode(node); }

  function bootViewer() {
    if (booted) return;
    booted = true;
    ensureRenderer();
    if (typeof window.init === 'function') { window.init(); return; }
    installControls();
    if (typeof renderStats === 'function' && typeof emptyStats === 'function') renderStats(emptyStats());
    if (typeof renderEmptyState === 'function') renderEmptyState();
    if (typeof loadGraphList    === 'function') loadGraphList();
    if (typeof initResizeHandles === 'function') initResizeHandles();
  }

  // ── Exports ─────────────────────────────────────────────────────────────────
  window.ensureRenderer        = ensureRenderer;
  window.bootViewer            = bootViewer;
  window.renderGraph           = renderGraph;
  window.teardownGraph         = teardownGraph;
  window.refreshLabelVisibility = refreshLabelVisibility;
  window.selectNode            = selectNode;
  window.selectNodes           = selectNodes;
  window.toggleNodeSelection   = toggleNodeSelection;
  window.deselectAll           = deselectAll;
  window.highlightNode         = highlightNode;
  window.highlightPath         = highlightPath;
  window.zoomIn                = zoomIn;
  window.zoomOut               = zoomOut;
  window.fitGraph              = fitGraph;
  window.zoomToNode            = zoomToNode;
})();