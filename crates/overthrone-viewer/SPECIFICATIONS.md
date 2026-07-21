# Overthrone Graph Viewer -- Multi-Platform Rendering Engine

## Comprehensive Development Specification

> **Version:** 1.0.0  
> **Target:** `overthrone-viewer` crate + `overthrone-cli` TUI  
> **Covers:** TUI (ratatui), Three.js WebGL GUI, D3.js migration, OVT command overlays, time metrics  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Shared Graph Data Model](#3-shared-graph-data-model)
4. [TUI Graph Renderer (ratatui/crossterm)](#4-tui-graph-renderer-ratatuicrossterm)
5. [Three.js WebGL GUI (Migrated from D3.js)](#5-threejs-webgl-gui-migrated-from-d3js)
6. [D3.js -> Three.js Migration Guide](#6-d3js--threejs-migration-guide)
7. [OVT Command Overlay on Graph Edges/Nodes](#7-ovt-command-overlay-on-graph-edgesnodes)
8. [Time Metrics & Performance Instrumentation](#8-time-metrics--performance-instrumentation)
9. [API Server Additions](#9-api-server-additions)
10. [Performance Budgets & Targets](#10-performance-budgets--targets)
11. [Appendix A: Edge Type -> OVT Command Map](#appendix-a-edge-type--ovt-command-map)
12. [Appendix B: Color & Theme Reference](#appendix-b-color--theme-reference)

---

## 1. Executive Summary

This document defines the implementation of **three graph rendering methods** for the Overthrone Active Directory attack-graph platform:

| Method | Engine | Target | Use Case |
|--------|--------|--------|----------|
| **TUI** | ratatui + crossterm | Terminal (256-color+) | Local fast inspection, SSH sessions, low-resource environments |
| **Three.js GUI** | WebGL via Three.js | Browser (WebGL 2) | Full interactive graph exploration with GPU-accelerated rendering |
| **D3.js (legacy)** | SVG Canvas | Browser | Existing implementation -- to be superseded by Three.js |

**Core Goals:**
- Extreme performance at scale: **10,000+ nodes, 100,000+ edges** without browser freeze or TUI lag
- Zero-dependency graph rendering in TUI (no external JS/wasm)
- Visually consistent design language across TUI and GUI
- Every ACE/ACL edge annotated with its **exact `ovt` command** for immediate operator action
- Precise time metrics on every load, render, search, and path-finding operation

---

## 2. Architecture Overview

```
+----------------------------------------------------------------+
|                    overthrone-viewer crate                      |
|                                                                |
|  +--------------+    +------------------+    +---------------+ |
|  | graph_data.rs|--->|  Shared State    |<---|  server.rs    | |
|  | (Rust core)  |    |  (Arc<RwLock>)   |    |  (axum HTTP)  | |
|  +--------------+    +--------+---------+    +-------+-------+ |
|                               |                      |         |
|                    +----------+----------+           |         |
|                    |   Render Backend     |           |         |
|                    |                      |           |         |
|            +-------+-------+    +---------+--------+ |         |
|            |  TUI Engine   |    | Three.js Engine  | |         |
|            |  (ratatui)    |    |  (WebAssembly)   | |         |
|            +---------------+    +------------------+ |         |
|                                                        |         |
|  +----------------------------------------------------+-----+ |
|  |  index.html (SPA) -- loads Three.js WASM or falls back   | |
|  |  D3.js for non-WebGL browsers                            | |
|  +----------------------------------------------------------+ |
|                                                                |
|  TimeMetrics --> embedded in every API response + UI HUD       |
+----------------------------------------------------------------+
```

### Design Principles

1. **Single source of truth**: `graph_data.rs` remains the canonical graph engine. No duplication.
2. **Server-driven rendering**: The Rust server computes node positions, clustering, and filtering. Renderers only display.
3. **Progressive disclosure**: Load stats first -> skeleton UI -> node/edge data -> full detail panels.
4. **Performance-first**: Instanced rendering (Three.js), batched DOM updates (TUI cell buffer), lazy edge labels.

---

## 3. Shared Graph Data Model

### 3.1 Enhanced ViewerGraph (graph_data.rs)

Add timing and command-annotation fields. **Do not modify the wire format** -- extend via optional fields.

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewerGraph {
    pub nodes: Vec<ViewerNode>,
    pub edges: Vec<ViewerEdge>,
    pub outgoing: Vec<Vec<usize>>,
    pub incoming: Vec<Vec<usize>>,
    pub relationships: Vec<String>,
    pub stats: ViewerStats,
    pub lookup: HashMap<String, usize>,
    pub search_index: Vec<SearchIndexEntry>,
    
    // === NEW: Performance instrumentation ===
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_metrics: Option<GraphLoadMetrics>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GraphLoadMetrics {
    pub parse_ms: u128,           // JSON parse time
    pub build_ms: u128,           // Graph construction (nodes + edges)
    pub index_ms: u128,           // Search index + lookup construction
    pub layout_ms: u128,          // Hierarchical layout computation
    pub total_ms: u128,           // End-to-end from file to ready
    pub node_count: usize,
    pub edge_count: usize,
    pub file_bytes: u64,
}

// === NEW: Annotated edge for OVT command overlay ===
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewerEdge {
    pub source: usize,
    pub target: usize,
    pub relationship: String,
    pub cost: u32,
    #[allow(dead_code)]
    pub properties: BTreeMap<String, String>,
    
    // === NEW: Computed fields for GUI/TUI overlay ===
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ovt_command: Option<String>,      // e.g., "ovt acl enum --sid S-1-5-21-..."
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ovt_command_desc: Option<String>, // Human-readable description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guidance: Option<String>,
}
```

### 3.2 Enhanced Node Response

```rust
#[derive(Serialize)]
pub struct NodeResponse {
    pub id: String,
    pub label: String,
    pub display_name: String,
    #[serde(rename = "type")]
    pub node_type: String,
    pub domain: String,
    pub distinguished_name: Option<String>,
    pub enabled: Option<bool>,
    pub high_value: bool,
    pub owned: bool,
    // NEW: pre-computed adjacency counts for TUI layout
    pub out_degree: usize,
    pub in_degree: usize,
}
```

### 3.3 Timing Helper (to be added to graph_data.rs)

```rust
use std::time::Instant;

pub struct PerfTimer {
    start: Instant,
    label: &'static str,
}

impl PerfTimer {
    pub fn start(label: &'static str) -> Self {
        Self { start: Instant::now(), label }
    }
    
    pub fn elapsed_ms(&self) -> u128 {
        self.start.elapsed().as_millis()
    }
}

// Usage in from_sources():
// let t_parse = PerfTimer::start("parse");
// ... parse JSON ...
// metrics.parse_ms = t_parse.elapsed_ms();
```

---

## 4. TUI Graph Renderer (ratatui/crossterm)

### Location: `crates/overthrone-cli/src/tui/graph_view.rs`

### 4.1 Performance Strategy

The existing TUI already outperforms D3.js for large graphs because:
- **Cell-based rendering**: ratatui writes directly to a cell buffer -- no DOM, no reflow
- **Zero GC pressure**: Rust manages all memory; no garbage collector pauses
- **Selective redraw**: Only dirty regions re-render via `Frame::render_widget`

**Enhancements for extreme scale:**

#### A. Spatial Indexing for Node Lookup

```rust
use std::collections::BTreeMap;

/// Spatial grid for O(1) approximate nearest-node lookup during hover/selection
#[derive(Default)]
struct SpatialGrid {
    cell_size: f64,
    cells: HashMap<(i64, i64), Vec<NodeId>>,
}

impl SpatialGrid {
    fn new(cell_size: f64) -> Self {
        Self { cell_size, cells: HashMap::new() }
    }
    
    fn insert(&mut self, x: f64, y: f64, node_id: NodeId) {
        let cx = (x / self.cell_size).floor() as i64;
        let cy = (y / self.cell_size).floor() as i64;
        self.cells.entry((cx, cy)).or_default().push(node_id);
    }
    
    fn query_radius(&self, x: f64, y: f64, radius: f64) -> Vec<NodeId> {
        let mut result = Vec::new();
        let r_cells = (radius / self.cell_size).ceil() as i64;
        let cx = (x / self.cell_size).floor() as i64;
        let cy = (y / self.cell_size).floor() as i64;
        
        for dx in -r_cells..=r_cells {
            for dy in -r_cells..=r_cells {
                if let Some(nodes) = self.cells.get(&(cx + dx, cy + dy)) {
                    result.extend(nodes.iter().copied());
                }
            }
        }
        result
    }
}
```

#### B. Level-of-Detail (LOD) Rendering

```rust
/// Determine rendering detail level based on node count and available area
enum RenderLOD {
    Full,       // ≤500 nodes: labels, badges, glyphs, all edges
    Compact,    // 501-2000: labels for HV/owned only, simplified edges
    Minimal,    // 2001-5000: dots only, edge arrows only for critical
    DotCloud,   // >5000: density plot, no individual labels
}

fn select_lod(node_count: usize, area_height: u16) -> RenderLOD {
    if node_count <= 500 { RenderLOD::Full }
    else if node_count <= 2000 { RenderLOD::Compact }
    else if node_count <= 5000 { RenderLOD::Minimal }
    else { RenderLOD::DotCloud }
}
```

#### C. Batched Glyph Rendering

```rust
/// Render all nodes as a single styled string for maximum throughput
fn render_node_batch(
    frame: &mut Frame,
    nodes: &[LayoutNode],
    area: Rect,
    lod: &RenderLOD,
) {
    match lod {
        RenderLOD::Full | RenderLOD::Compact => {
            // Use a Span with grapheme clusters for each node position
            let mut spans = Vec::with_capacity(nodes.len() * 2);
            for node in nodes {
                let color = node_color(&node.node_type);
                let glyph = node_glyph(&node.node_type);
                spans.push(Span::styled(
                    format!("{} ", glyph),
                    Style::default().fg(color),
                ));
            }
            // Render as single paragraph positioned via layout coordinates
            let line = Line::from(spans);
            // ... clip to area, offset by scroll
        }
        RenderLOD::Minimal | RenderLOD::DotCloud => {
            // Unicode block characters for density
            let dot = Span::raw("·");
            // ... batch render
        }
    }
}
```

### 4.2 TUI Layout System

```
+---------------------------------------------------------+
|  [Stats Bar: Users:500  Computers:200  Groups:80...]    |
+---------------------------------------------------------+
|                                                         |
|  +---------------------------------------------------+  |
|  |              GRAPH CANVAS                          |  |
|  |  (scrollable, zoomable via mouse/keyboard)         |  |
|  |                                                    |  |
|  |  U--->G--->C-------------------------D            |  |
|  |  |     |     |    ██████████████████              |  |
|  |  ▼     ▼     ▼    ██  Attack Path  ██              |  |
|  |  [+]   [+]   [+]  ██████████████████              |  |
|  |                   +---------------------------+    |  |
|  +---------------------------------------------------+  |
|                                                         |
|  +--------------+  +--------------------------------+  |
|  | Node Detail  |  | ACL Findings    | Attack Path  |  |
|  | -----------  |  | -------------   | ----------   |  |
|  | Name: svc_   |  | [S1] WriteDacl  | 1. User -->G |  |
|  | Type: Comp   |  | [S1] GenericAll | 2. Group->D |  |
|  | Domain: ...  |  | [S2] AddMember  |              |  |
|  | [Sev1] Bad!  |  |                 |              |  |
|  +--------------+  +--------------------------------+  |
+---------------------------------------------------------+
```

### 4.3 TUI Navigation & Interaction

| Key | Action |
|-----|--------|
| `Tab` | Cycle focus: Graph -> Detail -> ACLs -> Path |
| `^/v/<-/->` | Scroll / pan canvas |
| `+`/`-` | Zoom in/out |
| `Enter` | Select node -> show detail panel |
| `f` | Fuzzy search node (opens type-ahead) |
| `p` | Find attack path (source=selected, prompts for target) |
| `h` | Toggle highlight: show only edges to/from selected |
| `c` | Toggle node type filter (Users/Computers/Groups/Domains) |
| `o` | OVT command: copy selected edge's abuse command to clipboard |
| `t` | Toggle between hierarchical / force / circular layout |
| `s` | Toggle sidebar (detail panels) |
| `Esc` | Deselect, clear search, reset view |
| `/` | Quick filter (type node name substring) |

### 4.4 TUI Force-Directed Layout (GPU-free)

Use Barnes-Hut approximation for O(n log n) force simulation:

```rust
/// Barnes-Hut tree node for O(n log n) force simulation
enum BHNode {
    Internal {
        mass: f64,
        com: (f64, f64),  // center of mass
        quad: Quadrant,
        children: [Option<Box<BHNode>>; 4],
    },
    Leaf {
        node_id: NodeId,
        pos: (f64, f64),
        mass: f64,
    },
}

/// Simulation parameters (tuned for AD graph aesthetics)
struct SimParams {
    repulsion_strength: f64,    // -2000.0 (like charges)
    attraction_strength: f64,   // 0.001 (spring force)
    damping: f64,               // 0.9 (velocity decay)
    max_velocity: f64,          // 10.0 pixels/tick
    theta: f64,                 // 0.5 (Barnes-Hut approximation threshold)
    gravity: f64,               // 0.01 (pull toward center)
    cooling: f64,               // 0.999 per tick
}

/// Run simulation for N ticks (called in TUI event loop)
fn simulate_step(
    nodes: &mut [LayoutNode],
    edges: &[ViewerEdge],
    params: &SimParams,
    bh_tree: &mut BHNode,
) {
    // 1. Build Barnes-Hut tree from current positions: O(n log n)
    rebuild_bh_tree(nodes, bh_tree);
    
    // 2. Compute repulsive forces via BH approximation: O(n log n)
    for node in nodes.iter_mut() {
        let force = compute_repulsion(node, bh_tree, params);
        node.vx += force.0 * params.repulsion_strength;
        node.vy += force.1 * params.repulsion_strength;
    }
    
    // 3. Compute attractive forces along edges: O(e)
    for edge in edges {
        let (fx, fy) = spring_force(
            nodes[edge.source].pos(),
            nodes[edge.target].pos(),
            params.attraction_strength,
            IDEAL_EDGE_LENGTH,
        );
        nodes[edge.source].vx += fx;
        nodes[edge.source].vy += fy;
        nodes[edge.target].vx -= fx;
        nodes[edge.target].vy -= fy;
    }
    
    // 4. Apply gravity toward center
    for node in nodes.iter_mut() {
        let (dx, dy) = (CENTER_X - node.x, CENTER_Y - node.y);
        let dist = (dx * dx + dy * dy).sqrt().max(1.0);
        node.vx += dx / dist * params.gravity;
        node.vy += dy / dist * params.gravity;
    }
    
    // 5. Update positions with velocity and damping
    for node in nodes.iter_mut() {
        if node.pinned { continue; }
        node.vx *= params.damping;
        node.vy *= params.damping;
        node.vx = node.vx.clamp(-params.max_velocity, params.max_velocity);
        node.vy = node.vy.clamp(-params.max_velocity, params.max_velocity);
        node.x += node.vx;
        node.y += node.vy;
    }
}
```

**Target**: Stable layout in ≤200ms for 1,000 nodes, ≤800ms for 5,000 nodes (single-threaded).

### 4.5 TUI Hierarchical Layout (Default)

The existing hierarchical (DAG) layout in `index.html`'s `computeHierarchicalLayout()` should be ported to Rust and kept as the default because AD attack graphs are directed and hierarchical by nature.

```rust
fn hierarchical_layout(
    nodes: &mut [LayoutNode],
    edges: &[ViewerEdge],
    area: Rect,
) -> LayoutDuration {
    let timer = PerfTimer::start("hierarchical_layout");
    
    // 1. Assign ranks via BFS from source nodes (users, owned nodes)
    let ranks = assign_dag_ranks(nodes, edges);
    
    // 2. Minimize edge crossings (barycenter heuristic)
    minimize_crossings(nodes, edges, &ranks);
    
    // 3. Assign x,y coordinates within grid
    let (layer_gap, vert_gap) = compute_gaps(nodes.len(), area);
    place_nodes_in_grid(nodes, &ranks, area, layer_gap, vert_gap);
    
    timer.elapsed_ms() // returned for metrics
}
```

### 4.6 TUI Hover/Detail Rendering

```rust
/// When cursor hovers over a node, render a floating tooltip
fn render_tooltip(
    frame: &mut Frame,
    node: &ViewerNode,
    area: Rect,
    mouse_x: u16,
    mouse_y: u16,
) {
    let lines = vec![
        Line::from(Span::styled(
            node.display_name.clone(),
            Style::default().fg(node_color(&node.node_type)).add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::raw("Type: "),
            Span::styled(format!("{:?}", node.node_type), Style::default().fg(node_color(&node.node_type))),
        ]),
        Line::from(vec![
            Span::raw("Domain: "),
            Span::styled(node.domain.clone().unwrap_or_default(), Style::default().fg(Color::Magenta)),
        ]),
        Line::from(vec![
            Span::raw("SID: "),
            Span::styled(
                node.properties.get("objectid").cloned().unwrap_or_default(),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ];
    
    // Render at mouse position, clipped to frame area
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    
    let area = area.intersection(Rect {
        x: mouse_x + 2,
        y: mouse_y,
        width: 30,
        height: lines.len() as u16 + 2,
    });
    
    frame.render_widget(Clear, area);
    frame.render_widget(Paragraph::new(lines).block(block), area);
}
```

---

## 5. Three.js WebGL GUI (Migrated from D3.js)

### Location: `crates/overthrone-viewer/src/static/index.html`

### 5.1 Why Three.js over D3.js

| Aspect | D3.js (SVG) | Three.js (WebGL) |
|--------|-------------|-------------------|
| Nodes at 5,000 | DOM overhead, 2-5s render | InstancedMesh, <100ms |
| Edge count 50k | SVG paths choke browser | LineSegments/GPU, smooth |
| Zoom/Pan | CSS transforms, janky | GPU matrix uniforms, 60fps |
| Node labels | DOM text, expensive | SDF font atlas on GPU |
| Memory | High (DOM nodes) | Low (GPU buffers) |
| Drag | Layout thrash | Direct buffer update |

### 5.2 Three.js Scene Architecture

```
Scene
+-- AmbientLight (0x222222, 0.5)
+-- DirectionalLight (0xffffff, 0.8, from top-left)
+-- PointLight (0xffffff, 0.3, at camera position for hover glow)
|
+-- InstancedMesh (nodes) -- 1 geometry, N instances
|   +-- SphereBufferGeometry (radius varies by node type)
|   +-- MeshPhongMaterial (per-instance color)
|   +-- Custom shader for: selected state, owned/high-value glow
|
+-- InstancedMesh (edge cylinders/lines)
|   +-- CylinderGeometry or LineSegments
|   +-- Per-instance: color, opacity, dashed pattern
|
+-- Sprite[] (labels -- only visible at close zoom)
|   +-- CanvasTexture generated from text
|
+-- Sprite[] (edge labels)
|
+-- ArrowHelper[] (direction indicators, only for important edges)
|
+-- OrthographicCamera (top-down by default)
|   +-- Smooth zoom with dolly
|
+-- OrbitControls (modified: lock Y-axis rotation)
|
+-- CSS2DObject overlay (HTML tooltips, detail panels)
```

### 5.3 Performance-Critical Three.js Patterns

#### A. Instanced Mesh for Nodes

```javascript
import * as THREE from 'three';

// Create a single geometry, reused for all nodes
const nodeGeometry = new THREE.SphereGeometry(1, 16, 16);

// Pre-allocate max instances
const MAX_NODES = 20000;
const nodeMesh = new THREE.InstancedMesh(nodeGeometry, nodeMaterial, MAX_NODES);
nodeMesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
nodeMesh.instanceColor = new THREE.InstancedBufferAttribute(
    new Float32Array(MAX_NODES * 3), 3
);

scene.add(nodeMesh);

// When graph data arrives, update instances
function updateNodes(graphData) {
    const dummy = new THREE.Object3D();
    const color = new THREE.Color();
    
    for (let i = 0; i < graphData.nodes.length; i++) {
        const node = graphData.nodes[i];
        
        dummy.position.set(node.layout_x, node.layout_y, 0);
        dummy.scale.setScalar(node.radius / 10); // normalize
        dummy.updateMatrix();
        nodeMesh.setMatrixAt(i, dummy.matrix);
        
        const c = NODE_COLORS[node.type] || 0x74747d;
        color.setHex(c);
        nodeMesh.setColorAt(i, color);
    }
    
    nodeMesh.count = graphData.nodes.length;
    nodeMesh.instanceMatrix.needsUpdate = true;
    nodeMesh.instanceColor.needsUpdate = true;
}
```

#### B. Instanced Mesh for Edges (Lines)

```javascript
// Use LineSegments with InstancedBufferGeometry for edges
const edgeGeometry = new THREE.InstancedBufferGeometry();

// Base geometry: unit line along X-axis
const basePositions = new Float32Array([
    0, 0, 0,
    1, 0, 0,
]);
edgeGeometry.setAttribute('position', new THREE.BufferAttribute(basePositions, 3));

// Per-instance attributes
const instanceStart = new Float32Array(MAX_EDGES * 3);
const instanceEnd = new Float32Array(MAX_EDGES * 3);
const instanceColor = new Float32Array(MAX_EDGES * 3);
const instanceWidth = new Float32Array(MAX_EDGES);

edgeGeometry.setAttribute('startPos', new THREE.InstancedBufferAttribute(instanceStart, 3));
edgeGeometry.setAttribute('endPos', new THREE.InstancedBufferAttribute(instanceEnd, 3));
edgeGeometry.setAttribute('colorAttr', new THREE.InstancedBufferAttribute(instanceColor, 3));
edgeGeometry.setAttribute('widthAttr', new THREE.InstancedBufferAttribute(instanceWidth, 1));

// Custom shader for edge rendering
const edgeMaterial = new THREE.ShaderMaterial({
    vertexShader: `
        attribute vec3 startPos;
        attribute vec3 endPos;
        attribute vec3 colorAttr;
        attribute float widthAttr;
        
        varying vec3 vColor;
        varying float vProgress;
        
        void main() {
            vColor = colorAttr;
            vProgress = position.x; // 0.0 to 1.0 along the line
            
            vec3 pos = mix(startPos, endPos, position.x);
            // Add slight z-offset for edges to avoid z-fighting
            pos.z = -0.01 * widthAttr;
            
            vec4 mvPosition = modelViewMatrix * vec4(pos, 1.0);
            gl_Position = projectionMatrix * mvPosition;
        }
    `,
    fragmentShader: `
        varying vec3 vColor;
        varying float vProgress;
        
        void main() {
            // Dash pattern for MemberOf/Contains edges
            float dash = step(0.5, fract(vProgress * 10.0));
            float alpha = mix(0.3, 0.8, dash);
            gl_FragColor = vec4(vColor, alpha);
        }
    `,
    transparent: true,
    depthWrite: false,
});

const edgeMesh = new THREE.Mesh(edgeGeometry, edgeMaterial);
scene.add(edgeMesh);
```

#### C. GPU-Based Label Rendering (SDF Font Atlas)

```javascript
// Pre-generate font atlas for node labels
const fontAtlas = generateSDFAtlas({
    fontFamily: 'Inter, system-ui, sans-serif',
    fontSize: 14,
    characters: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@._-',
    textureSize: 1024,
});

// Labels are Quads with SDF shader material, only rendered when zoom > threshold
class LabelManager {
    constructor(maxLabels = 500) {
        this.quads = [];
        this.visible = new Map(); // nodeId -> Quad index
    }
    
    updateVisible(camera, nodes, minZoom = 0.8) {
        // Only show labels at close zoom or for high-value nodes
        const zoom = camera.zoom;
        
        this.quads.forEach(q => q.visible = false);
        this.visible.clear();
        
        let quadIdx = 0;
        for (const node of nodes) {
            const alwaysShow = node.high_value || node.owned || node.type === 'Domain';
            const zoomShow = zoom >= minZoom && (zoom >= 1.5 || node.degree >= 10);
            
            if (alwaysShow || zoomShow) {
                this.quads[quadIdx].visible = true;
                this.quads[quadIdx].position.set(node.layout_x, node.layout_y, 0.01);
                this.quads[quadIdx].scale.set(
                    node.display_name.length * 0.5, 0.3, 1
                );
                this.visible.set(node.id, quadIdx);
                quadIdx++;
            }
        }
    }
    
    shouldShowLabel(node, zoom) {
        if (zoom >= 2.0) return true;
        if (node.high_value || node.owned || node.type === 'Domain') return true;
        if (zoom >= 1.2 && node.degree >= 6) return true;
        if (zoom >= 0.8 && node.degree >= 18) return true;
        return false;
    }
}
```

#### D. Shader-Based Node Highlighting

```javascript
// Node shader with built-in state (selected, hovered, dimmed, high-value, owned)
const nodeShaderMaterial = new THREE.ShaderMaterial({
    uniforms: {
        time: { value: 0 },
        selectedNodeIndex: { value: -1 },
        hoveredNodeIndex: { value: -1 },
        highlightMode: { value: 0 }, // 0=normal, 1=show-neighbors, 2=show-path
        zoomLevel: { value: 1.0 },
    },
    vertexShader: `
        attribute float nodeType; // encoded as float
        attribute float isHighValue;
        attribute float isOwned;
        attribute float isSelected;
        attribute float isDimmed;
        
        varying float vType;
        varying float vHv;
        varying float vOwned;
        varying float vSelected;
        varying float vDimmed;
        varying float vRadius;
        
        void main() {
            vType = nodeType;
            vHv = isHighValue;
            vOwned = isOwned;
            vSelected = isSelected;
            vDimmed = isDimmed;
            vRadius = scale.x;
            
            vec3 pos = position;
            if (isSelected > 0.5) pos.z += 0.05; // raise selected
            
            vec4 mvPosition = modelViewMatrix * vec4(pos, 1.0);
            gl_PointSize = scale.x * 300.0 / -mvPosition.z;
            gl_Position = projectionMatrix * mvPosition;
        }
    `,
    fragmentShader: `
        uniform float time;
        uniform int highlightMode;
        
        varying float vType;
        varying float vHv;
        varying float vOwned;
        varying float vSelected;
        varying float vDimmed;
        varying float vRadius;
        
        // Node color palette
        vec3 typeColors[8];
        // ... initialize in main or as uniforms
        
        void main() {
            float dist = length(gl_PointCoord - vec2(0.5));
            if (dist > 0.5) discard;
            
            vec3 baseColor = getNodeTypeColor(vType);
            
            if (vDimmed > 0.5) {
                baseColor *= 0.12;
            } else if (highlightMode == 1 && vSelected < 0.5) {
                baseColor *= 0.25;
            }
            
            // Glow for high-value / owned
            if (vHv > 0.5 || vOwned > 0.5) {
                float glow = smoothstep(0.3, 0.0, dist);
                baseColor += vec3(0.2, 0.1, 0.0) * glow * (1.0 + 0.3 * sin(time * 2.0));
            }
            
            // Selected ring
            if (vSelected > 0.5) {
                float ring = smoothstep(0.45, 0.55, dist) - smoothstep(0.4, 0.5, dist);
                baseColor += vec3(1.0) * ring;
            }
            
            gl_FragColor = vec4(baseColor, vDimmed > 0.5 ? 0.14 : 0.9);
        }
    `,
});
```

### 5.4 Interaction System (Three.js)

```javascript
class GraphInteraction {
    constructor(renderer, camera, scene, graphData) {
        this.raycaster = new THREE.Raycaster();
        this.mouse = new THREE.Vector2();
        this.renderer = renderer;
        this.camera = camera;
        this.graphData = graphData;
        
        // Performance: use a low-res offscreen render for picking
        this.pickingTexture = new THREE.WebGLRenderTarget(
            renderer.domElement.width,
            renderer.domElement.height,
            { samples: 0 } // no MSAA for picking
        );
        this.pickingMaterial = new THREE.MeshBasicMaterial({
            vertexColors: true // encode node index as vertex color
        });
    }
    
    onMouseMove(event) {
        // Calculate normalized device coordinates
        this.mouse.x = (event.clientX / window.innerWidth) * 2 - 1;
        this.mouse.y = -(event.clientY / window.innerHeight) * 2 + 1;
        
        // Debounce hover checks to every 2 frames
        if (this.frameCount % 2 === 0) {
            this.checkHover();
        }
        this.frameCount++;
    }
    
    checkHover() {
        this.raycaster.setFromCamera(this.mouse, this.camera);
        
        // Use GPU picking (render node IDs to offscreen buffer)
        const nodeIdx = this.gpuPicking(this.raycaster);
        
        if (nodeIdx !== this.lastHovered) {
            this.lastHovered = nodeIdx;
            if (nodeIdx >= 0) {
                this.showTooltip(
                    this.graphData.nodes[nodeIdx],
                    event.clientX,
                    event.clientY
                );
            } else {
                this.hideTooltip();
            }
        }
    }
    
    onMouseClick(event) {
        const nodeIdx = this.gpuPicking(this.raycaster);
        if (nodeIdx >= 0) {
            this.selectNode(nodeIdx);
        } else {
            this.deselectAll();
        }
    }
    
    /**
     * GPU picking: render scene with node indices as colors to offscreen
     * buffer, then read pixel color to determine which node was hit.
     * O(1) per click regardless of node count.
     */
    gpuPicking(raycaster) {
        // Temporarily swap materials to index-encoded shader
        const originalMat = this.nodeMesh.material;
        this.nodeMesh.material = this.pickingMaterial;
        
        this.renderer.setRenderTarget(this.pickingTexture);
        this.renderer.render(this.scene, this.camera);
        this.renderer.setRenderTarget(null);
        
        // Restore original material
        this.nodeMesh.material = originalMat;
        
        // Read pixel under mouse
        const pixelBuffer = new Uint8Array(4);
        this.renderer.readRenderTargetPixels(
            this.pickingTexture,
            Math.floor(this.mouse.x * 0.5 + 0.5) * this.renderer.domElement.width,
            Math.floor(-this.mouse.y * 0.5 + 0.5) * this.renderer.domElement.height,
            1, 1, pixelBuffer
        );
        
        const nodeIndex = pixelBuffer[0] | (pixelBuffer[1] << 8) | (pixelBuffer[2] << 16);
        return nodeIndex < this.graphData.nodes.length ? nodeIndex : -1;
    }
    
    selectNode(idx) {
        this.selectedNode = idx;
        this.nodeShader.uniforms.selectedNodeIndex.value = idx;
        this.updateNodeAttributes(); // set dimmed flags on all instances
        this.showNodeDetail(this.graphData.nodes[idx]);
    }
    
    deselectAll() {
        this.selectedNode = -1;
        this.nodeShader.uniforms.selectedNodeIndex.value = -1;
        this.nodeShader.uniforms.highlightMode.value = 0;
        this.updateNodeAttributes();
        this.clearNodeDetail();
    }
    
    selectPath(hops) {
        // Highlight path nodes and edges
        const pathNodeSet = new Set();
        const pathEdgeSet = new Set();
        
        hops.forEach(hop => {
            pathNodeSet.add(hop.source_id);
            pathNodeSet.add(hop.target_id);
            pathEdgeSet.add(`${hop.source_id}->${hop.target_id}:${hop.relationship}`);
        });
        
        // Update instance attributes
        for (let i = 0; i < this.graphData.nodes.length; i++) {
            const node = this.graphData.nodes[i];
            this.nodeShader.uniforms.isDimmed.value[i] = pathNodeSet.has(node.id) ? 0 : 1;
        }
        
        // Re-upload instance matrix buffer
        this.nodeMesh.instanceMatrix.needsUpdate = true;
    }
}
```

### 5.5 Camera System (Three.js)

```javascript
class GraphCamera {
    constructor(camera, domElement) {
        this.camera = camera;
        this.dom = domElement;
        this.zoom = 1.0;
        this.minZoom = 0.04;
        this.maxZoom = 12;
        
        // Smooth zoom with inertia
        this.targetZoom = 1.0;
        this.zoomVelocity = 0;
        this.zoomDamping = 0.85;
        
        this.setupControls();
    }
    
    setupControls() {
        // Custom orbit controls -- X/Y pan + zoom, no rotation (graph is 2D)
        this.dom.addEventListener('wheel', (e) => {
            e.preventDefault();
            const zoomFactor = e.deltaY > 0 ? 0.92 : 1.08;
            this.targetZoom = Math.max(this.minZoom, Math.min(this.maxZoom, this.targetZoom * zoomFactor));
            
            // Zoom toward mouse position
            const rect = this.dom.getBoundingClientRect();
            const mx = ((e.clientX - rect.left) / rect.width) * 2 - 1;
            const my = -((e.clientY - rect.top) / rect.height) * 2 + 1;
            this.panOffset.x -= mx * (this.targetZoom - this.zoom) * 2;
            this.panOffset.y -= my * (this.targetZoom - this.zoom) * 2;
        }, { passive: false });
        
        // Pan with mouse drag
        let isDragging = false;
        let lastPos = { x: 0, y: 0 };
        
        this.dom.addEventListener('mousedown', (e) => {
            isDragging = true;
            lastPos = { x: e.clientX, y: e.clientY };
        });
        
        window.addEventListener('mousemove', (e) => {
            if (!isDragging) return;
            const dx = (e.clientX - lastPos.x) / this.zoom;
            const dy = (e.clientY - lastPos.y) / this.zoom;
            this.panOffset.x += dx * 0.5;
            this.panOffset.y -= dy * 0.5;
            lastPos = { x: e.clientX, y: e.clientY };
        });
        
        window.addEventListener('mouseup', () => { isDragging = false; });
    }
    
    update() {
        // Smooth zoom interpolation
        this.zoom += (this.targetZoom - this.zoom) * 0.15;
        this.camera.zoom = this.zoom;
        this.camera.updateProjectionMatrix();
        
        // Update camera position
        this.camera.position.x = this.panOffset.x * this.zoom;
        this.camera.position.y = this.panOffset.y * this.zoom;
        this.camera.updateMatrixWorld();
    }
    
    fitToGraph(nodes) {
        // Compute bounding box and fit
        let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
        for (const n of nodes) {
            minX = Math.min(minX, n.layout_x);
            maxX = Math.max(maxX, n.layout_x);
            minY = Math.min(minY, n.layout_y);
            maxY = Math.max(maxY, n.layout_y);
        }
        
        const width = maxX - minX + 200;
        const height = maxY - minY + 200;
        const aspect = this.dom.clientWidth / this.dom.clientHeight;
        
        const zoomX = this.dom.clientWidth / width;
        const zoomY = this.dom.clientHeight / height;
        this.targetZoom = Math.min(zoomX, zoomY) * 0.8;
        
        this.panOffset.x = -(minX + maxX) / 2;
        this.panOffset.y = -(minY + maxY) / 2;
    }
}
```

### 5.6 Animation Loop

```javascript
class GraphRenderer {
    constructor(canvas) {
        this.scene = new THREE.Scene();
        this.camera = new THREE.OrthographicCamera();
        this.renderer = new THREE.WebGLRenderer({
            canvas,
            antialias: false,     // perf: disable AA for large graphs
            alpha: true,
            powerPreference: 'high-performance',
            preserveDrawingBuffer: false,
        });
        this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2)); // cap DPR
        this.renderer.setSize(canvas.clientWidth, canvas.clientHeight);
        
        this.clock = new THREE.Clock();
        this.interaction = new GraphInteraction(this.renderer, this.camera, this.scene, null);
        this.cameraCtrl = new GraphCamera(this.camera, canvas);
        
        this.statsElement = document.getElementById('perf-stats');
        this.frameTimes = []; // rolling buffer for FPS
    }
    
    animate() {
        requestAnimationFrame(() => this.animate());
        
        const dt = this.clock.getDelta();
        this.cameraCtrl.update();
        
        // Update uniforms
        this.nodeShader.uniforms.time.value = this.clock.elapsedTime;
        this.nodeShader.uniforms.zoomLevel.value = this.cameraCtrl.zoom;
        
        // Dynamic LOD: adjust label visibility based on zoom
        this.labelManager.updateVisible(this.camera, this.graphData.nodes, this.cameraCtrl.zoom);
        
        // Render
        const t0 = performance.now();
        this.renderer.render(this.scene, this.camera);
        const t1 = performance.now();
        
        // Performance overlay
        this.frameTimes.push(t1 - t0);
        if (this.frameTimes.length > 60) this.frameTimes.shift();
        
        if (this.frameTimes.length % 30 === 0) {
            const avg = this.frameTimes.reduce((a, b) => a + b, 0) / this.frameTimes.length;
            this.statsElement.textContent = `${(1000 / avg).toFixed(0)} FPS | ${avg.toFixed(1)}ms/frame | ${this.graphData.nodes.length} nodes`;
        }
    }
}
```

### 5.7 Main Entry Point (Replacing D3.js init)

```javascript
async function init() {
    const renderer = new GraphRenderer(document.getElementById('graph-canvas'));
    
    // Load graph data from API
    const graphData = await loadGraph('/api/graph?graph=...');
    renderer.setGraphData(graphData);
    
    // Setup controls
    renderer.interaction.onSelect = (nodeId) => showNodeDetail(nodeId);
    renderer.interaction.onHover = (node) => showHoverTooltip(node);
    renderer.interaction.onPathFind = (from, to) => findPath(from, to);
    
    // Start render loop
    renderer.animate();
}
```

---

## 6. D3.js -> Three.js Migration Guide

### 6.1 Mapping Table

| D3.js Feature (Current) | Three.js Replacement | Migration Notes |
|--------------------------|---------------------|-----------------|
| `d3.select('svg')` | `new THREE.Scene()` | Scene replaces SVG root |
| `svg.append('g')` | `scene.add(group)` | Use `THREE.Group` for layers |
| `data.join('circle')` | `InstancedMesh` | One draw call for all nodes |
| `data.join('path')` (links) | `LineSegments` or `MeshLine` | Instanced edges |
| `d3.forceSimulation()` | Custom shader or JS physics | GPU particle sim or JS Barnes-Hut |
| `d3.zoom()` | Custom `OrbitControls` (2D locked) | Modified for orthographic, Y-lock |
| `d3.drag()` | Custom raycast + plane drag | Raycast hit -> move on XY plane |
| `svg.append('text')` | `CSS2DRenderer` or `Sprite` | SDF sprite atlas for perf |
| `selection.classed()` | Shader uniform flags | Per-instance boolean uniform |
| `selection.attr('cx')` | `instanceMatrix` | Build matrix from position/scale |
| `.on('mouseenter')` | `raycaster.intersectObject()` | GPU picking or CPU sphere test |
| `svg.transition()` | `gsap` or `TWEEN` | Animate uniforms, not DOM |
| `.style('stroke')` | `ShaderMaterial.uniforms.color` | Per-instance color buffer |
| `marker-end` (arrows) | Custom geometry or shader | Add triangle at line end in vertex shader |
| `.append('defs').append('filter')` | Post-processing `EffectComposer` | Bloom for glow, FXAA for edges |

### 6.2 Feature-for-Feature Migration Checklist

- [ ] **Node circles** -> `InstancedMesh(SphereGeometry, ...)` ✅ 
- [ ] **Node colors by type** -> `instanceColor` attribute ✅
- [ ] **Node size by type/importance** -> `instanceMatrix` scale ✅
- [ ] **High-value/owned rings** -> Shader glow effect ✅
- [ ] **Edge lines** -> `LineSegments` with `InstancedBufferGeometry` ✅
- [ ] **Edge arrows** -> Custom shader fragment (triangle at end) ✅
- [ ] **Edge dash (MemberOf/Contains)** -> SDF dash in fragment shader ✅
- [ ] **Edge labels** -> `CSS2DObject` or sprite atlas (visibility culled) ✅
- [ ] **Node labels** -> `CSS2DObject` or sprite atlas (zoom-culled) ✅
- [ ] **Node badges (degree)** -> Sprite overlay ✅
- [ ] **Force layout** -> JS Barnes-Hut simulation (reuse positions from server) ✅
- [ ] **Hierarchical layout** -> Server-computed, read from API ✅
- [ ] **Zoom/pan** -> Custom orthographic camera controller ✅
- [ ] **Drag** -> Plane intersection + raycast hit test ✅
- [ ] **Highlight connected** -> Shader uniform `isDimmed` per instance ✅
- [ ] **Path highlight** -> Update dim/uniform for path nodes ✅
- [ ] **Tooltip on hover** -> CSS2D overlay positioned at projected point ✅
- [ ] **Search selection** -> Flash animation via uniform `time` ✅
- [ ] **Empty state** -> HTML overlay (keep as-is, outside canvas) ✅
- [ ] **Sidebar, filters, stats** -> Keep as HTML/CSS (no change needed) ✅

### 6.3 Design Preservation Rules

The existing D3.js design includes specific aesthetic choices that **must** be preserved:

1. **Color palette**: All node and edge colors must match exactly (see Appendix B)
2. **Stroke widths**: Important edges = 2.4px equivalent (scale with zoom); others = 1.3px
3. **Dash pattern**: `MemberOf` and `Contains` = `5,4` dash
4. **Arrow style**: Small open triangle at target end (#4d4d55 fill)
5. **Node border**: `stroke: #030303`, width 3px, selected = 5px white
6. **Label font**: Inter/system-ui, 12px, `paint-order: stroke` with 4px stroke
7. **Badge style**: Circle at upper-right of node, with number inside
8. **Filter highlight**: Connected nodes full opacity, rest = 0.14 opacity
9. **Animation**: Zoom transitions ~180-420ms ease (replicate with lerp)

---

## 7. OVT Command Overlay on Graph Edges/Nodes

### 7.1 Design Philosophy

Every **ACE/ACL relationship** displayed on the graph must show the exact `ovt` command needed to investigate or exploit that relationship. This turns the graph into an **interactive attack playbook**.

### 7.2 Data Flow

```
server.rs: edge_security_guidance() 
  -> returns (severity, guidance)
  
NEW: ovt_command_for_edge(relationship, source_node, target_node)
  -> returns (command_string, command_description)
  
API response includes:
EdgeResponse {
    ...,
    ovt_command: String,      // e.g., "ovt acl enum --sid S-1-5-21-...-513"
    ovt_command_desc: String,  // "Enumerate abusable ACEs on Domain Admins group"
}
```

### 7.3 OVT Command Computation (server.rs, Rust)

```rust
/// Compute the appropriate OVT command for a given edge type and context
fn ovt_command_for_edge(
    edge: &ViewerEdge,
    source_node: &ViewerNode,
    target_node: &ViewerNode,
    graph: &ViewerGraph,
) -> (String, String) {
    match edge.relationship.as_str() {
        // -- GenericAll ----------------------------------
        "GenericAll" => {
            let sid = target_node.properties.get("objectid")
                .or_else(|| target_node.properties.get("objectsid"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| target_node.id.clone());
            
            let cmd = format!("ovt powerview acls --sid {}", sid);
            let desc = format!(
                "Enumerate ACLs on {} -- GenericAll means full control: "+
                "password reset, DACL edit, group modification, shadow credentials. "+
                "Review current state before changing anything.",
                target_node.display_name
            );
            (cmd, desc)
        }
        
        // -- GenericWrite --------------------------------
        "GenericWrite" => {
            let sid = target_node.properties.get("objectid")
                .or_else(|| target_node.properties.get("objectsid"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| target_node.id.clone());
            
            let cmd = format!("ovt powerview acls --sid {}", sid);
            let desc = format!(
                "Enumerate ACLs on {} -- Write access. Look for targeted Kerberoasting, "+
                "shadow credentials, SPN writes, logon script changes, or certificate mapping.",
                target_node.display_name
            );
            (cmd, desc)
        }
        
        // -- WriteDacl ----------------------------------
        "WriteDacl" => {
            let sid = target_node.properties.get("objectid")
                .or_else(|| target_node.properties.get("objectsid"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| target_node.id.clone());
            
            (
                format!("ovt acls writedacl --target {}", target_node.id),
                format!("Add a tightly scoped ACE on {}, complete the operation, "+
                       "then restore the original ACL from your notes.",
                       target_node.display_name)
            )
        }
        
        // -- WriteOwner / Owns -------------------------
        "WriteOwner" | "Owns" => {
            let sid = target_node.properties.get("objectid")
                .or_else(|| target_node.properties.get("objectsid"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| target_node.id.clone());
            
            (
                format!("ovt acls writedacl --target {}", target_node.id),
                format!("Take ownership of {}, then modify DACL for GenericAll. "+
                       "Restore original owner after validation.",
                       target_node.display_name)
            )
        }
        
        // -- ForceChangePassword ------------------------
        "ForceChangePassword" => {
            let sid = target_node.properties.get("objectid")
                .or_else(|| target_node.properties.get("objectsid"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| target_node.id.clone());
            
            (
                format!("ovt acl force-password --target {} --password <NEW_PASSWORD>", target_node.id),
                format!("Reset password for {}. Noisy; prefer maintenance window "+
                       "or controlled lab validation.",
                       target_node.display_name)
            )
        }
        
        // -- AddMembers / AddSelf -----------------------
        "AddMembers" | "AddSelf" => {
            let sid = target_node.properties.get("objectid")
                .or_else(|| target_node.properties.get("objectsid"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| target_node.id.clone());
            
            (
                format!("ovt acl add-member --group {} --member <YOUR_ACCOUNT>", target_node.id),
                format!("Add only the required principal to {}, scope and time-box it. "+
                       "Remove immediately after dependent action completes.",
                       target_node.display_name)
            )
        }
        
        // -- AllExtendedRights --------------------------
        "AllExtendedRights" => {
            let sid = target_node.properties.get("objectid")
                .or_else(|| target_node.properties.get("objectsid"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| target_node.id.clone());
            
            (
                format!("ovt powerview acls --sid {}", sid),
                format!("Extended rights on {}. On users -> password reset; on domains -> "+
                       "confirm replication rights before DCSync.",
                       target_node.display_name)
            )
        }
        
        // -- CreateChild --------------------------------
        "CreateChild" => {
            let sid = target_node.properties.get("objectid")
                .or_else(|| target_node.properties.get("objectsid"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| target_node.id.clone());
            
            (
                format!("ovt acls writedacl --target {}", target_node.id),
                format!("CreateChild on {}/container/OU. Only create disposable test "+
                       "objects and remove them; scope matters.",
                       target_node.display_name)
            )
        }
        
        // -- WriteSelf ----------------------------------
        "WriteSelf" => {
            let sid = target_node.properties.get("objectid")
                .or_else(|| target_node.properties.get("objectsid"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| target_node.id.clone());
            
            (
                format!("ovt powerview acls --sid {}", sid),
                format!("Validated self-write on {}. Attribute-specific; "+
                       "confirm member/self or SPN semantics.",
                       target_node.display_name)
            )
        }
        
        // -- LAPS Read Operations -----------------------
        "ReadLapsPassword" | "ReadLapsPasswordExpiry" | "ReadLapsEncryptedPassword" => {
            let sid = target_node.properties.get("objectid")
                .or_else(|| target_node.properties.get("objectsid"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| target_node.id.clone());
            
            (
                format!("ovt laps read --computer {} --target-dc {}", target_node.label, source_node.domain.clone().unwrap_or_default()),
                format!("Read LAPS password for {}. Treat as credential material; "+
                       "avoid repeated reads.",
                       target_node.display_name)
            )
        }
        
        // -- ReadGmsaPassword ---------------------------
        "ReadGmsaPassword" => {
            let sid = target_node.properties.get("objectid")
                .or_else(|| target_node.properties.get("objectsid"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| target_node.id.clone());
            
            (
                format!("ovt powerview acls --sid {}", sid),
                format!("GMSA password for {}. Derive managed account secret and "+
                       "map where the service identity has reach.",
                       target_node.display_name)
            )
        }
        
        // -- AllowedToDelegate --------------------------
        "AllowedToDelegate" => {
            let sid = target_node.properties.get("objectid")
                .or_else(|| target_node.properties.get("objectsid"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| target_node.id.clone());
            
            (
                format!("ovt powerview delegations --target {}", target_node.id),
                format!("Constrained delegation on {}. Enumerate allowed services "+
                       "before S4U testing with minimal ticket requests.",
                       target_node.display_name)
            )
        }
        
        // -- AllowedToAct -------------------------------
        "AllowedToAct" => {
            let sid = target_node.properties.get("objectid")
                .or_else(|| target_node.properties.get("objectsid"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| target_node.id.clone());
            
            (
                format!("ovt acls add-allowed-to-act --target {}", target_node.id),
                format!("RBCD on {}. Use a controlled machine account, request only "+
                       "needed service tickets, then remove the ACE.",
                       target_node.display_name)
            )
        }
        
        // -- ADCS ESC Paths -----------------------------
        "AdcsEsc1" | "AdcsEsc2" | "AdcsEsc3" | "AdcsEsc4" |
        "AdcsEsc5" | "AdcsEsc6" | "AdcsEsc7" | "AdcsEsc8" |
        "AdcsEsc9" | "AdcsEsc10" | "AdcsEsc11" | "AdcsEsc12" |
        "AdcsEsc13" | "AdcsEsc14" | "AdcsEsc15" | "AdcsEsc16" => {
            let esc_num = edge.relationship.trim_start_matches("AdcsEsc");
            
            (
                format!("ovt adcs esc{} --ca <CA_HOST> --template <TEMPLATE>", esc_num),
                format!("ADCS ESC{} path to {}. Verify template EKUs, SAN policy, "+
                       "enrollment agent requirements, and mapping policy before proceeding.",
                       esc_num, target_node.display_name)
            )
        }
        
        // -- DcSync / GetChanges / GetChangesAll ---------
        "DcSync" | "GetChanges" | "GetChangesAll" => {
            (
                format!("ovt adcs dcsync --target {} --domain {}", target_node.id, source_node.domain.clone().unwrap_or_default()),
                format!("Replication rights on {}. Validate scope; prefer targeted "+
                       "secret retrieval over full DCSync.",
                       target_node.display_name)
            )
        }
        
        // -- WriteSPN / WriteServicePrincipalName --------
        "WriteSPN" | "WriteServicePrincipalName" => {
            (
                format!("ovt acl write-spn --target {} --spn <SPN>", target_node.id),
                format!("SPN write on {}. Set one temporary SPN for Kerberoasting, "+
                       "collect one TGS, then restore original SPN set.",
                       target_node.display_name)
            )
        }
        
        // -- WriteKeyCredentialLink ----------------------
        "WriteKeyCredentialLink" | "WriteMsDsKeyCredentialLink" | "AddKeyCredentialLink" => {
            (
                format!("ovt acl shadow-creds --target {} --cert <CERT_FILE>", target_node.id),
                format!("Shadow credentials on {}. Add controlled KeyCredentialLink, "+
                       "authenticate with PKINIT, then remove the value.",
                       target_node.display_name)
            )
        }
        
        // -- WriteAltSecurityIdentities ------------------
        "WriteAltSecurityIdentities" => {
            (
                format!("ovt adcs alt-sid --target {}", target_node.id),
                format!("Certificate mapping write on {}. Verify ADCS mapping policy "+
                       "and restore original values.",
                       target_node.display_name)
            )
        }
        
        // -- WriteAccountRestrictions --------------------
        "WriteAccountRestrictions" => {
            (
                format!("ovt acl modify --target {} --restrictions", target_node.id),
                format!("Account restrictions write on {}. May alter delegation or "+
                       "auth-policy; inspect target class first.",
                       target_node.display_name)
            )
        }
        
        // -- WriteLogonScript / WriteProfilePath / WriteScriptPath -
        "WriteLogonScript" | "WriteProfilePath" | "WriteScriptPath" => {
            (
                format!("ovt acl write-script --target {}", target_node.id),
                format!("Script path write on {}. Visible execution surface; "+
                       "keep payloads minimal and reversible.",
                       target_node.display_name)
            )
        }
        
        // -- WriteDnsHostName ----------------------------
        "WriteDnsHostName" => {
            (
                format!("ovt acl write-dnshost --target {}", target_node.id),
                format!("DNS hostname write on {}. Validate DNS, SPN, and delegation "+
                       "side effects before modifying host identity fields.",
                       target_node.display_name)
            )
        }
        
        // -- WriteProperty -------------------------------
        "WriteProperty" => {
            (
                format!("ovt acl write-property --target {}", target_node.id),
                format!("WriteProperty on {}. Inspect the exact attribute GUID; "+
                       "abuse varies from SPN to delegation to ADCS mapping.",
                       target_node.display_name)
            )
        }
        
        // -- WritePwdProperties family ------------------
        "WritePwdProperties" | "WriteLockoutThreshold" | "WriteMinPwdLength" |
        "WritePwdHistoryLength" | "WritePwdComplexity" | "WritePwdReversibleEncryption" |
        "WritePwdAge" | "WriteLockoutDuration" | "WriteLockoutObservationWindow" => {
            (
                format!("ovt acl modify --target {} --pwd-policy", target_node.id),
                format!("Password policy write on {}. Domain-visible and potentially "+
                       "disruptive; document original policy and prefer read-only proof.",
                       target_node.display_name)
            )
        }
        
        // -- WriteGPLink ---------------------------------
        "WriteGPLink" => {
            (
                format!("ovt gpo link --target {} --gpo <GPO_ID>", target_node.id),
                format!("GPLink write on {}. Validate OU scope, inheritance, enforcement, "+
                       "and security filtering before GPO changes.",
                       target_node.display_name)
            )
        }
        
        // -- EnrollCertificate / EnrollOnBehalfOf --------
        "EnrollCertificate" | "EnrollOnBehalfOf" => {
            (
                format!("ovt adcs enroll --template <TEMPLATE> --target {}", target_node.id),
                format!("Certificate enrollment on {}. Inspect template EKUs, subject "+
                       "supply, manager approval, and enrollment-agent restrictions.",
                       target_node.display_name)
            )
        }
        
        // -- HasSpn / DontReqPreauth ---------------------
        "HasSpn" | "DontReqPreauth" => {
            // These are markers, not directly exploitable via ACL
            let abuser_name = source_node.display_name.clone();
            (
                format!("ovt kerberoast --spn {} --output <TICKETS>", edge.relationship),
                format!("{} marker on {}. Request scoped service tickets and continue "+
                       "offline cracking. Do NOT request repeated online queries.",
                       edge.relationship, target_node.display_name)
            )
        }
        
        // -- AdminTo -------------------------------------
        "AdminTo" => {
            (
                format!("ovt exec --target {} --method auto", target_node.id),
                format!("Local admin on {}. Choose lowest-volume remote-management "+
                       "primitive (WinRM/PS-Remoting -> WMI -> PsExec -> RDP).",
                       target_node.display_name)
            )
        }
        
        // -- CanRDP / CanPSRemote / ExecuteDCOM / SQLAdmin -
        "CanRDP" => {
            (
                format!("ovt exec --target {} --method rdp", target_node.id),
                format!("RDP on {}. Interactive but visible; prefer non-interactive "+
                       "validation unless RDP is required.",
                       target_node.display_name)
            )
        }
        "CanPSRemote" => {
            (
                format!("ovt exec --target {} --method psremote", target_node.id),
                format!("PS-Remoting on {}. Keep commands low-volume and host-scoped.",
                       target_node.display_name)
            )
        }
        "ExecuteDCOM" => {
            (
                format!("ovt exec --target {} --method dcom", target_node.id),
                format!("DCOM on {}. High telemetry surface; reserve for approved "+
                       "execution phases.",
                       target_node.display_name)
            )
        }
        "SQLAdmin" => {
            (
                format!("ovt mssql --target {} --query 'SELECT @@version'", target_node.id),
                format!("SQL admin on {}. Check linked servers, xp_cmdshell, impersonation, "+
                       "CLRs, and trust relationships.",
                       target_node.display_name)
            )
        }
        
        // -- HasSession ----------------------------------
        "HasSession" => {
            (
                format!("ovt exec --target {} --method token", target_node.id),
                format!("Session on {}. Impersonation if admin on host (Incognito / "+
                       "mimikatz tokens). Verify session freshness first.",
                       target_node.display_name)
            )
        }
        
        // -- TrustedBy -----------------------------------
        "TrustedBy" => {
            (
                format!("ovt move trust --domain {} --target {}", source_node.domain.clone().unwrap_or_default(), target_node.id),
                format!("Cross-domain trust from {}. Confirm direction, SID filtering, "+
                       "selective auth, and transitive scope.",
                       source_node.domain.clone().unwrap_or_default())
            )
        }
        
        // -- MemberOf / Contains -------------------------
        "MemberOf" => {
            let sid = target_node.properties.get("objectid")
                .or_else(|| target_node.properties.get("objectsid"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| target_node.id.clone());
            
            (
                format!("ovt powerview members --group {} --recurse", target_node.id),
                format!("Membership in {}. Check nested memberships for privilege escalation.",
                       target_node.display_name)
            )
        }
        "Contains" => {
            (
                format!("ovt powerview container --target {}", target_node.id),
                format!("Containment of {}. Useful for scoping GPO inheritance, "+
                       "OU ownership, and principal locations.",
                       target_node.display_name)
            )
        }
        
        // -- GpoLink -------------------------------------
        "GpoLink" => {
            (
                format!("ovt gpo status --target {}", target_node.id),
                format!("GPO link on {}. Review linked OUs and security filtering.",
                       target_node.display_name)
            )
        }
        
        // -- HasSIDHistory -------------------------------
        "HasSidHistory" => {
            (
                format!("ovt move sid-history --target {}", target_node.id),
                format!("SIDHistory on {}. Validate effective membership and "+
                       "cross-domain side effects.",
                       target_node.display_name)
            )
        }
        
        // -- Fallback ------------------------------------
        _ => {
            let safe_rel = edge.relationship.replace(|c: char| !c.is_ascii_alphanumeric(), "_");
            (
                format!("ovt powerview acls --sid {} --edge-type {}", 
                       target_node.properties.get("objectid")
                           .or_else(|| target_node.properties.get("objectsid"))
                           .unwrap_or(&target_node.id),
                       safe_rel),
                format!("Review {} relationship on {}. Confirm directionality "+
                       "and validate abuse primitive before acting.",
                       edge.relationship, target_node.display_name)
            )
        }
    }
}
```

### 7.4 HTML Overlay for OVT Commands (Three.js GUI)

When user hovers/clicks a node or edge, display the OVT command in the detail panel:

```html
<!-- Added to detail panel (index.html) -->
<div id="ovt-commands" class="detail-section">
    <div class="detail-section-title">! OVT Commands</div>
    <div class="command-list" id="command-list">
        <!-- Dynamically populated -->
    </div>
</div>

<style>
.command-list {
    display: flex;
    flex-direction: column;
    gap: 6px;
    margin-top: 8px;
}
.command-row {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    background: #101012;
    border: 1px solid var(--line);
    border-radius: 6px;
    padding: 8px 10px;
    cursor: pointer;
    transition: border-color 0.15s;
}
.command-row:hover {
    border-color: var(--cyan);
}
.command-text {
    font-family: "Cascadia Mono", "JetBrains Mono", monospace;
    font-size: 11px;
    color: var(--text);
    flex: 1;
    word-break: break-all;
    line-height: 1.5;
}
.command-copy {
    flex: 0 0 auto;
    color: var(--muted);
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    background: transparent;
    border: 1px solid var(--line);
    border-radius: 4px;
    padding: 3px 7px;
    cursor: pointer;
}
.command-copy:hover {
    color: var(--cyan);
    border-color: var(--cyan);
}
.command-label {
    font-size: 10px;
    color: var(--muted);
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
</style>

<script>
function renderOvtCommands(edges, graphId) {
    const container = document.getElementById('command-list');
    container.innerHTML = edges.map(e => `
        <div class="command-row" data-cmd="${escapeAttr(e.ovt_command)}">
            <div>
                <span class="command-label">${escapeHtml(e.relationship)}</span>
                <div class="command-text">${escapeHtml(e.ovt_command_desc)}</div>
            </div>
            <button class="command-copy" onclick="copyOvtCmd(this)">copy</button>
        </div>
    `).join('');
}

function copyOvtCmd(btn) {
    const row = btn.closest('.command-row');
    const cmd = row.getAttribute('data-cmd');
    navigator.clipboard.writeText(cmd).then(() => {
        btn.textContent = 'copied!';
        setTimeout(() => btn.textContent = 'copy', 1500);
    });
}
</script>
```

### 7.5 TUI OVT Command Panel (ratatui)

```rust
/// Render OVT commands for the selected node's edges
fn render_ovt_commands(
    f: &mut Frame,
    area: Rect,
    app: &App,
) {
    let Some(selected_idx) = app.selected_node else {
        return;
    };
    
    let graph = app.graph.lock().unwrap();
    let node = match graph.get_node(selected_idx) {
        Some(n) => n,
        None => return,
    };
    
    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        " OVT Commands ",
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )));
    
    // Collect all edges with OVT commands
    let mut edges_with_cmd: Vec<_> = graph.edges_from(selected_idx)
        .chain(graph.edges_to(selected_idx))
        .filter_map(|e| {
            e.ovt_command().map(|cmd| (e.weight().clone(), cmd, e.ovt_command_desc()))
        })
        .collect();
    
    // Deduplicate by edge type, keeping first occurrence
    let mut seen = HashSet::new();
    let unique: Vec<_> = edges_with_cmd.drain(..)
        .filter(|(wt, ..)| seen.insert(format!("{:?}", wt)))
        .collect();
    
    for (edge_type, cmd, desc) in unique {
        let color = edge_color(&edge_type, false);
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(
                format!("[{:?}]", edge_type),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::raw("  $ "),
            Span::styled(cmd.clone(), Style::default().fg(Color::Cyan)),
        ]));
        if let Some(d) = desc {
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled(d, Style::default().fg(Color::DarkGray)),
            ]));
        }
    }
    
    // Render with scroll
    let scroll = app.ovt_scroll.unwrap_or(0);
    let scrolled: Vec<Line> = lines.into_iter().skip(scroll).collect();
    
    let widget = Paragraph::new(scrolled)
        .block(
            Block::default()
                .title(" OVT Commands [^/v scroll, Ctrl+C to copy] ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .wrap(Wrap { trim: false });
    
    f.render_widget(widget, area);
}
```

### 7.6 Edge Properties to OVT Command Mapping (GraphData Level)

Add the command computation into `graph_data.rs` during the `finish()` method:

```rust
fn finish(self) -> Result<ViewerGraph, String> {
    // ... existing finish logic ...
    
    let mut edges_with_commands = Vec::with_capacity(visual_edges.len());
    for edge in &visual_edges {
        let (cmd, desc) = ovt_command_for_edge(edge, &self.nodes);
        edges_with_commands.push(ViewerEdge {
            source: edge.source,
            target: edge.target,
            cost: edge.cost,
            relationship: edge.relationship.clone(),
            properties: edge.properties.clone(),
            ovt_command: Some(cmd),
            ovt_command_desc: Some(desc),
            severity: Some(edge_severity(&edge.relationship)),
            guidance: Some(edge_guidance(&edge.relationship)),
        });
    }
    
    Ok(ViewerGraph {
        // ... existing fields ...
        edges: edges_with_commands,
        // ...
    })
}
```

### 7.7 Complete OVT Command Map (All Edge Types)

See **Appendix A** at the end of this document for the exhaustive command mapping.

### 7.8 Node-Level OVT Commands

In addition to edge commands, provide commands for **right-clicking a node**:

```
Context Menu (Right-click / Shift+Enter on node):
+--  "ovt powerview users --identity <name>"               -> Get-DomainUser
+--  "ovt powerview computers --filter name=<name>$"        -> Get-DomainComputer
+--  "ovt powerview groups --identity <name>"               -> Get-DomainGroup
+--  "ovt powerview gpos --identity <name>"                 -> Get-DomainGPO
+--  "ovt powerview ous --identity <name>"                  -> Get-DomainOU
+--  "ovt acl enum --sid <SID>"                               -> Enum abusable ACLs
+--  "ovt acls writedacl --target <name>"                    -> DACL modification
+--  "ovt acl force-password --target <name>"                -> Force password reset
+--  "ovt acl add-member --group <name>"                     -> Add to group
+--  "ovt acl shadow-creds --target <name>"                  -> Shadow credentials
+--  "ovt exec --target <name> --method <auto|winrm|ps|dcom>"-> Lateral movement
+--  "ovt kerberoast --spn <SPN>"                            -> Kerberoast
+--  "ovt asrep --user <name>"                               -> AS-REP roast
+--  "ovt laps read --computer <name>"                       -> LAPS read
+--  "ovt sid-history --target <name>"                       -> SIDHistory enumeration
+--  "Copy all commands to clipboard"                           -> Copy all as script
+--  "Show in graph" (already shown)
```

---

## 8. Time Metrics & Performance Instrumentation

### 8.1 Metrics Collection Points

Every operation is timed. Metrics are returned in all API responses.

```rust
/// Time measurement container
#[derive(Serialize, Clone, Debug, Default)]
pub struct OperationMetrics {
    pub started_at: String,           // ISO 8601
    pub total_ms: u128,
    pub phases: Vec<(String, u128)>, // (phase_name, ms)
}

impl OperationMetrics {
    pub fn new() -> Self {
        Self {
            started_at: chrono::Utc::now().to_rfc3339(),
            total_ms: 0,
            phases: Vec::new(),
        }
    }
    
    pub fn phase(&mut self, name: &str, elapsed_ms: u128) {
        self.phases.push((name.to_string(), elapsed_ms));
    }
    
    pub fn total(&mut self) {
        self.total_ms = self.phases.iter().map(|(_, ms)| ms).sum();
    }
}
```

### 8.2 API Response Enhancement

Every API response includes timing:

```rust
// Add to GraphResponse
pub struct GraphResponse {
    // ... existing fields ...
    pub metrics: OperationMetrics,
    pub load_time_ms: u128,
    pub render_time_ms: u128,   // estimated client render budget
}

// Add to PathResponse
pub struct PathResponse {
    // ... existing fields ...
    pub metrics: OperationMetrics,
    pub pathfinding_ms: u128,
}

// Add to NodeDetail
pub struct NodeDetail {
    // ... existing fields ...
    pub retrieval_ms: u128,
}
```

### 8.3 Enhanced API Endpoints with Metrics

```rust
/// GET /api/graph -- with timing
async fn get_graph(
    State(state): State<Arc<AppState>>,
    Query(query): Query<GraphQuery>,
) -> Result<Json<GraphResponse>, StatusCode> {
    let mut metrics = OperationMetrics::new();
    
    let t0 = Instant::now();
    let (bundle, graph) = load_graph(&state, query.graph.as_deref()).await?;
    metrics.phase("cache_or_load", t0.elapsed().as_millis());
    
    let t1 = Instant::now();
    let total_nodes = graph.stats().total_nodes;
    let total_edges = graph.stats().total_edges;
    let type_filter = parse_type_filter(query.types.as_deref());
    let node_limit = resolve_node_limit(query.limit, total_nodes);
    let edge_limit = resolve_edge_limit(query.edges, node_limit, total_nodes, total_edges);
    metrics.phase("resolve_limits", t1.elapsed().as_millis());
    
    let t2 = Instant::now();
    let selected_nodes = if let Some(focus) = query.focus.as_deref() {
        let focus_idx = graph.resolve_node(focus).ok_or(StatusCode::NOT_FOUND)?;
        select_focus_nodes(&graph, focus_idx, node_limit, &type_filter)
    } else {
        select_graph_nodes(&graph, node_limit, &type_filter)
    };
    metrics.phase("node_selection", t2.elapsed().as_millis());
    
    let t3 = Instant::now();
    let selected_set: HashSet<usize> = selected_nodes.into_iter().collect();
    let nodes = graph_nodes(&graph, &selected_set);
    metrics.phase("node_serialization", t3.elapsed().as_millis());
    
    let t4 = Instant::now();
    let edges = graph_edges(&graph, &selected_set, edge_limit);
    metrics.phase("edge_serialization", t4.elapsed().as_millis());
    
    metrics.total();
    
    let load_time_ms = metrics.total_ms;
    // Estimate client render time based on node/edge count
    let render_time_ms = estimate_render_time(nodes.len(), edges.len());
    
    Ok(Json(GraphResponse {
        // ... existing fields ...
        metrics,
        load_time_ms,
        render_time_ms,
    }))
}

fn estimate_render_time(node_count: usize, edge_count: usize) -> u128 {
    // Three.js GPU instanced rendering is ~O(1) for draw calls
    // Budget: 50ms base + per-batch overhead
    let base_ms: u128 = 50;
    let node_batch_ms = (node_count / 5000).saturating_add(1) as u128 * 8;
    let edge_batch_ms = (edge_count / 20000).saturating_add(1) as u128 * 3;
    base_ms + node_batch_ms + edge_batch_ms
}
```

### 8.4 Client-Side Performance HUD

Add a persistent performance overlay in the Three.js canvas:

```html
<div id="perf-hud" style="
    position: absolute; top: 10px; right: 10px;
    font-family: monospace; font-size: 11px;
    background: rgba(13,13,15,0.85); color: var(--cyan);
    padding: 8px 12px; border-radius: 6px;
    pointer-events: none; z-index: 100;
    display: none; /* Toggle with F3 */
">
    <div id="perf-fps">FPS: --</div>
    <div id="perf-draw">Draw: --ms</div>
    <div id="perf-load">API Load: --ms</div>
    <div id="perf-nodes">Nodes: 0</div>
    <div id="perf-edges">Edges: 0</div>
    <div id="perf-mem">GPU: --</div>
</div>
```

```javascript
// Keyboard shortcut: F3 toggles performance HUD
window.addEventListener('keydown', (e) => {
    if (e.key === 'F3') {
        e.preventDefault();
        const hud = document.getElementById('perf-hud');
        hud.style.display = hud.style.display === 'none' ? 'block' : 'none';
    }
});
```

### 8.5 TUI Timing Display

In the TUI, after any load/operation, show timing in the bottom bar:

```
--- Status Bar --------------------------------------------------------
 Loaded: 5000 nodes, 45000 edges in 342ms [parse:12ms, build:89ms, index:45ms, layout:196ms]  |
-----------------------------------------------------------------------
```

---

## 9. API Server Additions

### 9.1 New Endpoints

```
GET  /api/graph/:id/timings    -> GraphLoadMetrics (load timing breakdown)
POST /api/commands/lookup      -> Given edge type + node context, return ovt command
GET  /api/edge-types           -> All edge types with icons, colors, severity, ovt commands
```

### 9.2 Enhanced `/api/graph` Response

Add to `GraphResponse`:

```rust
#[derive(Serialize)]
pub struct GraphResponse {
    // ... existing fields ...
    
    // NEW: Time metrics
    pub load_time_ms: u128,
    pub render_time_ms: u128,
    pub server_metrics: OperationMetrics,
    
    // NEW: Edge commands pre-computed
    pub edges: Vec<EdgeResponse>,
}

#[derive(Serialize)]
pub struct EdgeResponse {
    // ... existing fields ...
    
    // NEW: OVT command overlay
    pub ovt_command: String,
    pub ovt_command_desc: String,
    pub severity: u8,
}
```

### 9.3 Server-Side Command Computation

Add to `server.rs`:

```rust
/// Compute OVT command from edge relationship + node context
fn compute_ovt_command(
    relationship: &str,
    source: &ViewerNode,
    target: &ViewerNode,
) -> (String, String) {
    // Delegate to comprehensive matching logic from §7.3
    ovt_command_for_edge_by_name(relationship, source, target)
}

/// Edge response builder with full command annotation
fn edge_response_with_commands(
    graph: &ViewerGraph,
    edge: &ViewerEdge,
) -> Option<EdgeResponse> {
    let src = graph.get_node(edge.source)?;
    let tgt = graph.get_node(edge.target)?;
    let (severity, guidance) = edge_security_guidance(&edge.relationship);
    let (cmd, cmd_desc) = compute_ovt_command(&edge.relationship, src, tgt);
    
    Some(EdgeResponse {
        source: src.id.clone(),
        target: tgt.id.clone(),
        relationship: edge.relationship.clone(),
        cost: edge.cost,
        severity,
        guidance: guidance.to_string(),
        ovt_command: cmd,
        ovt_command_desc: cmd_desc,
    })
}
```

---

## 10. Performance Budgets & Targets

### 10.1 TUI Performance Targets

| Operation | ≤1k Nodes | ≤5k Nodes | ≤10k Nodes | ≤20k Nodes |
|-----------|-----------|-----------|------------|------------|
| Graph load + parse | <200ms | <500ms | <1.5s | <3s |
| Hierarchical layout | <50ms | <200ms | <500ms | <1s |
| Force sim (stable) | <100ms | <400ms | <1s | <2s |
| Node selection filter | <5ms | <20ms | <50ms | <100ms |
| Full redraw (frame) | <16ms | <33ms | <50ms | <83ms |
| Search (fuzzy) | <10ms | <20ms | <50ms | <100ms |
| Path finding (BFS) | <5ms | <20ms | <50ms | <100ms |

**Target**: 60 FPS render during interaction, ≤30 FPS during force simulation.

### 10.2 Three.js WebGL Performance Targets

| Operation | ≤1k Nodes | ≤5k Nodes | ≤10k Nodes | ≤20k Nodes |
|-----------|-----------|-----------|------------|------------|
| API load + parse | <200ms | <500ms | <1.5s | <3s |
| First render (GPU upload) | <100ms | <300ms | <800ms | <1.5s |
| Frame render (steady) | <10ms | <16ms | <25ms | <40ms |
| Node selection + highlight | <5ms | <10ms | <20ms | <30ms |
| Path highlight | <5ms | <10ms | <15ms | <20ms |
| Search / filter | <15ms | <30ms | <60ms | <120ms |
| Fit-to-view | <10ms | <20ms | <30ms | <50ms |

**Target**: 60 FPS at all scales up to 5,000 nodes. Sustained 30 FPS up to 20,000 nodes.

### 10.3 Memory Targets

| Scale | RAM (TUI) | RAM (Three.js) |
|-------|-----------|-----------------|
| 1k nodes, 5k edges | <10 MB | <30 MB |
| 5k nodes, 25k edges | <50 MB | <80 MB |
| 10k nodes, 50k edges | <100 MB | <150 MB |
| 20k nodes, 100k edges | <200 MB | <300 MB |

### 10.4 API Response Size Budgets

| Operation | Max Payload Size | Compression |
|-----------|-----------------|-------------|
| Full graph (no filter) | 2 MB raw | gzip |
| Filtered graph (1k nodes) | 200 KB raw | none |
| Path response | 50 KB raw | none |
| Node detail | 5 KB raw | none |
| Stats only | 1 KB raw | none |

---

## Appendix A: Edge Type -> OVT Command Map

| Edge Type (Relationship) | Severity | OVT Command | Notes |
|--------------------------|----------|-------------|-------|
| **GenericAll** | 1 (crit) | `ovt powerview acls --sid <SID>` | Full control. Password reset, DACL edit, group mod, shadow creds. |
| **GenericWrite** | 2 (high) | `ovt powerview acls --sid <SID>` | Write access. Targeted Kerberoast, shadow creds, SPN writes, logon scripts. |
| **WriteDacl** | 1 (crit) | `ovt acls writedacl --target <TARGET>` | Add scoped ACE -> act -> restore original. |
| **WriteOwner** | 1 (crit) | `ovt acls writedacl --target <TARGET>` | Ownership -> DACL -> GenericAll. Restore after. |
| **Owns** | 1 (crit) | `ovt acls writedacl --target <TARGET>` | Already owner -> modify DACL -> GenericAll. |
| **ForceChangePassword** | 2 (high) | `ovt acl force-password --target <TGT> --password <PW>` | Noisy. Prefer maintenance window. |
| **AddMembers** | 2 (high) | `ovt acl add-member --group <GRP> --member <ACCT>` | Scope tightly. Remove immediately after. |
| **AddSelf** | 2 (high) | `ovt acl add-self --group <GRP>` | Self-write validated. Add own account. |
| **AllExtendedRights** | 1 (crit) | `ovt powerview acls --sid <SID>` | Password reset (users) or DCSync (domains). Confirm scope. |
| **CreateChild** | 3 (med) | `ovt acls writedacl --target <TGT>` | Create disposable objects. Check machine-acct/group scope. |
| **WriteSelf** | 2 (high) | `ovt powerview acls --sid <SID>` | Validated self-write. Group self-add or attribute updates. |
| **ReadLapsPassword** | 2 (high) | `ovt laps read --computer <COMP> --target-dc <DC>` | Recover cleartext LAPS password. |
| **ReadLapsPasswordExpiry** | 2 (high) | `ovt laps read --computer <COMP> --target-dc <DC>` | Read LAPS expiry timestamp. |
| **ReadGmsaPassword** | 2 (high) | `ovt powerview acls --sid <SID>` | Derive gMSA secret. Map service-identity reach. |
| **AllowedToDelegate** | 2 (high) | `ovt powerview delegations --target <TGT>` | Constrained delegation. Enumerate allowed services. Test S4U. |
| **AllowedToAct** | 1 (crit) | `ovt acls add-allowed-to-act --target <TGT>` | RBCD. Controlled machine acct -> getST.py -> impersonate DA. |
| **WriteAllowedToDelegateTo** | 1 (crit) | `ovt acls writedacl --target <TGT>` | Change msDS-AllowedToDelegateTo. Test S4U path. Record & restore. |
| **AddAllowedToAct** | 1 (crit) | `ovt acls add-allowed-to-act --target <TGT>` | Add controlled computer to msDS-AllowedToActOnBehalfOfOther. |
| **HasSidHistory** | 3 (med) | `ovt move sid-history --target <TGT>` | Validate effective SIDHistory membership + cross-domain effects. |
| **DcSync** | 1 (crit) | `ovt adcs dcsync --target <TGT> --domain <DOM>` | secretsdump -just-dc. Validate scope. |
| **GetChanges** | 2 (high) | `ovt adcs dcsync --target <TGT> --domain <DOM>` | Part of DCSync. Principal needs both GetChanges flags. |
| **GetChangesAll** | 2 (high) | `ovt adcs dcsync --target <TGT> --domain <DOM>` | Part of DCSync. Principal needs both GetChanges flags. |
| **HasSpn** | 4 (info) | `ovt kerberoast --spn <SPN>` | Kerberoast marker. Scoped tickets, offline crack. |
| **DontReqPreauth** | 4 (info) | `ovt asrep --user <USER>` | AS-REP roast. Collect once, offline crack. |
| **CanRDP** | 3 (med) | `ovt exec --target <TGT> --method rdp` | GUI access. May not require local admin. |
| **CanPSRemote** | 3 (med) | `ovt exec --target <TGT> --method psremote` | PowerShell remoting. Low-volume, host-scoped. |
| **ExecuteDCOM** | 3 (med) | `ovt exec --target <TGT> --method dcom` | High telemetry. Reserve for approved phases. |
| **SQLAdmin** | 2 (high) | `ovt mssql --target <TGT> --query ...` | Check linked servers, xp_cmdshell, impersonation, CLR. |
| **HasSession** | 3 (med) | `ovt exec --target <TGT> --method token` | Token impersonation if admin on host. Verify freshness. |
| **TrustedBy** | 2 (high) | `ovt move trust --domain <SRC> --target <TGT>` | Cross-domain trust. Confirm direction, SID filtering, transitivity. |
| **GpoLink** | 2 (high) | `ovt gpo status --target <TGT>` | Review linked OUs, enforcement, security filtering. |
| **WriteGPLink** | 2 (high) | `ovt gpo link --target <TGT> --gpo <ID>` | Link controlled GPO. Confirm scope & rollback. |
| **WriteSPN** | 2 (high) | `ovt acl write-spn --target <TGT> --spn <SPN>` | Set temp SPN -> Kerberoast -> restore. |
| **WriteServicePrincipalName** | 2 (high) | `ovt acl write-spn --target <TGT> --spn <SPN>` | Same as WriteSPN. |
| **WriteKeyCredentialLink** | 1 (crit) | `ovt acl shadow-creds --target <TGT>` | Shadow creds. PKINIT auth. Capture & restore original. |
| **WriteMsDsKeyCredentialLink** | 1 (crit) | `ovt acl shadow-creds --target <TGT>` | Same as WriteKeyCredentialLink. |
| **AddKeyCredentialLink** | 1 (crit) | `ovt acl shadow-creds --target <TGT>` | Same as WriteKeyCredentialLink. |
| **WriteAltSecurityIdentities** | 1 (crit) | `ovt adcs alt-sid --target <TGT>` | Cert mapping. Verify mapping policy; restore original. |
| **WriteUserParameters** | 3 (med) | `ovt acl write-script --target <TGT>` | Legacy exec/persistence surface. Validate first. |
| **WritePwdProperties** | 3 (med) | `ovt acl modify --target <TGT> --pwd-policy` | Domain-visible. Prefer read-only. |
| **WriteLockoutThreshold** | 3 (med) | `ovt acl modify --target <TGT> --pwd-policy` | Domain-visible. |
| **WriteWritelockoutduration** | 3 (med) | `ovt acl modify --target <TGT> --pwd-policy` | Domain-visible. |
| **WriteMinPwdLength** | 3 (med) | `ovt acl modify --target <TGT> --pwd-policy` | Domain-visible. |
| **WritePwdHistoryLength** | 3 (med) | `ovt acl modify --target <TGT> --pwd-policy` | Domain-visible. |
| **WritePwdComplexity** | 3 (med) | `ovt acl modify --target <TGT> --pwd-policy` | Domain-visible. |
| **WritePwdReversibleEncryption** | 3 (med) | `ovt acl modify --target <TGT> --pwd-policy` | Domain-visible. |
| **WritePwdAge** | 3 (med) | `ovt acl modify --target <TGT> --pwd-policy` | Domain-visible. |
| **WriteLockoutObservationWindow** | 3 (med) | `ovt acl modify --target <TGT> --pwd-policy` | Domain-visible. |
| **EnrollCertificate** | 2 (high) | `ovt adcs enroll --template <TMPL> --target <TGT>` | Review EKUs, supply, approval, agent scope. |
| **EnrollOnBehalfOf** | 1 (crit) | `ovt adcs enroll --template <TMPL> --target <TGT>` | Validate template constraints & approval. |
| **AdcsEsc1** -- **AdcsEsc16** | 1 (crit) | `ovt adcs esc<N> --ca <CA> --template <TMPL>` | Per-ESC variant guidance (see §7.3). |
| **WriteProperty** | 2 (high) | `ovt acl write-property --target <TGT>` | Inspect attribute GUID; abuse varies. |
| **MemberOf** | 5 | `ovt powerview members --group <GRP> --recurse` | Membership. Check nested for priv esc. |
| **Contains** | 5 | `ovt powerview container --target <TGT>` | Scoping: GPO inheritance, OU ownership. |
| **MemberOfTierZero** | 1 (crit) | `ovt powerview members --group <GRP> --recurse` | Tier-zero membership. Domain-impacting. |

---

## Appendix B: Color & Theme Reference

### Node Colors (Shared Across TUI & Three.js)

| Node Type | Hex | TUI Color | Three.js Color |
|-----------|-----|-----------|----------------|
| User | `#6aa8ff` | `Color::Green` (ratatui) | `0x6aa8ff` |
| Computer | `#5bea8c` | `Color::Blue` | `0x5bea8c` |
| Group | `#f4c95d` | `Color::Yellow` | `0xf4c95d` |
| Domain | `#ff4d4d` | `Color::Magenta` | `0xff4d4d` |
| GPO | `#d08cff` | `Color::Cyan` | `0xd08cff` |
| OU | `#ff7dbd` | `Color::LightBlue` | `0xff7dbd` |
| CertTemplate / EnterpriseCA | `#49e4d6` | `Color::LightMagenta` | `0x49e4d6` |
| Container | `#b5b5bc` | `Color::Gray` | `0xb5b5bc` |
| Unknown | `#74747d` | `Color::DarkGray` | `0x74747d` |

### High-Value / Owned Indicators

| State | Border/Outline | Three.js Effect |
|-------|---------------|-----------------|
| High Value | Yellow `#f4c95d`, 3px solid | Pulsing glow shader (yellow tint) |
| Owned | Green `#5bea8c`, 3px solid | Pulsing glow shader (green tint) |
| Selected | White `#ffffff`, 5px solid | Raised Z + bright ring |
| Dimmed (de-focused) | Opacity 0.14 | Opacity 0.14 uniform |

### Edge Colors (Shared)

| Relationship | Color | Category |
|-------------|-------|----------|
| GenericAll, WriteDacl, WriteOwner, Owns, AllowedToAct, ADCS paths | `#f4c95d` (yellow) | Critical (severity 1-2) |
| AdminTo, CanPSRemote, ExecuteDCOM | `#ff4d4d` (red) | High (severity 2-3) |
| HasSession, HasSpn, DontReqPreauth, AddMembers, AddSelf | `#6aa8ff` (blue) | Medium (severity 3-4) |
| TrustedBy, GpoLink, WriteGPLink, WriteAllowedToDelegateTo | `#d08cff` (magenta) | Trusted/Policy |
| CanRDP, SQLAdmin, EnrollCertificate | `#49e4d6` (cyan) | Access/Enrollment |
| MemberOf, Contains | `#74747d` (gray), dashed | Membership/Structure |
| WriteProperty, WriteSPN, Shadow Creds, etc. | `#ff4d4d` (red) | Write/AE |

---

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-05-13 | Auto-generated | Initial comprehensive spec for TUI + Three.js + OVT overlay |