# overthrone-viewer Implementation TODO

> **Goal:** Build a BloodHound-style graph viewer for Overthrone's attack path graph.
> See `DESIGN.md` for the full architecture and visual design specification.

---

## Phase 1: Core Infrastructure

- [x] **1.1** Create `crates/overthrone-viewer/` crate scaffold (Cargo.toml, lib.rs, main.rs)
- [x] **1.2** Implement `graph/convert.rs` -- `petgraph::StableDiGraph` conversion from `AttackGraph`
  - [x] Node mapping (AttackGraphNode -> petgraph node index)
  - [x] Edge mapping (AttackEdge -> petgraph edge with relationship + cost)
  - [x] `Direction` enum for edge direction
  - [x] `petgraph::graph::Edge reference` wrapper
- [x] **1.3** Implement `graph/overlay.rs` -- OverlayManager
  - [x] Multiple named overlays (privesc, lateral, sessions, etc.)
  - [x] Enable/disable/visibility toggle
  - [x] `get_active_graph()` -- combined filtered view
  - [x] `get_combined_filtered_view()` -- intersection of active overlays
  - [x] Edge classification per overlay
- [x] **1.4** Implement `graph/analysis.rs` -- GraphAnalyzer
  - [x] Community detection (LabelRankZ / weakly connected components)
  - [x] PageRank computation
  - [x] Betweenness centrality
  - [x] `get_communities()` -- returns Community map
  - [x] `get_critical_paths()` -- high-betweenness paths
  - [x] `rank_nodes()` -- node importance ranking

## Phase 2: Layout Engine

- [x] **2.1** Create `layout/mod.rs` -- LayoutEngine trait + manager
- [x] **2.2** Implement `layout/force_directed.rs` -- ForceDirectedLayout (d3-force-3d equivalent)
  - [x] Velocity Verlet integration
  - [x] Center force, charge force (many-body), link force, collision force
  - [x] Radial force by node type (optional)
  - [x] Alpha cooling
  - [x] `compute_positions()` -- runs simulation to completion
- [x] **2.3** Implement `layout/tree.rs` -- TreeLayout for hierarchical views
  - [x] Sugiyama-style layered layout (topological levels)
  - [x] Layer assignment, ordering, coordinate assignment
  - [x] Better for domain OU hierarchy views
- [x] **2.4** Implement `layout/physics.rs` -- PhysicsConfig + PhysicsEngine
  - [x] Tuned physics params (gravity, repulsion, link distance, collision radius)
  - [x] Node-type-specific sizing
  - [x] Convergence detection (alpha < threshold)
  - [x] Real-time update support (reheat + recompute)

## Phase 3: Web Backend (Axum)

- [x] **3.1** Implement `server.rs` -- Axum HTTP server
  - [x] `GET /` -- Serve embedded SPA (include_str!)
  - [x] `GET /api/graph` -- Full graph data (nodes + edges + layout positions)
  - [x] `GET /api/graph?overlay=privesc` -- Filtered by overlay
  - [x] `GET /api/graph?community=3` -- Filtered by community
  - [x] `GET /api/node/:id` -- Single node + neighbors
  - [x] `GET /api/node/:id/path?to=X` -- Shortest path
  - [x] `GET /api/overlays` -- List available overlays
  - [x] `GET /api/communities` -- Community data
  - [x] `GET /api/search?q=...` -- Node name search (case-insensitive, top 50)
  - [x] `POST /api/layout/recalculate` -- Re-run layout with params
  - [x] Static file serving for embedded assets
- [x] **3.2** Implement `server.rs` -- WebSocket endpoint
  - [x] `/ws/updates` -- Real-time graph updates (node add/remove)
- [x] **3.3** Add CORS middleware for local dev

## Phase 4: SPA Frontend

- [x] **4.1** Create `static/index.html` -- Single HTML file with embedded CSS/JS
- [x] **4.2** Implement CSS (BloodHound-inspired dark theme)
  - [x] Header bar with search + controls
  - [x] SVG canvas for D3 rendering
  - [x] Side panels (node details, path results)
  - [x] Overlay toggle buttons
  - [x] Legend panel
  - [x] Responsive layout
- [x] **4.3** Implement JS -- D3.js force-directed graph rendering
  - [x] D3.js v7 loaded from CDN
  - [x] `d3-force` simulation with zoom/pan
  - [x] SVG node rendering with type-specific shapes and colors
  - [x] SVG edge rendering with directional arrows
  - [x] Edge labels (relationship type)
  - [x] Hover tooltips
  - [x] Click-to-select nodes
  - [x] Double-click to expand neighbors
  - [x] Color coding by node type (User=blue, Computer=red, Group=green, etc.)
  - [x] Color coding by attack stage (privesc=orange, lateral=yellow, etc.)
  - [x] Disabled nodes shown as hollow/striped
- [x] **4.4** Implement JS -- UI interactions
  - [x] Search bar with autocomplete
  - [x] Overlay toggle buttons
  - [x] Community filter
  - [x] Path finding UI (select source -> target)
  - [x] Shortest path highlight (animated)
  - [x] Node detail panel (properties, connections, groups)
  - [x] Edge detail on hover
  - [x] Legend panel
  - [x] Zoom to fit / zoom to node
- [x] **4.5** Implement JS -- Data fetching
  - [x] Fetch `/api/graph` on load
  - [x] Fetch `/api/node/:id` on select
  - [x] Fetch `/api/path?to=X` on path request
  - [x] Fetch `/api/search?q=...` on search
  - [x] WebSocket connection for live updates

## Phase 5: Integration & Polish

- [x] **5.1** Add `viewer` subcommand to CLI (in `commands_impl.rs`)
- [x] **5.2** Handle large graphs (>10k nodes) -- level-of-detail: skip borders/glow/icons,
       reduce edge labels, use fewer curve segments, limit arrow meshes
- [x] **5.3** Add keyboard shortcuts (Esc=clear, /=search, Tab=toggle panel)
- [x] **5.4** Add loading spinner while graph data loads
- [x] **5.5** Add graph export (PNG via canvas capture, JSON via API download)
- [x] **5.6** Add dark/light theme toggle (CSS vars + localStorage persistence)
- [x] **5.7** Make side panel resizable (drag to resize via `initResizeHandles`)

---

## File Structure

```
crates/overthrone-viewer/
+-- Cargo.toml          ✅ Created
+-- TODO.md             ✅ This file
+-- DESIGN.md           ✅ Visual design spec
+-- src/
|   +-- lib.rs          ✅ Public API
|   +-- main.rs         ✅ Standalone binary entry point
|   +-- server.rs       ✅ Axum web server + API routes
|   +-- graph/
|   |   +-- mod.rs      ✅ Module declarations
|   |   +-- convert.rs  ✅ AttackGraph -> petgraph conversion
|   |   +-- overlay.rs  ✅ Overlay manager (multiple named overlays)
|   |   +-- analysis.rs ✅ Community detection, PageRank, critical paths
|   +-- layout/
|   |   +-- mod.rs      ✅ LayoutEngine trait + LayoutManager
|   |   +-- force_directed.rs  ✅ D3-style force simulation
|   |   +-- tree.rs     ✅ Sugiyama hierarchical layout
|   |   +-- physics.rs  ✅ Physics config + real-time engine
|   +-- static/
|       +-- index.html  ✅ Embedded SPA (CSS + JS + D3.js)
```

---

## Design References

- `DESIGN.md` -- Full visual design, color palette, layout, interactions
- Overthrone `AttackGraph` -- `crates/overthrone-core/src/graph/mod.rs`
- BloodHound CE -- UI inspiration (dark theme, force-directed, panel layout)