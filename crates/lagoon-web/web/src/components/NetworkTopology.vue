<script setup>
import { ref, onMounted, onUnmounted, nextTick } from 'vue'

const props = defineProps({
  serverUrl: String,
})

const container = ref(null)
const mode = ref('') // '3d', '2d', or '' (loading)
const hoveredNode = ref(null)
const panelPos = ref({ x: 0, y: 0 })
let graph = null
let ws = null
let showBeams = true
let showNodes = true

// Mesh stats — updated on every snapshot.
const stats = ref({ nodes: 0, connected: 0, disconnected: 0, links: 0, spiralLinks: 0 })

// Color palette — Tokyo Night theme.
const COLORS = {
  self: '#7aa2f7',       // Blue — this node
  connected: '#9ece6a',  // Green — connected peer
  pruning: '#4d7a3a',    // Dark green — disconnected but VDF still ticking (pruning/transient)
  offline: '#f7768e',    // Red — actually unhealthy (VDF stalled or no data)
  browser: '#bb9af7',    // Purple — browser/web peer
  link: '#565f89',       // Muted — default link color (no metrics)
  background: '#1a1b26', // Dark background
  text: '#c0caf5',       // Light text
}

function nodeColor(node) {
  if (node.node_type === 'browser') return COLORS.browser
  if (node.is_self) return COLORS.self
  if (node.connected) return COLORS.connected
  // Disconnected: dark green if VDF is still ticking (pruning/transient),
  // red only if VDF has stalled or no VDF data (actually unhealthy).
  const liveness = vdfLiveness(node)
  if (liveness === 'ticking') return COLORS.pruning
  return COLORS.offline
}

function nodeLabel(node) {
  if (node.node_type === 'browser') return node.mesh_key.replace('web/', '')
  if (node.node_name && node.node_name !== node.server_name) {
    return `${node.server_name} (${node.node_name})`
  }
  return node.server_name
}

/** VDF liveness tracking.
 *  Updated in updateGraph() on each snapshot.  nodeColor() and the tooltip
 *  read _vdf_liveness from the node object — no side effects on read. */
const prevVdfSteps = new Map()

/** Update VDF liveness tracking for a node.  Called once per node per snapshot. */
function updateVdfLiveness(node) {
  if (node.is_self) { node._vdf_liveness = 'ticking'; return }
  if (node.vdf_step == null) { node._vdf_liveness = null; return }
  const key = node.id || node.mesh_key
  const prev = prevVdfSteps.get(key)
  prevVdfSteps.set(key, node.vdf_step)
  if (prev == null) { node._vdf_liveness = 'ticking'; return } // first observation
  node._vdf_liveness = node.vdf_step > prev ? 'ticking' : 'stalled'
}

/** Read VDF liveness state.  Side-effect-free — safe to call from any accessor. */
function vdfLiveness(node) {
  return node._vdf_liveness ?? null
}

/** Count links touching a given node ID in the current graph data. */
function countNodeLinks(nodeId) {
  if (!graph) return { total: 0, connected: 0, disconnected: 0 }
  const data = graph.graphData()
  const getId = x => typeof x === 'object' ? x.id : x
  let total = 0
  let connected = 0
  for (const link of data.links) {
    if (getId(link.source) === nodeId || getId(link.target) === nodeId) {
      total++
      // Links with latency or upload data are "live"
      if (link.latency_ms || link.upload_bps) connected++
    }
  }
  return { total, connected, disconnected: total - connected }
}

/** Handle node hover — show/hide info panel. */
function onNodeHover(node, event) {
  if (node) {
    hoveredNode.value = node
    if (event) {
      panelPos.value = { x: event.clientX + 16, y: event.clientY + 16 }
    }
  } else {
    hoveredNode.value = null
  }
}

/** Track mouse position for panel placement while hovering. */
function onMouseMove(event) {
  if (hoveredNode.value) {
    panelPos.value = { x: event.clientX + 16, y: event.clientY + 16 }
  }
}

// ---------------------------------------------------------------------------
// Link metric visualization helpers
// ---------------------------------------------------------------------------

/** Link width = upload bandwidth (logarithmic scale).
 *  Min 1.5 (idle/no data), max ~3.5 at 100MB/s. */
function linkWidthByUpload(link) {
  if (!link.upload_bps || link.upload_bps <= 0) return 1.5
  // Log scale: 1KB/s -> ~1.7, 1MB/s -> ~2.4, 100MB/s -> ~3.5
  return Math.max(1.5, 1.0 + Math.log10(link.upload_bps / 1000 + 1) * 0.625)
}

/** Link color = download bandwidth (gradient from muted -> green -> blue). */
function linkColorByDownload(link) {
  if (!link.download_bps || link.download_bps <= 0) return COLORS.link
  const low = 1000       // 1 KB/s
  const high = 10_000_000 // 10 MB/s
  const t = Math.min(1, Math.max(0,
    (Math.log10(link.download_bps) - Math.log10(low)) /
    (Math.log10(high) - Math.log10(low))
  ))
  if (t < 0.5) return lerpColor('#565f89', '#9ece6a', t * 2)   // muted -> green
  return lerpColor('#9ece6a', '#7aa2f7', (t - 0.5) * 2)        // green -> blue
}

/** Linear color interpolation between two hex colors. */
function lerpColor(a, b, t) {
  const parse = c => [
    parseInt(c.slice(1, 3), 16),
    parseInt(c.slice(3, 5), 16),
    parseInt(c.slice(5, 7), 16),
  ]
  const [ar, ag, ab] = parse(a)
  const [br, bg, bb] = parse(b)
  const r = Math.round(ar + (br - ar) * t)
  const g = Math.round(ag + (bg - ag) * t)
  const bl = Math.round(ab + (bb - ab) * t)
  return `#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${bl.toString(16).padStart(2, '0')}`
}

/** Format bytes per second as human-readable string. */
function formatBps(bps) {
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} MB/s`
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(1)} KB/s`
  return `${Math.round(bps)} B/s`
}

/** Link tooltip with bandwidth and latency metrics. */
function linkTooltip(link) {
  const parts = []
  if (link.link_type === 'spiral') parts.push('SPIRAL geometric neighbor')
  if (link.latency_ms) parts.push(`Latency: ${link.latency_ms.toFixed(1)}ms`)
  if (link.upload_bps) parts.push(`Up: ${formatBps(link.upload_bps)}`)
  if (link.download_bps) parts.push(`Down: ${formatBps(link.download_bps)}`)
  return parts.join('\n')
}

// ---------------------------------------------------------------------------
// Two-layer link rendering (SPIRAL structural + relay data links)
// ---------------------------------------------------------------------------

/** Link width by type: spiral neighbors are prominent, proof is thinner. */
function linkWidthByType(link) {
  if (link.link_type === 'spiral') return 2.0
  if (link.link_type === 'proof') return 1.0
  return linkWidthByUpload(link)
}

/** Link color by latency: green (low) → yellow (moderate) → red (high). */
function linkColorByLatency(link) {
  if (!link.latency_ms || link.latency_ms <= 0) return COLORS.link
  const low = 1     // 1ms
  const high = 200   // 200ms
  const t = Math.min(1, Math.max(0, (link.latency_ms - low) / (high - low)))
  if (t < 0.5) return lerpColor('#9ece6a', '#e0af68', t * 2)   // green → yellow
  return lerpColor('#e0af68', '#f7768e', (t - 0.5) * 2)         // yellow → red
}

/** Link color by type: spiral uses latency coloring, relay falls back to download. */
function linkColorByType(link) {
  // SPIRAL links carry real metrics now — color by latency like relay.
  if (link.link_type === 'spiral') {
    if (link.latency_ms && link.latency_ms > 0) return linkColorByLatency(link)
    return '#7aa2f7' // Blue for spiral without latency data
  }
  if (link.latency_ms && link.latency_ms > 0) return linkColorByLatency(link)
  return linkColorByDownload(link)
}

/** Link opacity by type: spiral prominent, proof dimmer, relay normal. */
function linkOpacityByType(link) {
  if (link.link_type === 'spiral') return 0.7
  if (link.link_type === 'proof') return 0.4
  return 0.5
}

/** Configure d3 forces for latency-proportional layout (PoLP).
 *  Link length reflects measured RTT: short = low latency, long = high latency.
 *  Strong charge repulsion prevents nodes from bunching up on LAN. */
function configureForces(g) {
  // Charge: strong repulsion so LAN nodes don't collapse into a dot.
  const charge = g.d3Force('charge')
  if (charge && charge.strength) {
    charge.strength(-300)
    charge.distanceMax(800)
  }

  // Link distance: log-scaled from RTT so sub-ms LAN links still spread out.
  const linkForce = g.d3Force('link')
  if (linkForce && linkForce.distance) {
    linkForce.distance(link => {
      if (link.latency_ms && link.latency_ms > 0) {
        // Log scale: 0.1ms → 80px, 1ms → 120px, 10ms → 160px, 100ms → 200px, 1000ms → 240px
        return 80 + 40 * Math.log10(Math.max(0.1, link.latency_ms))
      }
      return 150 // Default for links without latency data
    })
  }
}

// ---------------------------------------------------------------------------
// Graph initialization
// ---------------------------------------------------------------------------

async function try3D() {
  let ForceGraph3D, THREE
  try {
    const [fg, three] = await Promise.all([
      import('3d-force-graph'),
      import('three'),
    ])
    ForceGraph3D = fg.default
    THREE = three
  } catch {
    return false
  }

  try {
    if (!container.value) return false
    const g = ForceGraph3D({
      rendererConfig: { antialias: true, alpha: false },
    })(container.value)

    g.backgroundColor(COLORS.background)
      .nodeLabel(node => {
        const label = nodeLabel(node)
        if (node.node_type === 'browser') return label
        return `${label}\n${node.mesh_key.substring(0, 16)}...`
      })
      .nodeColor(nodeColor)
      .nodeVal(node => node.is_self ? 4 : node.node_type === 'browser' ? 1 : 2)
      .nodeOpacity(0.9)
      .nodeVisibility(() => showNodes)
      .linkVisibility(() => showBeams)
      .linkColor(linkColorByType)
      .linkOpacity(linkOpacityByType)
      .linkWidth(linkWidthByType)
      .linkLabel(linkTooltip)
      .nodeThreeObject(node => {
        const group = new THREE.Group()
        const isBrowser = node.node_type === 'browser'
        const size = node.is_self ? 6 : isBrowser ? 2.5 : 4
        const geo = new THREE.SphereGeometry(size, 16, 16)
        const color = nodeColor(node)
        const mat = new THREE.MeshLambertMaterial({ color, transparent: true, opacity: 0.9 })
        group.add(new THREE.Mesh(geo, mat))

        // Text sprite for label.
        const canvas = document.createElement('canvas')
        const ctx = canvas.getContext('2d')
        canvas.width = 512
        canvas.height = 64
        ctx.font = isBrowser ? '20px monospace' : '22px monospace'
        ctx.fillStyle = COLORS.text
        ctx.textAlign = 'center'
        ctx.fillText(nodeLabel(node), 256, 28)
        if (!isBrowser) {
          ctx.font = '14px monospace'
          ctx.fillStyle = '#565f89'
          ctx.fillText(node.mesh_key.substring(5, 21) + '...', 256, 52)
        }

        const texture = new THREE.CanvasTexture(canvas)
        const spriteMat = new THREE.SpriteMaterial({ map: texture, transparent: true })
        const sprite = new THREE.Sprite(spriteMat)
        sprite.scale.set(isBrowser ? 40 : 60, 10, 1)
        sprite.position.y = size + 8
        group.add(sprite)
        return group
      })
      .linkDirectionalParticles(link => (link.link_type === 'relay' || link.link_type === 'spiral') ? 2 : 0)
      .linkDirectionalParticleSpeed(link => {
        if (link.latency_ms && link.latency_ms > 0) {
          return Math.max(0.001, 0.02 / Math.max(1, link.latency_ms / 10))
        }
        return 0.005
      })
      .linkDirectionalParticleWidth(1.5)
      .linkDirectionalParticleColor(link => linkColorByType(link))
      .onNodeHover((node, prevNode) => {
        onNodeHover(node)
        if (container.value) container.value.style.cursor = node ? 'pointer' : 'default'
      })

    // Force layout: repulsion + latency-proportional link distance.
    configureForces(g)

    graph = g
    mode.value = '3d'
    return true
  } catch {
    // WebGL renderer or Three.js init failed — clean up partial state.
    if (container.value) container.value.innerHTML = ''
    return false
  }
}

async function try2D() {
  let ForceGraph
  try {
    const fg = await import('force-graph')
    ForceGraph = fg.default
  } catch {
    return false
  }

  if (!container.value) return false
  const g = ForceGraph()(container.value)

  g.backgroundColor(COLORS.background)
    .nodeLabel(node => {
      const label = nodeLabel(node)
      if (node.node_type === 'browser') return label
      return `${label}\n${node.mesh_key.substring(0, 16)}...`
    })
    .nodeColor(nodeColor)
    .nodeVal(node => node.is_self ? 6 : node.node_type === 'browser' ? 1.5 : 3)
    .nodeVisibility(() => showNodes)
    .linkVisibility(() => showBeams)
    .linkColor(linkColorByType)
    .linkWidth(linkWidthByType)
    .linkLabel(linkTooltip)
    .nodeCanvasObject((node, ctx, globalScale) => {
      const isBrowser = node.node_type === 'browser'
      const size = node.is_self ? 8 : isBrowser ? 3 : 5
      const color = nodeColor(node)

      // Filled circle.
      ctx.beginPath()
      ctx.arc(node.x, node.y, size, 0, 2 * Math.PI)
      ctx.fillStyle = color
      ctx.globalAlpha = isBrowser ? 0.8 : 0.9
      ctx.fill()
      ctx.globalAlpha = 1

      // Glow ring for self node.
      if (node.is_self) {
        ctx.strokeStyle = color
        ctx.lineWidth = 1.5
        ctx.stroke()
      }

      // Label.
      const label = nodeLabel(node)
      const fontSize = Math.max((isBrowser ? 10 : 12) / globalScale, 3)
      ctx.font = `${fontSize}px monospace`
      ctx.textAlign = 'center'
      ctx.textBaseline = 'top'
      ctx.fillStyle = COLORS.text
      ctx.fillText(label, node.x, node.y + size + 2)

      // Truncated lens ID (servers only).
      if (!isBrowser) {
        const smallSize = Math.max(9 / globalScale, 2)
        ctx.font = `${smallSize}px monospace`
        ctx.fillStyle = '#565f89'
        ctx.fillText(node.mesh_key.substring(5, 21) + '...', node.x, node.y + size + 2 + fontSize + 1)
      }
    })
    .nodePointerAreaPaint((node, color, ctx) => {
      const isBrowser = node.node_type === 'browser'
      const size = node.is_self ? 8 : isBrowser ? 3 : 5
      ctx.beginPath()
      ctx.arc(node.x, node.y, size + 4, 0, 2 * Math.PI)
      ctx.fillStyle = color
      ctx.fill()
    })
    .linkDirectionalParticles(link => (link.link_type === 'relay' || link.link_type === 'spiral') ? 2 : 0)
    .linkDirectionalParticleSpeed(link => {
      if (link.latency_ms && link.latency_ms > 0) {
        return Math.max(0.001, 0.02 / Math.max(1, link.latency_ms / 10))
      }
      return 0.005
    })
    .linkDirectionalParticleWidth(1.5)
    .linkDirectionalParticleColor(link => linkColorByType(link))
    .onNodeHover((node, prevNode) => {
      onNodeHover(node)
      if (container.value) container.value.style.cursor = node ? 'pointer' : 'default'
    })

  // Latency-based link distance.
  configureForces(g)

  graph = g
  mode.value = '2d'
  return true
}

async function initGraph() {
  if (!container.value) return

  // Ensure the container has dimensions.
  await nextTick()
  if (!container.value || container.value.clientWidth === 0) return

  // Try 3D (WebGL) first, fall back to 2D (Canvas2D).
  if (await try3D()) return
  if (await try2D()) return

  mode.value = 'error'
}

function updateGraph(snapshot) {
  // Update stats from snapshot.
  const serverNodes = snapshot.nodes.filter(n => (n.node_type || 'server') === 'server')
  const connCount = serverNodes.filter(n => n.connected || n.is_self).length
  const spiralCount = snapshot.links.filter(l => l.link_type === 'spiral').length
  stats.value = {
    nodes: serverNodes.length,
    connected: connCount,
    disconnected: serverNodes.length - connCount,
    links: snapshot.links.length,
    spiralLinks: spiralCount,
  }

  if (!graph) return

  const current = graph.graphData()
  const currentNodeMap = new Map(current.nodes.map(n => [n.id, n]))

  // Build a link key for identity comparison.
  // force-graph mutates source/target from string IDs to node object refs
  // after the first graphData() call, so we must handle both forms.
  const linkKey = l => {
    const s = typeof l.source === 'object' ? l.source.id : l.source
    const t = typeof l.target === 'object' ? l.target.id : l.target
    return `${s}\0${t}`
  }
  const currentLinkMap = new Map(current.links.map(l => [linkKey(l), l]))

  // Incoming node/link sets.
  const incomingNodeIds = new Set(snapshot.nodes.map(n => n.mesh_key))
  const incomingLinks = snapshot.links.map(l => ({
    source: l.source,
    target: l.target,
    upload_bps: l.upload_bps || 0,
    download_bps: l.download_bps || 0,
    latency_ms: l.latency_ms || null,
    link_type: l.link_type || 'relay',
  }))
  const incomingLinkKeys = new Set(incomingLinks.map(l => `${l.source}\0${l.target}`))

  let structureChanged = false

  // --- Update or add nodes ---
  for (const n of snapshot.nodes) {
    const existing = currentNodeMap.get(n.mesh_key)
    if (existing) {
      // Mutate in-place — no simulation reset.
      existing.server_name = n.server_name
      existing.mesh_key = n.mesh_key
      existing.is_self = n.is_self
      existing.connected = n.connected
      existing.node_type = n.node_type || 'server'
      existing.node_name = n.node_name || ''
      existing.site_name = n.site_name || ''
      existing.ygg_addr = n.ygg_addr || null
      existing.vdf_resonance_credit = n.vdf_resonance_credit ?? null
      existing.spiral_index = n.spiral_index ?? null
      existing.is_spiral_neighbor = n.is_spiral_neighbor || false

      existing.vdf_step = n.vdf_step ?? null
      existing.peer_count = n.peer_count ?? null
      existing.connected_count = n.connected_count ?? null
      existing.ygg_up_count = n.ygg_up_count ?? null
      existing.disconnected_count = n.disconnected_count ?? null
      updateVdfLiveness(existing)
    } else {
      // New node — must rebuild.
      structureChanged = true
    }
  }

  // Check for removed nodes.
  if (current.nodes.length !== incomingNodeIds.size) {
    structureChanged = true
  }
  for (const node of current.nodes) {
    if (!incomingNodeIds.has(node.id)) {
      structureChanged = true
      break
    }
  }

  // --- Update or add links ---
  for (const l of incomingLinks) {
    const key = `${l.source}\0${l.target}`
    const existing = currentLinkMap.get(key)
    if (existing) {
      // Mutate metrics in-place — accessor functions pick up changes per-frame.
      existing.upload_bps = l.upload_bps
      existing.download_bps = l.download_bps
      existing.latency_ms = l.latency_ms
      existing.link_type = l.link_type
    } else {
      structureChanged = true
    }
  }

  // Check for removed links.
  if (current.links.length !== incomingLinks.length) {
    structureChanged = true
  }
  for (const link of current.links) {
    if (!incomingLinkKeys.has(linkKey(link))) {
      structureChanged = true
      break
    }
  }

  // Only call graphData() when topology structure changed (add/remove).
  // This avoids resetting d3 simulation alpha, preventing the re-heat glitch.
  if (structureChanged) {
    const nodes = snapshot.nodes.map(n => {
      // Preserve existing position for nodes that already exist.
      const prev = currentNodeMap.get(n.mesh_key)
      const base = {
        id: n.mesh_key,
        server_name: n.server_name,
        mesh_key: n.mesh_key,
        is_self: n.is_self,
        connected: n.connected,
        node_type: n.node_type || 'server',
        node_name: n.node_name || '',
        site_name: n.site_name || '',
        ygg_addr: n.ygg_addr || null,
        vdf_resonance_credit: n.vdf_resonance_credit ?? null,
        spiral_index: n.spiral_index ?? null,
        is_spiral_neighbor: n.is_spiral_neighbor || false,

        vdf_step: n.vdf_step ?? null,
        peer_count: n.peer_count ?? null,
        connected_count: n.connected_count ?? null,
        ygg_up_count: n.ygg_up_count ?? null,
        disconnected_count: n.disconnected_count ?? null,
      }
      updateVdfLiveness(base)
      // Preserve previous position so d3 doesn't reset the simulation.
      if (prev) {
        base.x = prev.x
        base.y = prev.y
        base.z = prev.z
        base.vx = prev.vx
        base.vy = prev.vy
        base.vz = prev.vz
      }
      return base
    })

    graph.graphData({ nodes, links: incomingLinks })
    configureForces(graph)
  }
}

function connectWs() {
  const url = new URL(props.serverUrl || window.location.origin)
  const proto = url.protocol === 'https:' ? 'wss:' : 'ws:'
  ws = new WebSocket(`${proto}//${url.host}/api/topology/ws`)

  ws.onmessage = (event) => {
    const snapshot = JSON.parse(event.data)
    updateGraph(snapshot)
  }

  ws.onclose = () => {
    // WebSocket closed — topology no longer updating.
  }
}

let resizeObserver = null

/** Re-apply visibility accessors after a toggle. No simulation reset. */
function refreshGraph() {
  if (!graph) return
  graph.nodeVisibility(() => showNodes)
  graph.linkVisibility(() => showBeams)
}

function onKeyDown(event) {
  // Ignore if typing in an input/textarea.
  if (event.target.tagName === 'INPUT' || event.target.tagName === 'TEXTAREA') return
  if (event.key === 'b' || event.key === 'B') {
    showBeams = !showBeams
    refreshGraph()
  } else if (event.key === 'n' || event.key === 'N') {
    showNodes = !showNodes
    refreshGraph()
  }
}

onMounted(async () => {
  await initGraph()
  if (graph && container.value) {
    resizeObserver = new ResizeObserver(() => {
      if (container.value && graph) {
        graph.width(container.value.clientWidth)
        graph.height(container.value.clientHeight)
      }
    })
    resizeObserver.observe(container.value)
  }
  connectWs()
  window.addEventListener('keydown', onKeyDown)
  window.addEventListener('mousemove', onMouseMove)
})

onUnmounted(() => {
  window.removeEventListener('keydown', onKeyDown)
  window.removeEventListener('mousemove', onMouseMove)
  if (ws) ws.close()
  if (resizeObserver) resizeObserver.disconnect()
  if (graph) graph._destructor?.()
})
</script>

<template>
  <div v-if="mode === 'error'" class="topology-fallback">
    <div class="fallback-content">
      <p>Could not initialize graph renderer.</p>
    </div>
  </div>
  <div v-else class="topology-container" ref="container"></div>

  <!-- Mesh stats overlay -->
  <div v-if="stats.nodes > 0" class="stats-panel">
    <div class="stats-row">
      <span class="stats-value">{{ stats.nodes }}</span>
      <span class="stats-label">nodes</span>
    </div>
    <div class="stats-row">
      <span class="stats-value status-up">{{ stats.connected }}</span>
      <span class="stats-label">connected</span>
    </div>
    <div v-if="stats.disconnected > 0" class="stats-row">
      <span class="stats-value status-down">{{ stats.disconnected }}</span>
      <span class="stats-label">disconnected</span>
    </div>
    <div class="stats-row">
      <span class="stats-value">{{ stats.links }}</span>
      <span class="stats-label">links</span>
    </div>
    <div v-if="stats.spiralLinks > 0" class="stats-row">
      <span class="stats-value spiral-tag">{{ stats.spiralLinks }}</span>
      <span class="stats-label">SPIRAL</span>
    </div>
  </div>

  <!-- Node hover info panel -->
  <div
    v-if="hoveredNode"
    class="node-panel"
    :style="{ left: panelPos.x + 'px', top: panelPos.y + 'px' }"
  >
    <div class="panel-header">
      <span class="panel-name">{{ hoveredNode.server_name }}</span>
      <span v-if="hoveredNode.node_name && hoveredNode.node_name !== hoveredNode.server_name" class="panel-pod">({{ hoveredNode.node_name }})</span>
    </div>
    <div class="panel-row">
      <span class="panel-label">Mesh Key</span>
      <span class="panel-value mono">{{ hoveredNode.mesh_key?.substring(0, 24) }}...</span>
    </div>
    <div v-if="hoveredNode.ygg_addr" class="panel-row">
      <span class="panel-label">Ygg Address</span>
      <span class="panel-value mono">{{ hoveredNode.ygg_addr }}</span>
    </div>
    <div v-if="hoveredNode.spiral_index != null" class="panel-row">
      <span class="panel-label">SPIRAL Slot</span>
      <span class="panel-value">#{{ hoveredNode.spiral_index }}</span>
    </div>
    <div v-if="hoveredNode.vdf_resonance_credit != null" class="panel-row">
      <span class="panel-label">VDF Credit</span>
      <span class="panel-value" :class="hoveredNode.vdf_resonance_credit > 0.99 ? 'credit-good' : hoveredNode.vdf_resonance_credit > 0.5 ? 'credit-ok' : 'credit-bad'">
        {{ (hoveredNode.vdf_resonance_credit * 100).toFixed(4) }}%
      </span>
    </div>
    <div class="panel-row">
      <span class="panel-label">Status</span>
      <span class="panel-value" :class="hoveredNode.connected ? 'status-up' : 'status-down'">
        {{ hoveredNode.is_self ? 'self' : hoveredNode.connected ? 'connected' : 'disconnected' }}
      </span>
    </div>
    <div v-if="hoveredNode.is_spiral_neighbor" class="panel-row">
      <span class="panel-label">Relation</span>
      <span class="panel-value spiral-tag">SPIRAL neighbor</span>
    </div>
    <!-- VDF liveness (the actual heartbeat) -->
    <div v-if="hoveredNode.vdf_step != null" class="panel-row">
      <span class="panel-label">VDF Step</span>
      <span class="panel-value">{{ hoveredNode.vdf_step.toLocaleString() }}</span>
    </div>
    <div v-if="!hoveredNode.is_self && vdfLiveness(hoveredNode) != null" class="panel-row">
      <span class="panel-label">VDF Heartbeat</span>
      <span class="panel-value" :class="vdfLiveness(hoveredNode) === 'ticking' ? 'status-up' : 'status-down'">
        {{ vdfLiveness(hoveredNode) === 'ticking' ? 'ticking' : 'STALLED — eject' }}
      </span>
    </div>
    <!-- Self node peer stats -->
    <div v-if="hoveredNode.peer_count != null" class="panel-section">
      <div class="panel-divider"></div>
      <div class="panel-row">
        <span class="panel-label">Peers Known</span>
        <span class="panel-value">{{ hoveredNode.peer_count }}</span>
      </div>
      <div class="panel-row">
        <span class="panel-label">Relays Up</span>
        <span class="panel-value status-up">{{ hoveredNode.connected_count }}</span>
      </div>
      <div v-if="hoveredNode.ygg_up_count != null" class="panel-row">
        <span class="panel-label">Ygg Overlay</span>
        <span class="panel-value" :class="hoveredNode.ygg_up_count > 0 ? 'status-up' : 'status-down'">
          {{ hoveredNode.ygg_up_count }} up
        </span>
      </div>
      <div v-if="hoveredNode.disconnected_count > 0" class="panel-row">
        <span class="panel-label">Disconnected</span>
        <span class="panel-value status-down">{{ hoveredNode.disconnected_count }}</span>
      </div>
    </div>
    <!-- Link count from graph (all nodes) -->
    <div class="panel-row">
      <span class="panel-label">Graph Links</span>
      <span class="panel-value">{{ countNodeLinks(hoveredNode.id || hoveredNode.mesh_key).total }}</span>
    </div>
  </div>
</template>

<style scoped>
.topology-container {
  width: 100%;
  height: 100%;
  background: #1a1b26;
}

.topology-fallback {
  width: 100%;
  height: 100%;
  background: #1a1b26;
  display: flex;
  align-items: center;
  justify-content: center;
}

.fallback-content {
  text-align: center;
  color: #565f89;
  max-width: 400px;
  padding: 2rem;
}

.node-panel {
  position: fixed;
  z-index: 1000;
  background: #1f2335;
  border: 1px solid #3b4261;
  border-radius: 8px;
  padding: 12px 16px;
  min-width: 260px;
  max-width: 400px;
  pointer-events: none;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
  font-size: 12px;
  color: #c0caf5;
}

.panel-header {
  margin-bottom: 8px;
  padding-bottom: 6px;
  border-bottom: 1px solid #3b4261;
}

.panel-name {
  font-size: 14px;
  font-weight: 600;
  color: #7aa2f7;
}

.panel-pod {
  font-size: 12px;
  color: #565f89;
  margin-left: 6px;
}

.panel-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 2px 0;
  gap: 12px;
}

.panel-label {
  color: #565f89;
  white-space: nowrap;
}

.panel-value {
  color: #c0caf5;
  text-align: right;
}

.panel-value.mono {
  font-size: 11px;
  color: #a9b1d6;
}

.status-up { color: #9ece6a; }
.status-down { color: #f7768e; }
.credit-good { color: #9ece6a; }
.credit-ok { color: #e0af68; }
.credit-bad { color: #f7768e; }
.spiral-tag { color: #7aa2f7; }

.panel-divider {
  height: 1px;
  background: #3b4261;
  margin: 6px 0;
}

.stats-panel {
  position: fixed;
  top: 16px;
  left: 16px;
  z-index: 900;
  background: rgba(31, 35, 53, 0.85);
  border: 1px solid #3b4261;
  border-radius: 8px;
  padding: 10px 14px;
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
  font-size: 13px;
  color: #c0caf5;
  backdrop-filter: blur(8px);
  pointer-events: none;
}

.stats-row {
  display: flex;
  align-items: baseline;
  gap: 6px;
  padding: 1px 0;
}

.stats-value {
  font-weight: 700;
  font-size: 15px;
  min-width: 28px;
  text-align: right;
}

.stats-label {
  color: #565f89;
  font-size: 12px;
}
</style>
