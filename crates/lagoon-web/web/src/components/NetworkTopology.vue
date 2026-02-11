<script setup>
import { ref, onMounted, onUnmounted, nextTick } from 'vue'

const props = defineProps({
  serverUrl: String,
})

const container = ref(null)
const mode = ref('') // '3d', '2d', or '' (loading)
let graph = null
let ws = null
let showBeams = true
let showNodes = true

// Color palette — Tokyo Night theme.
const COLORS = {
  self: '#7aa2f7',       // Blue — this node
  connected: '#9ece6a',  // Green — connected peer
  offline: '#f7768e',    // Red — known but not connected
  browser: '#bb9af7',    // Purple — browser/web peer
  link: '#565f89',       // Muted — default link color (no metrics)
  background: '#1a1b26', // Dark background
  text: '#c0caf5',       // Light text
}

function nodeColor(node) {
  if (node.node_type === 'browser') return COLORS.browser
  if (node.is_self) return COLORS.self
  if (node.connected) return COLORS.connected
  return COLORS.offline
}

function nodeLabel(node) {
  if (node.node_type === 'browser') return node.lens_id.replace('web/', '')
  return node.server_name
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

/** Link width by type: thin structural for spiral, metric-based for relay. */
function linkWidthByType(link) {
  if (link.link_type === 'spiral') return 0.8
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

/** Link color by type: very muted for spiral, latency-based for relay. */
function linkColorByType(link) {
  if (link.link_type === 'spiral') return '#3b4261'
  // Prefer latency color for relay links; fall back to download-based.
  if (link.latency_ms && link.latency_ms > 0) return linkColorByLatency(link)
  return linkColorByDownload(link)
}

/** Link opacity by type: faint for spiral, dimmer for proof, normal for relay. */
function linkOpacityByType(link) {
  if (link.link_type === 'spiral') return 0.3
  if (link.link_type === 'proof') return 0.4
  return 0.6
}

/** Configure d3 link force distance based on latency (PoLP).
 *  Link length reflects measured RTT: short = low latency, long = high latency. */
function configureLinkDistance(g) {
  const linkForce = g.d3Force('link')
  if (linkForce && linkForce.distance) {
    linkForce.distance(link => {
      if (link.latency_ms && link.latency_ms > 0) {
        // Scale: 1ms → 30px, 500ms → 500px
        return Math.max(30, Math.min(500, link.latency_ms))
      }
      return 100 // Default for links without latency data
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
        return `${label}\n${node.lens_id.substring(0, 16)}...`
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
        canvas.width = 256
        canvas.height = 64
        ctx.font = isBrowser ? '20px monospace' : '24px monospace'
        ctx.fillStyle = COLORS.text
        ctx.textAlign = 'center'
        ctx.fillText(nodeLabel(node), 128, 28)
        if (!isBrowser) {
          ctx.font = '14px monospace'
          ctx.fillStyle = '#565f89'
          ctx.fillText(node.lens_id.substring(5, 21) + '...', 128, 52)
        }

        const texture = new THREE.CanvasTexture(canvas)
        const spriteMat = new THREE.SpriteMaterial({ map: texture, transparent: true })
        const sprite = new THREE.Sprite(spriteMat)
        sprite.scale.set(isBrowser ? 30 : 40, 10, 1)
        sprite.position.y = size + 8
        group.add(sprite)
        return group
      })
      .linkDirectionalParticles(link => link.link_type === 'relay' ? 2 : 0)
      .linkDirectionalParticleSpeed(link => {
        if (link.latency_ms && link.latency_ms > 0) {
          return Math.max(0.001, 0.02 / Math.max(1, link.latency_ms / 10))
        }
        return 0.005
      })
      .linkDirectionalParticleWidth(1.5)
      .linkDirectionalParticleColor(link => linkColorByType(link))

    // Latency-based link distance.
    configureLinkDistance(g)

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
      return `${label}\n${node.lens_id.substring(0, 16)}...`
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
        ctx.fillText(node.lens_id.substring(5, 21) + '...', node.x, node.y + size + 2 + fontSize + 1)
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
    .linkDirectionalParticles(link => link.link_type === 'relay' ? 2 : 0)
    .linkDirectionalParticleSpeed(link => {
      if (link.latency_ms && link.latency_ms > 0) {
        return Math.max(0.001, 0.02 / Math.max(1, link.latency_ms / 10))
      }
      return 0.005
    })
    .linkDirectionalParticleWidth(1.5)
    .linkDirectionalParticleColor(link => linkColorByType(link))

  // Latency-based link distance.
  configureLinkDistance(g)

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
  const incomingNodeIds = new Set(snapshot.nodes.map(n => n.lens_id))
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
    const existing = currentNodeMap.get(n.lens_id)
    if (existing) {
      // Mutate in-place — no simulation reset.
      existing.server_name = n.server_name
      existing.lens_id = n.lens_id
      existing.is_self = n.is_self
      existing.connected = n.connected
      existing.node_type = n.node_type || 'server'
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
      const prev = currentNodeMap.get(n.lens_id)
      const base = {
        id: n.lens_id,
        server_name: n.server_name,
        lens_id: n.lens_id,
        is_self: n.is_self,
        connected: n.connected,
        node_type: n.node_type || 'server',
      }
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
    configureLinkDistance(graph)
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
})

onUnmounted(() => {
  window.removeEventListener('keydown', onKeyDown)
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
</style>
