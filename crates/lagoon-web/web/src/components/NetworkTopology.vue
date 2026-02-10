<script setup>
import { ref, onMounted, onUnmounted, nextTick } from 'vue'

const props = defineProps({
  serverUrl: String,
})

const container = ref(null)
const mode = ref('') // '3d', '2d', or '' (loading)
let graph = null
let ws = null

// Color palette — Tokyo Night theme.
const COLORS = {
  self: '#7aa2f7',       // Blue — this node
  connected: '#9ece6a',  // Green — connected peer
  offline: '#f7768e',    // Red — known but not connected
  browser: '#bb9af7',    // Purple — browser/web peer
  link: '#565f89',       // Muted — link color
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
      .linkColor(() => COLORS.link)
      .linkOpacity(0.6)
      .linkWidth(1.5)
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

  const g = ForceGraph()(container.value)

  g.backgroundColor(COLORS.background)
    .nodeLabel(node => {
      const label = nodeLabel(node)
      if (node.node_type === 'browser') return label
      return `${label}\n${node.lens_id.substring(0, 16)}...`
    })
    .nodeColor(nodeColor)
    .nodeVal(node => node.is_self ? 6 : node.node_type === 'browser' ? 1.5 : 3)
    .linkColor(() => COLORS.link)
    .linkWidth(2)
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

  const nodes = snapshot.nodes.map(n => ({
    id: n.lens_id,
    server_name: n.server_name,
    lens_id: n.lens_id,
    is_self: n.is_self,
    connected: n.connected,
    node_type: n.node_type || 'server',
  }))

  const links = snapshot.links.map(l => ({
    source: l.source,
    target: l.target,
  }))

  graph.graphData({ nodes, links })
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
})

onUnmounted(() => {
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
