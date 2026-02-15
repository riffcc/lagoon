<script setup>
import { ref, shallowRef, computed, watch } from 'vue'
import { useCommunities } from './composables/useCommunities.js'
import { createConnection } from './composables/useConnection.js'
import CommunitySidebar from './components/CommunitySidebar.vue'
import CommunityModal from './components/CommunityModal.vue'
import CircleModal from './components/CircleModal.vue'
import IrcClient from './components/IrcClient.vue'
import NetworkTopology from './components/NetworkTopology.vue'

// Public routes — rendered without authentication.
const isMapRoute = window.location.pathname === '/map'

// useCommunities manages server connections in localStorage.
const {
  communities: servers, activeCommunityId: activeServerId, activeCommunity: activeServer,
  addCommunity: addServer, removeCommunity: removeServer, updateCommunity: updateServer, setActive: setActiveServer,
} = useCommunities()

// Connection instances keyed by server ID.
const connections = new Map()
const activeConnection = shallowRef(null)

// Active community state.
const activeCommunityId = ref('')

const showServerModal = ref(false)
const showCommunityModal = ref(false)
const noServers = computed(() => servers.value.length === 0)
const activeUsername = computed(() => activeConnection.value?.username.value || '')

// Build community groups for the sidebar — communities grouped by server.
const communityGroups = computed(() => {
  const groups = []
  for (const server of servers.value) {
    const conn = connections.get(server.id)
    const communities = conn?.circles?.value || []
    groups.push({
      server: { id: server.id, name: server.name, url: server.url },
      communities,
    })
  }
  return groups
})

// Find the community object for the active community.
const activeCommunity = computed(() => {
  for (const group of communityGroups.value) {
    const found = group.communities.find(c => c.id === activeCommunityId.value)
    if (found) return found
  }
  return null
})

// When active server changes, disconnect old, connect new.
watch(activeServerId, (newId, oldId) => {
  if (oldId && connections.has(oldId)) {
    connections.get(oldId).disconnect()
  }

  if (newId) {
    const server = servers.value.find(c => c.id === newId)
    if (server) {
      if (!connections.has(newId)) {
        const conn = createConnection(server)
        // Only fires after all reconnect retries are exhausted.
        conn.onAuthFail(() => onLogout(newId))
        connections.set(newId, conn)
      }
      const conn = connections.get(newId)
      conn.connect()
      activeConnection.value = conn
    }
  } else {
    activeConnection.value = null
  }
}, { immediate: true })

// Update server name from NETWORK= token.
watch(
  () => activeConnection.value?.communityName.value,
  (name) => {
    if (name && activeServerId.value) {
      updateServer(activeServerId.value, { name })
    }
  },
)

// When communities load, auto-select the first one if nothing is selected.
// Watch communityGroups (a computed we control) for maximum reliability.
watch(communityGroups, (groups) => {
  if (activeCommunityId.value) return
  for (const g of groups) {
    if (g.communities.length) {
      activeCommunityId.value = g.communities[0].id
      break
    }
  }
}, { deep: true })

// When active community changes, join its IRC channels.
watch(activeCommunityId, () => {
  if (activeCommunity.value && activeConnection.value) {
    activeConnection.value.joinCircleChannels(activeCommunity.value)
  }
})

function onServerJoined(server) {
  addServer(server)
  setActiveServer(server.id)
  showServerModal.value = false
}

function onCommunityCreated(community) {
  showCommunityModal.value = false
  activeCommunityId.value = community.id
  if (activeConnection.value) {
    activeConnection.value.joinCircleChannels(community)
  }
}

function onSelectCommunity({ serverId, communityId }) {
  if (activeServerId.value !== serverId) {
    setActiveServer(serverId)
  }
  activeCommunityId.value = communityId
}

function onLogout(serverId) {
  if (connections.has(serverId)) {
    connections.get(serverId).disconnect()
    connections.delete(serverId)
  }
  removeServer(serverId)
  activeCommunityId.value = ''
}
</script>

<template>
  <!-- Public map route — no auth required -->
  <NetworkTopology v-if="isMapRoute" class="fullscreen-map" />

  <div v-else class="app">
    <!-- Welcome state: no servers → auth modal -->
    <CommunityModal
      v-if="noServers"
      :welcome="true"
      @joined="onServerJoined"
    />

    <!-- Normal state -->
    <template v-else>
      <CommunitySidebar
        :groups="communityGroups"
        :activeCommunityId="activeCommunityId"
        :username="activeUsername"
        @selectCommunity="onSelectCommunity"
        @addCommunity="showCommunityModal = true"
        @addServer="showServerModal = true"
      />
      <IrcClient
        v-if="activeConnection"
        :connection="activeConnection"
        :community="activeServer"
        :activeCommunity="activeCommunity"
        @logout="onLogout(activeServerId)"
      />
    </template>

    <!-- Add server modal -->
    <CommunityModal
      v-if="showServerModal && !noServers"
      @joined="onServerJoined"
      @close="showServerModal = false"
    />

    <!-- Create community modal -->
    <CircleModal
      v-if="showCommunityModal && activeConnection"
      :createCommunity="activeConnection.createCircle"
      @created="onCommunityCreated"
      @close="showCommunityModal = false"
    />
  </div>
</template>

<style>
:root {
  --bg-primary: #1a1b26;
  --bg-secondary: #24283b;
  --bg-tertiary: #414868;
  --text-primary: #c0caf5;
  --text-secondary: #565f89;
  --accent: #7aa2f7;
  --accent-green: #9ece6a;
  --accent-red: #f7768e;
  --accent-yellow: #e0af68;
  --accent-cyan: #7dcfff;
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  background: var(--bg-primary);
  color: var(--text-primary);
  font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
  font-size: 14px;
}

.app {
  height: 100vh;
  display: flex;
  flex-direction: row;
  overflow: hidden;
}

.fullscreen-map {
  width: 100vw;
  height: 100vh;
}
</style>
