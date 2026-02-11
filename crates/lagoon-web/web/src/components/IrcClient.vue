<script setup>
import { ref, computed, watch, nextTick } from 'vue'
import NetworkTopology from './NetworkTopology.vue'

const props = defineProps({
  connection: Object,
  community: Object,
  activeCommunity: Object,
})
const emit = defineEmits(['logout'])

const viewMode = ref('chat')
const inputText = ref('')
const messagesEl = ref(null)
const contextMenu = ref(null) // { x, y, user }

// Access connection state via computed to guarantee Vue reactivity tracking.
const conn = computed(() => props.connection)
const connected = computed(() => conn.value.connected.value)
const status = computed(() => conn.value.status.value)
const username = computed(() => conn.value.username.value)
const communityName = computed(() => conn.value.communityName.value)
const channels = computed(() => conn.value.channels)
const serverMessages = computed(() => conn.value.serverMessages)
const activeChannel = computed({
  get: () => conn.value.activeChannel.value,
  set: (v) => { conn.value.activeChannel.value = v },
})

const currentChannel = computed(() => {
  if (!activeChannel.value) return null
  return channels.value.get(activeChannel.value) || null
})

const channelList = computed(() => {
  const allChannels = [...channels.value.keys()]
  if (props.activeCommunity?.channels?.length) {
    const communitySet = new Set(props.activeCommunity.channels)
    // Community channels first, then any other channels the user has joined.
    const inCommunity = allChannels.filter(ch => communitySet.has(ch))
    const other = allChannels.filter(ch => !communitySet.has(ch))
    return ['Server', ...inCommunity, ...other]
  }
  return ['Server', ...allChannels]
})

const displayMessages = computed(() => {
  if (activeChannel.value === 'Server' || !activeChannel.value) {
    return serverMessages.value
  }
  return currentChannel.value?.messages || []
})

const displayName = computed(() => {
  if (props.activeCommunity?.name) return props.activeCommunity.name
  return communityName.value || props.community?.name || hostFromUrl(props.community?.url) || 'Lagoon'
})

function hostFromUrl(url) {
  if (!url) return ''
  try {
    return new URL(url).hostname
  } catch {
    return url
  }
}

function scrollToBottom() {
  nextTick(() => {
    if (messagesEl.value) {
      messagesEl.value.scrollTop = messagesEl.value.scrollHeight
    }
  })
}

watch(displayMessages, scrollToBottom, { deep: true })
watch(activeChannel, scrollToBottom)

function sendMessage() {
  const text = inputText.value.trim()
  if (!text) return
  inputText.value = ''
  props.connection.sendMessage(text)
}

function openUserMenu(event, user) {
  const bareNick = user.replace(/^[~&@%+]/, '')
  contextMenu.value = { x: event.clientX, y: event.clientY, user: bareNick }
}

function closeUserMenu() {
  contextMenu.value = null
}

function selectChannel(name) {
  viewMode.value = 'chat'
  conn.value.activeChannel.value = name
}

function startDm(nick) {
  contextMenu.value = null
  props.connection.ensureChannel(nick)
  conn.value.activeChannel.value = nick
}
</script>

<template>
  <div class="irc-layout">
    <!-- Channel sidebar -->
    <div class="sidebar">
      <div class="sidebar-header">
        <div class="header-info">
          <span class="community-name">{{ displayName }}</span>
          <span class="username-label">{{ username }}</span>
        </div>
        <button class="logout-btn" @click="$emit('logout')" title="Leave community">x</button>
      </div>
      <div v-if="!connected" class="status-bar">
        {{ status }}
      </div>
      <div class="channel-list">
        <div
          v-for="name in channelList"
          :key="name"
          class="channel-item"
          :class="{ active: viewMode === 'chat' && (activeChannel === name || (name === 'Server' && !activeChannel)) }"
          @click="selectChannel(name)"
        >
          {{ name }}
        </div>
        <div class="channel-separator"></div>
        <div
          class="channel-item mesh-item"
          :class="{ active: viewMode === 'mesh' }"
          @click="viewMode = 'mesh'"
        >
          Mesh Network
        </div>
      </div>
    </div>

    <!-- Main area: Chat view -->
    <template v-if="viewMode === 'chat'">
      <div class="main">
        <!-- Topic bar -->
        <div class="topic-bar" v-if="currentChannel?.topic">
          {{ currentChannel.topic }}
        </div>

        <!-- Messages -->
        <div class="messages" ref="messagesEl">
          <div
            v-for="(msg, i) in displayMessages"
            :key="i"
            class="message"
            :class="msg.type"
          >
            <span class="time">{{ msg.time }}</span>
            <span v-if="msg.type === 'msg'" class="nick" :class="{ self: msg.nick === username }">
              &lt;{{ msg.nick }}&gt;
            </span>
            <span v-else-if="msg.type === 'event'" class="event-nick">
              {{ msg.nick }}
            </span>
            <span v-else class="server-prefix">***</span>
            <span class="text">{{ msg.text }}</span>
          </div>
        </div>

        <!-- Input -->
        <div class="input-bar">
          <input
            v-model="inputText"
            @keydown.enter="sendMessage"
            :placeholder="activeChannel && activeChannel !== 'Server' ? `Message ${activeChannel}` : 'Type a command...'"
          />
        </div>
      </div>

      <!-- User list -->
      <div class="userlist" v-if="currentChannel?.users?.length">
        <div class="userlist-header">Users ({{ currentChannel.users.length }})</div>
        <div
          v-for="user in currentChannel.users"
          :key="user"
          class="user-item"
          @contextmenu.prevent="openUserMenu($event, user)"
        >
          {{ user }}
        </div>
      </div>

      <!-- User context menu -->
      <Teleport to="body">
        <div
          v-if="contextMenu"
          class="context-menu"
          :style="{ left: contextMenu.x + 'px', top: contextMenu.y + 'px' }"
          @click.stop
        >
          <div class="context-menu-header">{{ contextMenu.user }}</div>
          <div class="context-menu-item" @click="startDm(contextMenu.user)">Send Message</div>
          <div class="context-menu-item" @click="closeUserMenu">Cancel</div>
        </div>
        <div v-if="contextMenu" class="context-menu-overlay" @click="closeUserMenu" @contextmenu.prevent="closeUserMenu"></div>
      </Teleport>
    </template>

    <!-- Main area: Mesh Network view -->
    <div v-else class="main mesh-view">
      <NetworkTopology :serverUrl="community?.url || ''" />
    </div>
  </div>
</template>

<style scoped>
.irc-layout {
  display: flex;
  flex: 1;
  height: 100vh;
  overflow: hidden;
}

.sidebar {
  width: 220px;
  background: var(--bg-secondary);
  border-right: 1px solid var(--bg-tertiary);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
}

.sidebar-header {
  padding: 0.75rem 1rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--bg-tertiary);
}

.header-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.community-name {
  color: var(--accent);
  font-weight: bold;
  font-size: 0.95rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.username-label {
  color: var(--text-secondary);
  font-size: 0.75rem;
}

.logout-btn {
  background: none;
  border: none;
  color: var(--text-secondary);
  cursor: pointer;
  font-family: inherit;
  font-size: 1rem;
  flex-shrink: 0;
}

.logout-btn:hover {
  color: var(--accent-red);
}

.status-bar {
  padding: 0.5rem 1rem;
  font-size: 0.75rem;
  color: var(--accent-red);
  border-bottom: 1px solid var(--bg-tertiary);
}

.channel-list {
  flex: 1;
  overflow-y: auto;
}

.channel-item {
  padding: 0.5rem 1rem;
  cursor: pointer;
  color: var(--text-secondary);
}

.channel-item:hover {
  background: var(--bg-tertiary);
}

.channel-item.active {
  color: var(--text-primary);
  background: var(--bg-tertiary);
  border-left: 2px solid var(--accent);
}

.channel-separator {
  height: 1px;
  background: var(--bg-tertiary);
  margin: 0.5rem 1rem;
}

.mesh-item {
  color: var(--accent-cyan);
}

.mesh-view {
  display: flex;
  flex: 1;
}

.main {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.topic-bar {
  padding: 0.5rem 1rem;
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--bg-tertiary);
  font-size: 0.85rem;
  color: var(--text-secondary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.messages {
  flex: 1;
  overflow-y: auto;
  padding: 0.5rem 1rem;
}

.message {
  padding: 2px 0;
  line-height: 1.4;
}

.time {
  color: var(--text-secondary);
  margin-right: 0.5rem;
  font-size: 0.8rem;
}

.nick {
  color: var(--accent-cyan);
  margin-right: 0.25rem;
}

.nick.self {
  color: var(--accent);
}

.event-nick {
  color: var(--accent-yellow);
  margin-right: 0.25rem;
}

.server-prefix {
  color: var(--accent-green);
  margin-right: 0.25rem;
}

.message.event {
  color: var(--text-secondary);
  font-style: italic;
}

.message.server {
  color: var(--text-secondary);
  font-size: 0.85rem;
}

.text {
  word-break: break-word;
}

.input-bar {
  padding: 0.75rem;
  border-top: 1px solid var(--bg-tertiary);
}

.input-bar input {
  width: 100%;
  background: var(--bg-secondary);
  border: 1px solid var(--bg-tertiary);
  border-radius: 6px;
  padding: 0.75rem 1rem;
  color: var(--text-primary);
  font-family: inherit;
  font-size: 0.9rem;
  outline: none;
}

.input-bar input:focus {
  border-color: var(--accent);
}

.userlist {
  width: 160px;
  background: var(--bg-secondary);
  border-left: 1px solid var(--bg-tertiary);
  flex-shrink: 0;
  overflow-y: auto;
}

.userlist-header {
  padding: 0.75rem 1rem;
  font-size: 0.8rem;
  color: var(--text-secondary);
  border-bottom: 1px solid var(--bg-tertiary);
}

.user-item {
  padding: 0.25rem 1rem;
  font-size: 0.85rem;
  color: var(--text-secondary);
  cursor: pointer;
}

.user-item:hover {
  color: var(--text-primary);
  background: var(--bg-tertiary);
}
</style>

<style>
.context-menu-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  z-index: 999;
}

.context-menu {
  position: fixed;
  z-index: 1000;
  background: var(--bg-secondary);
  border: 1px solid var(--bg-tertiary);
  border-radius: 6px;
  padding: 4px 0;
  min-width: 160px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
}

.context-menu-header {
  padding: 6px 12px;
  font-size: 0.8rem;
  color: var(--text-secondary);
  border-bottom: 1px solid var(--bg-tertiary);
  margin-bottom: 2px;
}

.context-menu-item {
  padding: 6px 12px;
  font-size: 0.85rem;
  color: var(--text-primary);
  cursor: pointer;
}

.context-menu-item:hover {
  background: var(--accent);
  color: var(--bg-primary);
}
</style>
