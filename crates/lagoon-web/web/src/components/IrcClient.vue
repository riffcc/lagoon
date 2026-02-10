<script setup>
import { ref, reactive, computed, onMounted, onUnmounted, nextTick, watch } from 'vue'
import NetworkTopology from './NetworkTopology.vue'

const props = defineProps({
  token: String,
  username: String,
  serverUrl: String,
})
const emit = defineEmits(['logout'])

// View mode: 'chat' or 'mesh'.
const viewMode = ref('chat')

// Connection state.
const connected = ref(false)
const status = ref('Connecting...')
let ws = null

// IRC state.
const channels = reactive(new Map())   // name → { messages: [], users: [], topic: '' }
const activeChannel = ref('')
const inputText = ref('')
const serverMessages = reactive([])    // messages not tied to a channel
const messagesEl = ref(null)

// Current channel data.
const currentChannel = computed(() => {
  if (!activeChannel.value) return null
  return channels.get(activeChannel.value) || null
})

const channelList = computed(() => {
  return ['Server', ...channels.keys()]
})

const displayMessages = computed(() => {
  if (activeChannel.value === 'Server' || !activeChannel.value) {
    return serverMessages
  }
  return currentChannel.value?.messages || []
})

function scrollToBottom() {
  nextTick(() => {
    if (messagesEl.value) {
      messagesEl.value.scrollTop = messagesEl.value.scrollHeight
    }
  })
}

watch(displayMessages, scrollToBottom, { deep: true })
watch(activeChannel, scrollToBottom)

function connect() {
  const url = new URL(props.serverUrl || window.location.origin)
  const proto = url.protocol === 'https:' ? 'wss:' : 'ws:'
  ws = new WebSocket(`${proto}//${url.host}/api/ws`)

  ws.onopen = () => {
    // Authenticate.
    ws.send(JSON.stringify({ type: 'auth', token: props.token }))
  }

  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data)
    handleServerMessage(msg)
  }

  ws.onclose = () => {
    connected.value = false
    status.value = 'Disconnected'
    addServerMessage('--- Disconnected from server ---')
  }

  ws.onerror = () => {
    status.value = 'Connection error'
  }
}

function handleServerMessage(msg) {
  switch (msg.type) {
    case 'auth_ok':
      status.value = `Authenticated as ${msg.username}`
      break

    case 'auth_fail':
      status.value = `Auth failed: ${msg.reason}`
      emit('logout')
      break

    case 'status':
      connected.value = msg.connected
      status.value = msg.message
      if (msg.connected) {
        // Auto-join #lagoon after connecting.
        sendIrc('JOIN #lagoon')
      }
      break

    case 'irc':
      parseIrcLine(msg.line)
      break
  }
}

function parseIrcLine(line) {
  // Parse IRC protocol line.
  let prefix = ''
  let command = ''
  let params = []

  let rest = line
  if (rest.startsWith(':')) {
    const spaceIdx = rest.indexOf(' ')
    prefix = rest.substring(1, spaceIdx)
    rest = rest.substring(spaceIdx + 1)
  }

  const trailingIdx = rest.indexOf(' :')
  let trailing = null
  if (trailingIdx >= 0) {
    trailing = rest.substring(trailingIdx + 2)
    rest = rest.substring(0, trailingIdx)
  }

  const parts = rest.split(' ').filter(Boolean)
  command = parts[0] || ''
  params = parts.slice(1)
  if (trailing !== null) params.push(trailing)

  const nick = prefix.split('!')[0]
  const now = new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })

  switch (command) {
    case 'PRIVMSG': {
      const target = params[0]
      const text = params[1] || ''
      if (target.startsWith('#')) {
        ensureChannel(target)
        channels.get(target).messages.push({ time: now, nick, text, type: 'msg' })
      } else {
        // DM — create a pseudo-channel for the sender.
        ensureChannel(nick)
        channels.get(nick).messages.push({ time: now, nick, text, type: 'msg' })
      }
      break
    }

    case 'JOIN': {
      const chan = params[0]
      ensureChannel(chan)
      channels.get(chan).messages.push({ time: now, nick, text: 'has joined', type: 'event' })
      // Add to member list.
      const joinUsers = channels.get(chan).users
      if (!joinUsers.includes(nick)) {
        joinUsers.push(nick)
        joinUsers.sort((a, b) => a.replace(/^[~&@%+]/, '').localeCompare(b.replace(/^[~&@%+]/, '')))
      }
      if (nick === props.username && !activeChannel.value) {
        activeChannel.value = chan
      }
      break
    }

    case 'PART': {
      const chan = params[0]
      if (channels.has(chan)) {
        channels.get(chan).messages.push({ time: now, nick, text: params[1] || 'has left', type: 'event' })
        // Remove from member list (match with or without prefix).
        const partUsers = channels.get(chan).users
        const partIdx = partUsers.findIndex(u => u.replace(/^[~&@%+]/, '') === nick)
        if (partIdx !== -1) partUsers.splice(partIdx, 1)
      }
      break
    }

    case 'QUIT': {
      const reason = params[0] || 'Quit'
      for (const [, ch] of channels) {
        // Remove from all channel member lists.
        const quitIdx = ch.users.findIndex(u => u.replace(/^[~&@%+]/, '') === nick)
        if (quitIdx !== -1) {
          ch.users.splice(quitIdx, 1)
          ch.messages.push({ time: now, nick, text: `has quit (${reason})`, type: 'event' })
        }
      }
      break
    }

    case 'NICK': {
      const newNick = params[0]
      for (const [, ch] of channels) {
        const nickIdx = ch.users.findIndex(u => u.replace(/^[~&@%+]/, '') === nick)
        if (nickIdx !== -1) {
          // Preserve prefix (e.g. @, +) when renaming.
          const prefix = ch.users[nickIdx].match(/^[~&@%+]/)?.[0] || ''
          ch.users[nickIdx] = prefix + newNick
          ch.messages.push({ time: now, nick, text: `is now known as ${newNick}`, type: 'event' })
        }
      }
      break
    }

    case '332': // RPL_TOPIC
      if (params.length >= 3) {
        const chan = params[1]
        ensureChannel(chan)
        channels.get(chan).topic = params[2]
      }
      break

    case '353': { // RPL_NAMREPLY
      const chan = params[2]
      const names = (params[3] || '').split(' ').filter(Boolean)
      ensureChannel(chan)
      channels.get(chan).users = names
      break
    }

    case '366': // RPL_ENDOFNAMES
      break

    case 'PING':
      sendIrc(`PONG ${params[0] || ''}`)
      break

    case 'MODE':
      // Silently handle mode changes.
      break

    default:
      // Numerics and other messages go to server buffer.
      addServerMessage(`${prefix ? prefix + ' ' : ''}${command} ${params.join(' ')}`)
  }
}

function ensureChannel(name) {
  if (!channels.has(name)) {
    channels.set(name, { messages: [], users: [], topic: '' })
  }
}

function addServerMessage(text) {
  const now = new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
  serverMessages.push({ time: now, nick: '*', text, type: 'server' })
}

function sendIrc(line) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'irc', line }))
  }
}

function sendMessage() {
  const text = inputText.value.trim()
  if (!text) return
  inputText.value = ''

  if (text.startsWith('/')) {
    // Command.
    const parts = text.substring(1).split(' ')
    const cmd = parts[0].toUpperCase()
    const args = parts.slice(1).join(' ')

    switch (cmd) {
      case 'JOIN':
        sendIrc(`JOIN ${args}`)
        break
      case 'PART':
        sendIrc(`PART ${args || activeChannel.value}`)
        if (!args && activeChannel.value) {
          channels.delete(activeChannel.value)
          activeChannel.value = channelList.value[1] || 'Server'
        }
        break
      case 'MSG':
      case 'PRIVMSG': {
        const [target, ...rest] = args.split(' ')
        sendIrc(`PRIVMSG ${target} :${rest.join(' ')}`)
        break
      }
      case 'NICK':
        sendIrc(`NICK ${args}`)
        break
      case 'QUIT':
        sendIrc(`QUIT :${args || 'Leaving'}`)
        break
      default:
        sendIrc(`${cmd} ${args}`)
    }
  } else if (activeChannel.value && activeChannel.value !== 'Server') {
    // Regular message to current channel.
    sendIrc(`PRIVMSG ${activeChannel.value} :${text}`)
    const now = new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
    channels.get(activeChannel.value)?.messages.push({
      time: now,
      nick: props.username,
      text,
      type: 'msg',
    })
  }
}

onMounted(() => {
  connect()
})

onUnmounted(() => {
  if (ws) ws.close()
})
</script>

<template>
  <div class="irc-layout">
    <!-- Sidebar -->
    <div class="sidebar">
      <div class="sidebar-header">
        <span class="username">{{ username }}</span>
        <button class="logout-btn" @click="$emit('logout')" title="Logout">x</button>
      </div>
      <div class="status-bar" :class="{ connected }">
        {{ status }}
      </div>
      <div class="channel-list">
        <div
          v-for="name in channelList"
          :key="name"
          class="channel-item"
          :class="{ active: viewMode === 'chat' && (activeChannel === name || (name === 'Server' && !activeChannel)) }"
          @click="viewMode = 'chat'; activeChannel = name"
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
            :disabled="!connected"
          />
        </div>
      </div>

      <!-- User list -->
      <div class="userlist" v-if="currentChannel?.users?.length">
        <div class="userlist-header">Users ({{ currentChannel.users.length }})</div>
        <div v-for="user in currentChannel.users" :key="user" class="user-item">
          {{ user }}
        </div>
      </div>
    </template>

    <!-- Main area: Mesh Network view -->
    <div v-else class="main mesh-view">
      <NetworkTopology :serverUrl="serverUrl" />
    </div>
  </div>
</template>

<style scoped>
.irc-layout {
  display: flex;
  height: 100vh;
  overflow: hidden;
}

.sidebar {
  width: 200px;
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

.username {
  color: var(--accent);
  font-weight: bold;
}

.logout-btn {
  background: none;
  border: none;
  color: var(--text-secondary);
  cursor: pointer;
  font-family: inherit;
  font-size: 1rem;
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

.status-bar.connected {
  color: var(--accent-green);
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
}
</style>
