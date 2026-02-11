import { ref, reactive } from 'vue'

/**
 * Factory: creates a connection manager for a single Lagoon community.
 * Owns all WebSocket + IRC state. Caller controls connect/disconnect lifecycle.
 *
 * @param {{ url: string, token: string, username: string }} community
 */
export function createConnection(community) {
  const connected = ref(false)
  const status = ref('Disconnected')
  const channels = reactive(new Map())   // name → { messages: [], users: [], topic: '' }
  const activeChannel = ref('')
  const serverMessages = reactive([])
  const communityName = ref('')
  const username = ref(community.username)
  const circles = ref([])                // fetched from /api/communities

  let ws = null
  let authFailCallback = null
  let reconnectAttempts = 0
  let reconnectTimer = null
  let intentionalClose = false

  const MAX_RECONNECT_ATTEMPTS = 5
  // Backoff: 1s, 2s, 4s, 8s, 16s
  function backoffMs() { return Math.min(1000 * (2 ** reconnectAttempts), 16000) }

  function onAuthFail(cb) {
    authFailCallback = cb
  }

  function connect() {
    clearReconnectTimer()
    closeSocket()
    intentionalClose = false
    status.value = 'Connecting...'

    const url = new URL(community.url || window.location.origin)
    const proto = url.protocol === 'https:' ? 'wss:' : 'ws:'
    ws = new WebSocket(`${proto}//${url.host}/api/ws`)

    ws.onopen = () => {
      ws.send(JSON.stringify({ type: 'auth', token: community.token }))
    }

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data)
      handleServerMessage(msg)
    }

    ws.onclose = () => {
      const wasConnected = connected.value
      connected.value = false
      if (intentionalClose) return
      // If we had a working session and it dropped, reset retry counter —
      // this is a fresh disconnect, not a continuation of auth failures.
      if (wasConnected) reconnectAttempts = 0
      // Auto-reconnect with exponential backoff.
      if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
        const delay = backoffMs()
        reconnectAttempts++
        status.value = `Reconnecting (${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})...`
        addServerMessage(`--- Connection lost, reconnecting in ${delay / 1000}s ---`)
        reconnectTimer = setTimeout(() => connect(), delay)
      } else {
        status.value = 'Disconnected'
        addServerMessage('--- Disconnected from server (max retries reached) ---')
      }
    }

    ws.onerror = () => {
      // onclose will fire after onerror — reconnect logic lives there.
    }
  }

  function clearReconnectTimer() {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
  }

  function closeSocket() {
    if (ws) {
      ws.onclose = null
      ws.onerror = null
      ws.close()
      ws = null
    }
  }

  function disconnect() {
    intentionalClose = true
    clearReconnectTimer()
    reconnectAttempts = 0
    closeSocket()
  }

  function handleServerMessage(msg) {
    switch (msg.type) {
      case 'auth_ok':
        connected.value = true
        reconnectAttempts = 0
        status.value = `Authenticated as ${msg.username}`
        username.value = msg.username
        break

      case 'auth_fail':
        // On first few failures, try reconnecting (token might be stale from restart).
        // Only escalate to full logout after exhausting retries.
        // Mark intentional so ws.onclose doesn't double-reconnect.
        intentionalClose = true
        closeSocket()
        if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
          const delay = backoffMs()
          reconnectAttempts++
          status.value = `Auth failed, retrying (${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})...`
          addServerMessage(`--- Auth failed: ${msg.reason}, retrying in ${delay / 1000}s ---`)
          clearReconnectTimer()
          reconnectTimer = setTimeout(() => connect(), delay)
        } else {
          status.value = `Auth failed: ${msg.reason}`
          if (authFailCallback) authFailCallback()
        }
        break

      case 'status':
        connected.value = msg.connected
        status.value = msg.message
        if (msg.connected) {
          fetchCircles()
        }
        break

      case 'irc':
        parseIrcLine(msg.line)
        break
    }
  }

  function parseIrcLine(line) {
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
        if (target.startsWith('#') || target.startsWith('&')) {
          ensureChannel(target)
          channels.get(target).messages.push({ time: now, nick, text, type: 'msg' })
        } else {
          // DM — create pseudo-channel for the sender.
          ensureChannel(nick)
          channels.get(nick).messages.push({ time: now, nick, text, type: 'msg' })
        }
        break
      }

      case 'JOIN': {
        const chan = params[0]
        ensureChannel(chan)
        channels.get(chan).messages.push({ time: now, nick, text: 'has joined', type: 'event' })
        const joinUsers = channels.get(chan).users
        if (!joinUsers.includes(nick)) {
          joinUsers.push(nick)
          joinUsers.sort((a, b) =>
            a.replace(/^[~&@%+]/, '').localeCompare(b.replace(/^[~&@%+]/, ''))
          )
        }
        if (nick === username.value && !activeChannel.value) {
          activeChannel.value = chan
        }
        break
      }

      case 'PART': {
        const chan = params[0]
        if (channels.has(chan)) {
          channels.get(chan).messages.push({ time: now, nick, text: params[1] || 'has left', type: 'event' })
          const partUsers = channels.get(chan).users
          const partIdx = partUsers.findIndex(u => u.replace(/^[~&@%+]/, '') === nick)
          if (partIdx !== -1) partUsers.splice(partIdx, 1)
        }
        break
      }

      case 'KICK': {
        const chan = params[0]
        const kicked = params[1]
        const reason = params[2] || nick
        if (channels.has(chan)) {
          channels.get(chan).messages.push({
            time: now, nick, text: `kicked ${kicked} (${reason})`, type: 'event',
          })
          const kickUsers = channels.get(chan).users
          const kickIdx = kickUsers.findIndex(u => u.replace(/^[~&@%+]/, '') === kicked)
          if (kickIdx !== -1) kickUsers.splice(kickIdx, 1)
          // If we were kicked, remove the channel.
          if (kicked === username.value) {
            channels.delete(chan)
            if (activeChannel.value === chan) {
              activeChannel.value = channels.keys().next().value || 'Server'
            }
          }
        }
        break
      }

      case 'QUIT': {
        const reason = params[0] || 'Quit'
        for (const [, ch] of channels) {
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
            const pfx = ch.users[nickIdx].match(/^[~&@%+]/)?.[0] || ''
            ch.users[nickIdx] = pfx + newNick
            ch.messages.push({ time: now, nick, text: `is now known as ${newNick}`, type: 'event' })
          }
        }
        if (nick === username.value) {
          username.value = newNick
        }
        break
      }

      case 'TOPIC': {
        // Live topic change from another user.
        const chan = params[0]
        const topicText = params[1] || ''
        if (channels.has(chan)) {
          channels.get(chan).topic = topicText
          channels.get(chan).messages.push({
            time: now, nick, text: `changed the topic to: ${topicText}`, type: 'event',
          })
        }
        break
      }

      case '005': {
        // RPL_ISUPPORT — extract NETWORK= for community name.
        const tokenString = params.join(' ')
        const networkMatch = tokenString.match(/NETWORK=(\S+)/)
        if (networkMatch) {
          communityName.value = networkMatch[1]
        }
        addServerMessage(`${prefix ? prefix + ' ' : ''}${command} ${params.join(' ')}`)
        break
      }

      case '332': // RPL_TOPIC
        if (params.length >= 3) {
          const chan = params[1]
          ensureChannel(chan)
          channels.get(chan).topic = params[2]
        }
        break

      case '333': // RPL_TOPICWHOTIME — absorb silently.
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
        break

      default:
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

  function sendMessage(text) {
    if (!text) return

    if (text.startsWith('/')) {
      const cmdParts = text.substring(1).split(' ')
      const cmd = cmdParts[0].toUpperCase()
      const args = cmdParts.slice(1).join(' ')

      switch (cmd) {
        case 'JOIN':
          sendIrc(`JOIN ${args}`)
          break
        case 'PART':
          sendIrc(`PART ${args || activeChannel.value}`)
          if (!args && activeChannel.value) {
            channels.delete(activeChannel.value)
            activeChannel.value = channels.keys().next().value || 'Server'
          }
          break
        case 'MSG':
        case 'PRIVMSG': {
          const [target, ...rest] = args.split(' ')
          sendIrc(`PRIVMSG ${target} :${rest.join(' ')}`)
          break
        }
        case 'KICK': {
          sendIrc(`KICK ${args}`)
          break
        }
        case 'TOPIC': {
          sendIrc(`TOPIC ${args}`)
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
      sendIrc(`PRIVMSG ${activeChannel.value} :${text}`)
      const now = new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
      channels.get(activeChannel.value)?.messages.push({
        time: now,
        nick: username.value,
        text,
        type: 'msg',
      })
    }
  }

  // -- Circle API --

  function apiHeaders() {
    return {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${community.token}`,
    }
  }

  function apiUrl(path) {
    return `${community.url || window.location.origin}${path}`
  }

  async function fetchCircles() {
    try {
      const res = await fetch(apiUrl('/api/communities'), {
        headers: apiHeaders(),
      })
      if (res.ok) {
        circles.value = await res.json()
      }
    } catch { /* network error — circles stay empty */ }
  }

  async function createCircle(name, description) {
    const res = await fetch(apiUrl('/api/communities'), {
      method: 'POST',
      headers: apiHeaders(),
      body: JSON.stringify({ name, description: description || '' }),
    })
    if (!res.ok) {
      throw new Error(await res.text())
    }
    const created = await res.json()
    await fetchCircles()
    return created
  }

  async function joinCircle(id) {
    const res = await fetch(apiUrl(`/api/communities/${id}/join`), {
      method: 'POST',
      headers: apiHeaders(),
    })
    if (!res.ok) {
      throw new Error(await res.text())
    }
    await fetchCircles()
    return await res.json()
  }

  /** Join all IRC channels belonging to a circle. */
  function joinCircleChannels(circle) {
    if (!circle?.channels) return
    for (const ch of circle.channels) {
      if (!channels.has(ch)) {
        sendIrc(`JOIN ${ch}`)
      }
    }
  }

  return {
    // Reactive state
    connected,
    status,
    channels,
    serverMessages,
    activeChannel,
    communityName,
    username,
    circles,

    // Methods
    connect,
    disconnect,
    sendIrc,
    sendMessage,
    ensureChannel,
    onAuthFail,
    fetchCircles,
    createCircle,
    joinCircle,
    joinCircleChannels,
  }
}
