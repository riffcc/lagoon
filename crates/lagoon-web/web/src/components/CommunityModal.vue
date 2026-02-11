<script setup>
import { ref } from 'vue'
import { startRegistration, startAuthentication } from '@simplewebauthn/browser'

const props = defineProps({
  welcome: { type: Boolean, default: false },
})

const emit = defineEmits(['joined', 'close'])

// Welcome mode: skip URL entry, connect to this server directly.
// Add-server mode: show URL entry first.
const step = ref(props.welcome ? 'auth' : 'url')
const serverUrl = ref(props.welcome ? window.location.origin : '')
const authMode = ref('register')  // default to register for new users
const username = ref('')
const error = ref('')
const loading = ref(false)

function api(path) {
  return `${serverUrl.value}${path}`
}

function proceedToAuth() {
  // Normalize URL: ensure https:// prefix.
  let url = serverUrl.value.trim()
  if (!url) return
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url
  }
  // Strip trailing slash.
  url = url.replace(/\/+$/, '')
  serverUrl.value = url
  error.value = ''
  step.value = 'auth'
}

async function register() {
  if (!username.value.trim()) return
  loading.value = true
  error.value = ''

  try {
    const beginRes = await fetch(api('/api/auth/register/begin'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username.value.trim() }),
    })
    if (!beginRes.ok) {
      error.value = await beginRes.text()
      return
    }
    const { options } = await beginRes.json()

    // webauthn-rs wraps in { publicKey: ... }, simplewebauthn wants the inner object.
    const optionsJSON = options.publicKey || options
    const credential = await startRegistration({ optionsJSON })

    const completeRes = await fetch(api('/api/auth/register/complete'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: username.value.trim(),
        credential,
      }),
    })
    if (!completeRes.ok) {
      error.value = await completeRes.text()
      return
    }
    const result = await completeRes.json()
    onAuthSuccess(result)
  } catch (e) {
    error.value = e.message || 'Registration failed'
  } finally {
    loading.value = false
  }
}

async function login() {
  if (!username.value.trim()) return
  loading.value = true
  error.value = ''

  try {
    const beginRes = await fetch(api('/api/auth/login/begin'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username.value.trim() }),
    })
    if (!beginRes.ok) {
      error.value = await beginRes.text()
      return
    }
    const { options } = await beginRes.json()

    const optionsJSON = options.publicKey || options
    const credential = await startAuthentication({ optionsJSON })

    const completeRes = await fetch(api('/api/auth/login/complete'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: username.value.trim(),
        credential,
      }),
    })
    if (!completeRes.ok) {
      error.value = await completeRes.text()
      return
    }
    const result = await completeRes.json()
    onAuthSuccess(result)
  } catch (e) {
    error.value = e.message || 'Login failed'
  } finally {
    loading.value = false
  }
}

function onAuthSuccess(result) {
  emit('joined', {
    id: crypto.randomUUID(),
    url: serverUrl.value,
    token: result.token,
    username: result.username,
    name: '',
  })
}

function submitAuth() {
  if (authMode.value === 'register') register()
  else login()
}
</script>

<template>
  <div class="modal-backdrop" @click.self="!welcome && emit('close')">
    <div class="modal-box">
      <h2 v-if="welcome" class="modal-title">Lagoon</h2>
      <h2 v-else class="modal-title">Join Another Server</h2>
      <p v-if="welcome" class="modal-subtitle">where you call home</p>

      <!-- Step 1: Server URL -->
      <div v-if="step === 'url'" class="modal-step">
        <form @submit.prevent="proceedToAuth">
          <label class="field-label" for="server-url">Server URL</label>
          <input
            id="server-url"
            v-model="serverUrl"
            type="text"
            placeholder="lon.lagun.co"
            autofocus
          />
          <button type="submit" class="primary" :disabled="!serverUrl.trim()">Connect</button>
        </form>
        <p class="hint">Enter another Lagoon server address to add it to your sidebar.</p>
      </div>

      <!-- Step 2: Auth -->
      <div v-if="step === 'auth'" class="modal-step">
        <p v-if="!welcome" class="server-label">Connecting to <strong>{{ serverUrl }}</strong></p>

        <div class="tabs">
          <button :class="{ active: authMode === 'login' }" @click="authMode = 'login'">Sign in</button>
          <button :class="{ active: authMode === 'register' }" @click="authMode = 'register'">Register</button>
        </div>

        <form @submit.prevent="submitAuth">
          <input
            v-model="username"
            type="text"
            placeholder="Username"
            autocomplete="username webauthn"
            :disabled="loading"
            autofocus
          />
          <button type="submit" class="primary" :disabled="loading || !username.trim()">
            <span v-if="loading">...</span>
            <span v-else-if="authMode === 'register'">Create with Passkey</span>
            <span v-else>Sign in with Passkey</span>
          </button>
        </form>

        <p v-if="error" class="error">{{ error }}</p>

        <button v-if="!welcome" class="back-btn" @click="step = 'url'; error = ''">Back</button>

        <p class="hint">Your passkey <em>is</em> your identity. No password needed.</p>
      </div>
    </div>
  </div>
</template>

<style scoped>
.modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.6);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
}

.modal-box {
  background: var(--bg-secondary);
  border: 1px solid var(--bg-tertiary);
  border-radius: 12px;
  padding: 2.5rem;
  width: 420px;
  max-width: 90vw;
  text-align: center;
}

.modal-title {
  color: var(--accent);
  font-size: 1.5rem;
  margin-bottom: 0.25rem;
}

.modal-subtitle {
  color: var(--text-secondary);
  margin-bottom: 1.5rem;
  font-style: italic;
}

.modal-step {
  margin-top: 1rem;
}

.field-label {
  display: block;
  text-align: left;
  font-size: 0.75rem;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 0.25rem;
}

form {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

input {
  background: var(--bg-primary);
  border: 1px solid var(--bg-tertiary);
  border-radius: 6px;
  padding: 0.75rem 1rem;
  color: var(--text-primary);
  font-family: inherit;
  font-size: 1rem;
  outline: none;
}

input:focus {
  border-color: var(--accent);
}

.tabs {
  display: flex;
  margin-bottom: 0.75rem;
  border-radius: 6px;
  overflow: hidden;
  border: 1px solid var(--bg-tertiary);
}

.tabs button {
  flex: 1;
  padding: 0.5rem;
  background: transparent;
  color: var(--text-secondary);
  border: none;
  cursor: pointer;
  font-family: inherit;
  font-size: 0.9rem;
}

.tabs button.active {
  background: var(--bg-tertiary);
  color: var(--text-primary);
}

button.primary {
  background: var(--accent);
  color: var(--bg-primary);
  border: none;
  border-radius: 6px;
  padding: 0.75rem;
  font-family: inherit;
  font-size: 1rem;
  font-weight: bold;
  cursor: pointer;
}

button.primary:hover:not(:disabled) {
  opacity: 0.9;
}

button.primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.back-btn {
  margin-top: 0.75rem;
  background: none;
  border: none;
  color: var(--text-secondary);
  cursor: pointer;
  font-family: inherit;
  font-size: 0.85rem;
  text-decoration: underline;
}

.back-btn:hover {
  color: var(--text-primary);
}

.server-label {
  color: var(--text-secondary);
  font-size: 0.85rem;
  margin-bottom: 1rem;
}

.server-label strong {
  color: var(--text-primary);
}

.error {
  color: var(--accent-red);
  margin-top: 0.75rem;
  font-size: 0.85rem;
}

.hint {
  color: var(--text-secondary);
  margin-top: 1rem;
  font-size: 0.8rem;
}
</style>
