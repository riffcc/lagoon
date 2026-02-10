<script setup>
import { ref } from 'vue'
import { startRegistration, startAuthentication } from '@simplewebauthn/browser'

const emit = defineEmits(['login', 'update:serverUrl'])
const props = defineProps({
  serverUrl: String,
})

const username = ref('')
const error = ref('')
const loading = ref(false)
const mode = ref('login') // 'login' or 'register'

function api(path) {
  return `${props.serverUrl}${path}`
}

async function register() {
  if (!username.value.trim()) return
  loading.value = true
  error.value = ''

  try {
    // Step 1: Get challenge from server.
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

    // Step 2: Create passkey with browser WebAuthn API.
    // webauthn-rs wraps in { publicKey: ... }, simplewebauthn wants the inner object.
    const optionsJSON = options.publicKey || options
    const credential = await startRegistration({ optionsJSON })

    // Step 3: Send credential to server.
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
    emit('login', result)
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
    // Step 1: Get challenge.
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

    // Step 2: Authenticate with passkey.
    const optionsJSON = options.publicKey || options
    const credential = await startAuthentication({ optionsJSON })

    // Step 3: Verify with server.
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
    emit('login', result)
  } catch (e) {
    error.value = e.message || 'Login failed'
  } finally {
    loading.value = false
  }
}

function submit() {
  if (mode.value === 'register') register()
  else login()
}
</script>

<template>
  <div class="login-container">
    <div class="login-box">
      <h1 class="title">Lagoon</h1>
      <p class="subtitle">where you call home</p>

      <div class="tabs">
        <button
          :class="{ active: mode === 'login' }"
          @click="mode = 'login'"
        >Sign in</button>
        <button
          :class="{ active: mode === 'register' }"
          @click="mode = 'register'"
        >Register</button>
      </div>

      <form @submit.prevent="submit">
        <div class="server-field">
          <label for="server">Server</label>
          <input
            id="server"
            type="url"
            :value="serverUrl"
            @input="$emit('update:serverUrl', $event.target.value)"
            placeholder="https://lagoon.example.com"
            :disabled="loading"
          />
        </div>

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
          <span v-else-if="mode === 'register'">Create with Passkey</span>
          <span v-else>Sign in with Passkey</span>
        </button>
      </form>

      <p v-if="error" class="error">{{ error }}</p>

      <p class="hint">
        Your passkey <em>is</em> your identity. No password needed.
      </p>
    </div>
  </div>
</template>

<style scoped>
.login-container {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100vh;
}

.login-box {
  background: var(--bg-secondary);
  border: 1px solid var(--bg-tertiary);
  border-radius: 12px;
  padding: 2.5rem;
  width: 380px;
  text-align: center;
}

.title {
  font-size: 2rem;
  color: var(--accent);
  margin-bottom: 0.25rem;
}

.subtitle {
  color: var(--text-secondary);
  margin-bottom: 1.5rem;
  font-style: italic;
}

.tabs {
  display: flex;
  gap: 0;
  margin-bottom: 1.5rem;
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

form {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.server-field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  text-align: left;
}

.server-field label {
  font-size: 0.75rem;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.05em;
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

.server-field input {
  font-size: 0.85rem;
  padding: 0.5rem 0.75rem;
  color: var(--text-secondary);
}

.server-field input:focus {
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

.error {
  color: var(--accent-red);
  margin-top: 1rem;
  font-size: 0.85rem;
}

.hint {
  color: var(--text-secondary);
  margin-top: 1.5rem;
  font-size: 0.8rem;
}
</style>
