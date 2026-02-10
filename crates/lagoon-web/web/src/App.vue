<script setup>
import { ref, computed } from 'vue'
import Login from './components/Login.vue'
import IrcClient from './components/IrcClient.vue'

const token = ref(localStorage.getItem('lagoon_token') || '')
const username = ref(localStorage.getItem('lagoon_username') || '')
const serverUrl = ref(localStorage.getItem('lagoon_server') || window.location.origin)

const isLoggedIn = computed(() => !!token.value)

function onLogin(data) {
  token.value = data.token
  username.value = data.username
  localStorage.setItem('lagoon_token', data.token)
  localStorage.setItem('lagoon_username', data.username)
  localStorage.setItem('lagoon_server', serverUrl.value)
}

function onLogout() {
  token.value = ''
  username.value = ''
  localStorage.removeItem('lagoon_token')
  localStorage.removeItem('lagoon_username')
}
</script>

<template>
  <div class="app">
    <Login v-if="!isLoggedIn" v-model:serverUrl="serverUrl" @login="onLogin" />
    <IrcClient v-else :token="token" :username="username" :serverUrl="serverUrl" @logout="onLogout" />
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
  flex-direction: column;
}
</style>
