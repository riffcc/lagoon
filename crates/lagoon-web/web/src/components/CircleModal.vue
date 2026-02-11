<script setup>
import { ref } from 'vue'

const emit = defineEmits(['created', 'close'])

const props = defineProps({
  /** The active connection's createCommunity method. */
  createCommunity: Function,
})

const name = ref('')
const description = ref('')
const error = ref('')
const loading = ref(false)

async function submit() {
  const trimmed = name.value.trim()
  if (!trimmed) return
  loading.value = true
  error.value = ''
  try {
    const community = await props.createCommunity(trimmed, description.value.trim())
    emit('created', community)
  } catch (e) {
    error.value = e.message || 'Failed to create community'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="modal-backdrop" @click.self="emit('close')">
    <div class="modal-box">
      <h2 class="modal-title">Create a Community</h2>
      <p class="modal-subtitle">A community is a group of channels — your space within this server.</p>

      <form @submit.prevent="submit" class="modal-form">
        <label class="field-label" for="community-name">Community Name</label>
        <input
          id="community-name"
          v-model="name"
          type="text"
          placeholder="General"
          :disabled="loading"
          autofocus
        />

        <label class="field-label" for="community-desc">Description (optional)</label>
        <input
          id="community-desc"
          v-model="description"
          type="text"
          placeholder="The main hangout"
          :disabled="loading"
        />

        <button type="submit" class="primary" :disabled="loading || !name.trim()">
          <span v-if="loading">Creating...</span>
          <span v-else>Create Community</span>
        </button>
      </form>

      <p v-if="error" class="error">{{ error }}</p>

      <button class="back-btn" @click="emit('close')">Cancel</button>
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
  font-size: 0.85rem;
}

.modal-form {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.field-label {
  display: block;
  text-align: left;
  font-size: 0.75rem;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: -0.5rem;
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

.error {
  color: var(--accent-red);
  margin-top: 0.75rem;
  font-size: 0.85rem;
}
</style>
