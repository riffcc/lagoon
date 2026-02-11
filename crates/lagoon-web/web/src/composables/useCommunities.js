import { ref, computed, watch } from 'vue'

const STORAGE_KEY = 'lagoon_communities'
const ACTIVE_KEY = 'lagoon_active_community'

/**
 * Community list management with localStorage persistence.
 * Handles migration from old single-server keys.
 *
 * Community shape: { id: string, url: string, token: string, username: string, name: string }
 */
export function useCommunities() {
  const communities = ref(load())
  const activeCommunityId = ref(
    localStorage.getItem(ACTIVE_KEY) || communities.value[0]?.id || ''
  )

  const activeCommunity = computed(() =>
    communities.value.find(c => c.id === activeCommunityId.value) || null
  )

  // Persist on change.
  watch(communities, persist, { deep: true })
  watch(activeCommunityId, (id) => {
    if (id) localStorage.setItem(ACTIVE_KEY, id)
    else localStorage.removeItem(ACTIVE_KEY)
  })

  function addCommunity(community) {
    communities.value.push(community)
  }

  function removeCommunity(id) {
    communities.value = communities.value.filter(c => c.id !== id)
    if (activeCommunityId.value === id) {
      activeCommunityId.value = communities.value[0]?.id || ''
    }
  }

  function updateCommunity(id, updates) {
    const idx = communities.value.findIndex(c => c.id === id)
    if (idx !== -1) {
      Object.assign(communities.value[idx], updates)
    }
  }

  function setActive(id) {
    activeCommunityId.value = id
  }

  return {
    communities,
    activeCommunityId,
    activeCommunity,
    addCommunity,
    removeCommunity,
    updateCommunity,
    setActive,
  }
}

/** Load communities from localStorage, migrating old format if needed. */
function load() {
  // Try new format first.
  const stored = localStorage.getItem(STORAGE_KEY)
  if (stored) {
    try {
      const parsed = JSON.parse(stored)
      if (Array.isArray(parsed) && parsed.length > 0) return parsed
    } catch { /* fall through */ }
  }

  // Migrate from old single-server keys.
  const oldToken = localStorage.getItem('lagoon_token')
  const oldUsername = localStorage.getItem('lagoon_username')
  const oldServer = localStorage.getItem('lagoon_server')

  if (oldToken && oldUsername) {
    const community = {
      id: crypto.randomUUID(),
      url: oldServer || window.location.origin,
      token: oldToken,
      username: oldUsername,
      name: '',
    }

    // Persist new format and clean up old keys.
    localStorage.setItem(STORAGE_KEY, JSON.stringify([community]))
    localStorage.setItem(ACTIVE_KEY, community.id)
    localStorage.removeItem('lagoon_token')
    localStorage.removeItem('lagoon_username')
    localStorage.removeItem('lagoon_server')

    return [community]
  }

  return []
}

function persist(communities) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(communities))
}
