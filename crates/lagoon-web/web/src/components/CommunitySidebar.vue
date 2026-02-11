<script setup>
const props = defineProps({
  /** Array of { server, communities } groups. Each server has { id, name, url }. Each community has { id, name }. */
  groups: Array,
  activeCommunityId: String,
  username: String,
})

const emit = defineEmits(['selectCommunity', 'addCommunity', 'addServer'])

function communityIcon(community) {
  return community.name?.[0]?.toUpperCase() || '?'
}
</script>

<template>
  <div class="circle-rail">
    <!-- Home icon at top -->
    <div class="rail-icon home" title="Home">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
        <polyline points="9 22 9 12 15 12 15 22"/>
      </svg>
    </div>
    <span v-if="username" class="rail-username">{{ username }}</span>

    <div class="rail-separator"></div>

    <!-- Communities grouped by server -->
    <template v-for="(group, gi) in groups" :key="group.server.id">
      <div v-if="gi > 0 && group.communities.length" class="group-divider"></div>

      <div
        v-for="comm in group.communities"
        :key="comm.id"
        class="rail-icon community"
        :class="{ active: activeCommunityId === comm.id }"
        @click="emit('selectCommunity', { serverId: group.server.id, communityId: comm.id })"
        :title="comm.name"
      >
        <span class="icon-letter">{{ communityIcon(comm) }}</span>
        <div v-if="activeCommunityId === comm.id" class="active-pill"></div>
      </div>
    </template>

    <!-- Spacer pushes buttons to bottom -->
    <div class="rail-spacer"></div>

    <!-- Create community button -->
    <div class="rail-icon add-btn" @click="emit('addCommunity')" title="Create a community">
      <span class="add-icon">+</span>
    </div>

    <!-- Add server button (smaller, secondary) -->
    <div class="rail-icon server-btn" @click="emit('addServer')" title="Add another server">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>
        <rect x="2" y="14" width="20" height="8" rx="2" ry="2"/>
        <line x1="6" y1="6" x2="6.01" y2="6"/>
        <line x1="6" y1="18" x2="6.01" y2="18"/>
      </svg>
    </div>
  </div>
</template>

<style scoped>
.circle-rail {
  width: 72px;
  background: var(--bg-secondary);
  border-right: 1px solid var(--bg-tertiary);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
  padding: 12px 0;
  flex-shrink: 0;
  overflow-y: auto;
  scrollbar-width: none;
}

.circle-rail::-webkit-scrollbar {
  display: none;
}

.rail-icon {
  width: 48px;
  height: 48px;
  border-radius: 50%;
  background: var(--bg-tertiary);
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: border-radius 0.15s ease, background 0.15s ease;
  position: relative;
  flex-shrink: 0;
}

.rail-icon:hover {
  border-radius: 35%;
  background: var(--accent);
}

.rail-icon:hover .icon-letter,
.rail-icon:hover svg {
  color: var(--bg-primary);
}

.rail-icon.active {
  border-radius: 35%;
  background: var(--accent);
}

.rail-icon.active .icon-letter {
  color: var(--bg-primary);
}

.active-pill {
  position: absolute;
  left: -12px;
  width: 3px;
  height: 36px;
  background: var(--accent);
  border-radius: 0 4px 4px 0;
}

.icon-letter {
  color: var(--text-primary);
  font-size: 1.1rem;
  font-weight: bold;
  user-select: none;
}

.home {
  color: var(--text-primary);
}

.rail-username {
  color: var(--text-secondary);
  font-size: 0.6rem;
  text-align: center;
  width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  padding: 0 4px;
  flex-shrink: 0;
}

.rail-separator {
  width: 32px;
  height: 1px;
  background: var(--bg-tertiary);
  flex-shrink: 0;
  margin: 4px 0;
}

.group-divider {
  width: 32px;
  height: 2px;
  background: var(--bg-tertiary);
  border-radius: 1px;
  flex-shrink: 0;
  margin: 4px 0;
}

.rail-spacer {
  flex: 1;
}

.add-btn {
  background: transparent;
  border: 2px dashed var(--accent-green);
}

.add-btn:hover {
  background: var(--accent-green);
  border-color: var(--accent-green);
}

.add-btn:hover .add-icon {
  color: var(--bg-primary);
}

.add-icon {
  color: var(--accent-green);
  font-size: 1.5rem;
  font-weight: bold;
  line-height: 1;
}

.server-btn {
  width: 36px;
  height: 36px;
  background: transparent;
  border: 1px dashed var(--text-secondary);
  margin-top: 4px;
}

.server-btn:hover {
  background: var(--bg-tertiary);
  border-color: var(--accent);
}

.server-btn svg {
  color: var(--text-secondary);
}

.server-btn:hover svg {
  color: var(--accent);
}
</style>
