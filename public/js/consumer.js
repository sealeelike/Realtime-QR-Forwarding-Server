// Auth check and logout
async function checkAuth() {
  try {
    const res = await fetch('/api/auth/me');
    if (!res.ok) {
      window.location.href = '/login.html';
      return false;
    }
    const data = await res.json();
    document.getElementById('currentUser').textContent = `${data.user.username} (${data.user.role})`;
    
    // Inject admin link for admin/owner
    if (data.user.role === 'admin' || data.user.role === 'owner') {
      document.getElementById('admin-nav').innerHTML = '<a href="/admin.html">Admin</a>';
    }
    
    document.body.classList.add('auth-ready');
    return true;
  } catch {
    window.location.href = '/login.html';
    return false;
  }
}

async function logout() {
  await fetch('/api/auth/logout', { method: 'POST' });
  window.location.href = '/login.html';
}

const statusEl = document.getElementById('status');
const joinForm = document.getElementById('join-form');
const urlSection = document.getElementById('url-section');
const timerEl = document.getElementById('timer');
const currentUrlEl = document.getElementById('current-url');
const latencyEl = document.getElementById('latency');
const btnOpenUrl = document.getElementById('btn-open-url');
const channelIdInput = document.getElementById('channel-id-input');
const passwordInput = document.getElementById('password-input');
const btnJoin = document.getElementById('btn-join');
const autoJumpCheckbox = document.getElementById('auto-jump-checkbox');

let ws = null;
let currentUrl = null;
let expireTime = null;
let timerInterval = null;

// Load auto-jump preference from localStorage
const savedAutoJump = localStorage.getItem('autoJumpEnabled');
autoJumpCheckbox.checked = savedAutoJump === 'true';

autoJumpCheckbox.addEventListener('change', () => {
  localStorage.setItem('autoJumpEnabled', autoJumpCheckbox.checked);
});

const params = new URLSearchParams(window.location.search);
const urlChannelId = params.get('channel');
const urlPassword = params.get('password') || '';

if (urlChannelId) {
  channelIdInput.value = urlChannelId;
  passwordInput.value = urlPassword;
}

function connect() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

  ws.onopen = () => {
    updateStatus('connected', 'Connected to server');
    if (urlChannelId) {
      joinChannel(urlChannelId, urlPassword);
    }
  };

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    
    switch (data.type) {
      case 'channel_joined':
        joinForm.classList.add('hidden');
        urlSection.classList.remove('hidden');
        updateStatus('connected', `Joined channel: ${data.channelId}`);
        break;
      
      case 'url_update':
        handleUrlUpdate(data);
        break;
      
      case 'producer_left':
        updateStatus('disconnected', 'Producer has left the channel');
        currentUrlEl.textContent = 'Producer disconnected';
        timerEl.textContent = '--';
        timerEl.classList.add('expired');
        btnOpenUrl.disabled = true;
        break;
      
      case 'error':
        updateStatus('disconnected', `Error: ${data.message}`);
        break;
    }
  };

  ws.onclose = () => {
    updateStatus('disconnected', 'Disconnected from server');
    setTimeout(connect, 3000);
  };

  ws.onerror = () => {
    updateStatus('disconnected', 'Connection error');
  };
}

function joinChannel(channelId, password) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      type: 'join_channel',
      channelId: channelId,
      password: password || null
    }));
  }
}

function handleUrlUpdate(data) {
  currentUrl = data.url;
  const receivedAt = Date.now();
  const latency = receivedAt - data.timestamp;
  const actualRemaining = data.remainingMs - latency;
  
  currentUrlEl.innerHTML = `<a href="${escapeHtml(data.url)}" target="_blank">${escapeHtml(data.url)}</a>`;
  latencyEl.textContent = `Latency: ${latency}ms`;
  btnOpenUrl.disabled = actualRemaining <= 0;
  
  expireTime = receivedAt + actualRemaining;
  timerEl.classList.remove('expired');
  
  // Auto-jump if enabled and remaining time > 3 seconds
  if (autoJumpCheckbox.checked && actualRemaining > 3000) {
    window.open(currentUrl, '_blank');
  }
  
  if (timerInterval) clearInterval(timerInterval);
  timerInterval = setInterval(updateTimer, 100);
  updateTimer();
}

function updateTimer() {
  if (!expireTime) return;
  
  const remaining = Math.max(0, expireTime - Date.now());
  const seconds = (remaining / 1000).toFixed(1);
  timerEl.textContent = `${seconds}s remaining`;
  
  if (remaining <= 0) {
    timerEl.textContent = 'Expired';
    timerEl.classList.add('expired');
    btnOpenUrl.disabled = true;
    clearInterval(timerInterval);
  }
}

function updateStatus(type, message) {
  statusEl.className = `status ${type}`;
  statusEl.textContent = message;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

btnJoin.addEventListener('click', () => {
  const channelId = channelIdInput.value.trim();
  const password = passwordInput.value;
  if (!channelId) {
    alert('Please enter a channel ID');
    return;
  }
  joinChannel(channelId, password);
});

btnOpenUrl.addEventListener('click', () => {
  if (currentUrl) {
    window.open(currentUrl, '_blank');
  }
});

// Initialize
checkAuth().then(ok => {
  if (ok) connect();
});
