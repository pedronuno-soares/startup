const BASE = 'http://localhost:8888/api/v1';

// ── TOAST NOTIFICATIONS ──
function showToast(title, message, type = 'info') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  
  let icon = '[!]';
  if(type === 'success') icon = '[OK]';
  if(type === 'error') icon = '[ERRO]';

  toast.innerHTML = `
    <div class="toast-icon">${icon}</div>
    <div class="toast-content">
      <h4>${title}</h4>
      <p>${message}</p>
    </div>
    <div class="toast-progress"></div>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('closing');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// ── THEME TOGGLE ──
function toggleTheme() {
  const isLight = document.body.classList.toggle('light-theme');
  localStorage.setItem('dems_theme', isLight ? 'light' : 'dark');
}

// ── AUTH & INIT ──
function initApp() {
  const token = localStorage.getItem('dems_token');
  if (!token && !window.location.pathname.includes('/login')) {
    console.log('Public mode: no auth required');
    // window.location.href = '/login';
    // return;
  }

  // Restore theme
  if(localStorage.getItem('dems_theme') === 'light') {
    document.body.classList.add('light-theme');
  }

  // User Badge
  try {
    const u = JSON.parse(localStorage.getItem('dems_user') || '{}');
    const badgeText = document.getElementById('userBadgeText');
    if (badgeText && (u.name || u.email)) {
      badgeText.textContent = u.name || u.email;
      document.getElementById('userBadge').style.display = 'flex';
    }
  } catch {}

  // Spotlight Effect
  document.addEventListener('mousemove', e => {
    document.querySelectorAll('.spotlight').forEach(card => {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      card.style.setProperty('--mouse-x', `${x}px`);
      card.style.setProperty('--mouse-y', `${y}px`);
    });
  });

  if (!window.location.pathname.includes('/login')) {
    checkHealth();
    setInterval(checkHealth, 15000);
  }
}

function doLogout() {
  localStorage.removeItem('dems_token');
  localStorage.removeItem('dems_user');
  window.location.href = '/login';
}

// ── HEALTH CHECK ──
async function checkHealth() {
  const statusEl = document.getElementById('serverStatus');
  const badgeEl = document.getElementById('serverBadge');
  if(!statusEl) return;

  try {
    const d = await (await fetch(`${BASE}/health`)).json();
    const ok = d.quorum?.quorumAchievable;
    
    badgeEl.className = 'badge' + (ok ? '' : ' off');
    statusEl.textContent = ok ? 'Rede Online' : 'Falha no Quórum';
    
    const nodesVal = document.getElementById('statNodes');
    if(nodesVal) nodesVal.textContent = `${d.quorum?.healthy}/${d.quorum?.total}`;
    
    const quorumVal = document.getElementById('statQuorum');
    if(quorumVal) quorumVal.textContent = d.quorum?.quorumAchievable ? 'Garantido' : 'Falhou';
    
    const modeVal = document.getElementById('statMode');
    if(modeVal) modeVal.textContent = d.mode || 'N/A';
    
    const grid = document.getElementById('nodesGrid');
    if(grid) {
      grid.innerHTML = (d.auditNodes||[]).map((n,i)=>`
        <div class="node ${n.healthy?'up':'dn'} spotlight">
          <div class="node-hdr"><span class="node-nm">audit_node_${i+1}</span><span class="tag ${n.healthy?'':'dn'}">${n.healthy?'UP':'DOWN'}</span></div>
          <div class="node-uri" style="margin-top:8px">${n.uri||'in-memory'}</div>
        </div>`).join('');
    }
  } catch {
    badgeEl.className = 'badge off';
    statusEl.textContent = 'Rede Offline';
  }
}

// ── CYBER SCRAMBLE EFFECT ──
function scrambleText(element, finalString, duration = 1500) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()';
  let iter = 0;
  const maxIter = duration / 30;
  element.classList.add('glitch-text');
  
  const interval = setInterval(() => {
    let current = '';
    for(let i=0; i<finalString.length; i++) {
      if(i < (iter / maxIter) * finalString.length) {
        current += finalString[i];
      } else {
        current += chars[Math.floor(Math.random() * chars.length)];
      }
    }
    element.textContent = current;
    element.setAttribute('data-text', current);
    iter++;
    
    if(iter >= maxIter) {
      clearInterval(interval);
      element.textContent = finalString;
      element.classList.remove('glitch-text');
    }
  }, 30);
}

// ── CRYPTO (DIGITAL SIGNATURES) ──
async function initCryptoKeys() {
  if (localStorage.getItem('dems_privateKey') && localStorage.getItem('dems_publicKey')) return;
  
  const keyPair = await window.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  
  const exportKey = async (k) => {
    const exported = await window.crypto.subtle.exportKey("jwk", k);
    return JSON.stringify(exported);
  };
  
  localStorage.setItem('dems_privateKey', await exportKey(keyPair.privateKey));
  localStorage.setItem('dems_publicKey', await exportKey(keyPair.publicKey));
  console.log("[Crypto] Chaves ECDSA geradas para Não-Repúdio.");
}

async function signData(dataStr) {
  const privKeyStr = localStorage.getItem('dems_privateKey');
  if(!privKeyStr) throw new Error("Chave Privada não encontrada");
  
  const privateKey = await window.crypto.subtle.importKey(
    "jwk", JSON.parse(privKeyStr),
    { name: "ECDSA", namedCurve: "P-256" },
    true, ["sign"]
  );
  
  const enc = new TextEncoder();
  const signatureBuffer = await window.crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    privateKey,
    enc.encode(dataStr)
  );
  
  const signatureArray = Array.from(new Uint8Array(signatureBuffer));
  return signatureArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getPublicKeyHex() {
  const pubKeyStr = localStorage.getItem('dems_publicKey');
  if(!pubKeyStr) return 'NONE';
  const pubKeyObj = JSON.parse(pubKeyStr);
  return pubKeyObj.x + pubKeyObj.y; // Simplified public key rep
}

// ── SCREEN LOCK (INACTIVITY) ──
let inactivityTimer;
const LOCK_TIME = 90000; // 90 seconds
let isLocked = false;

function initScreenLock() {
  const token = localStorage.getItem('dems_token');
  if (!token) return; // Only lock if user is logged in

  // Inject Lock Screen HTML
  const lockHtml = `
    <div id="screenLockOverlay" class="screen-lock-overlay">
      <div class="screen-lock-modal">
        <h2>[ ACESSO BLOQUEADO ]</h2>
        <p>Inatividade detetada. O terminal foi trancado por segurança. Insira a palavra-passe para reativar a sessão.</p>
        <input type="password" id="lockPassword" placeholder="PALAVRA-PASSE" onkeydown="if(event.key === 'Enter') unlockScreen()" autocomplete="off">
        <button onclick="unlockScreen()">DESBLOQUEAR TERMINAL</button>
      </div>
    </div>
  `;
  document.body.insertAdjacentHTML('beforeend', lockHtml);

  // Setup timers
  resetTimer();
  window.addEventListener('mousemove', resetTimer);
  window.addEventListener('keydown', resetTimer);
  window.addEventListener('click', resetTimer);
  window.addEventListener('scroll', resetTimer);
}

function resetTimer() {
  if (isLocked) return;
  clearTimeout(inactivityTimer);
  inactivityTimer = setTimeout(lockScreen, LOCK_TIME);
}

function lockScreen() {
  isLocked = true;
  document.getElementById('screenLockOverlay').classList.add('active');
  document.getElementById('lockPassword').value = '';
  setTimeout(() => document.getElementById('lockPassword').focus(), 100);
}

async function unlockScreen() {
  const pwd = document.getElementById('lockPassword').value;
  if (!pwd) return;

  const uStr = localStorage.getItem('dems_user');
  if (!uStr) return;
  const email = JSON.parse(uStr).email;

  try {
    const res = await fetch(BASE + '/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: pwd })
    });
    
    if (res.ok) {
      const d = await res.json();
      localStorage.setItem('dems_token', d.token);
      document.getElementById('screenLockOverlay').classList.remove('active');
      isLocked = false;
      resetTimer();
      showToast('Sessão Reativada', 'Autenticação confirmada.', 'success');
    } else {
      showToast('Acesso Negado', 'Palavra-passe incorreta.', 'error');
      document.getElementById('lockPassword').value = '';
    }
  } catch(e) {
    showToast('Erro', 'Falha na comunicação com o servidor.', 'error');
  }
}

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
    initApp();
    initScreenLock();
    if(window.location.pathname.includes('/login') === false) {
        initCryptoKeys();
    }
});
