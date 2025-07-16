function updateIndicator(len) {
  const indicator = document.getElementById('offline-indicator');
  const countSpan = document.getElementById('offline-count');
  if (!indicator || !countSpan) return;
  if (len > 0) {
    indicator.style.display = 'block';
    countSpan.textContent = len;
  } else {
    indicator.style.display = 'none';
    countSpan.textContent = '0';
  }
}

function showSyncComplete() {
  const msg = document.getElementById('sync-message');
  if (!msg) return;
  msg.style.display = 'block';
  setTimeout(() => {
    msg.style.display = 'none';
  }, 3000);
}

if ('serviceWorker' in navigator) {
  let deferredPrompt;
  const installBtn = document.getElementById('install-btn');
  if (installBtn) {
    installBtn.addEventListener('click', () => {
      if (!deferredPrompt) return;
      deferredPrompt.prompt();
      deferredPrompt.userChoice.finally(() => {
        installBtn.style.display = 'none';
        deferredPrompt = null;
      });
    });
  }
  window.addEventListener('beforeinstallprompt', e => {
    e.preventDefault();
    deferredPrompt = e;
    if (installBtn) installBtn.style.display = 'block';
  });
  window.addEventListener('appinstalled', () => {
    if (installBtn) installBtn.style.display = 'none';
  });
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('service-worker.js').then(() => {
      if (navigator.serviceWorker.controller) {
        navigator.serviceWorker.controller.postMessage({ type: 'flush' });
        navigator.serviceWorker.controller.postMessage({ type: 'getQueueLength' });
      }
    });
  });
  navigator.serviceWorker.addEventListener('message', e => {
    if (e.data && e.data.type === 'queueLength') {
      updateIndicator(e.data.length);
    } else if (e.data && e.data.type === 'syncComplete') {
      showSyncComplete();
    }
  });
  window.addEventListener('online', () => {
    if (navigator.serviceWorker.controller) {
      navigator.serviceWorker.controller.postMessage({ type: 'flush' });
      navigator.serviceWorker.controller.postMessage({ type: 'getQueueLength' });
    }
  });
}
