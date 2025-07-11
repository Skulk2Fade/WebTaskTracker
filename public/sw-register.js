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

if ('serviceWorker' in navigator) {
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
    }
  });
  window.addEventListener('online', () => {
    if (navigator.serviceWorker.controller) {
      navigator.serviceWorker.controller.postMessage({ type: 'flush' });
      navigator.serviceWorker.controller.postMessage({ type: 'getQueueLength' });
    }
  });
}
