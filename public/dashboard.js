async function init() {
  const res = await fetch('/api/me');
  const me = await res.json();
  if (!me.user) {
    window.location = 'index.html';
    return;
  }
  if (me.user.role === 'admin') {
    document.getElementById('admin-link').style.display = 'inline';
  }
  const dataRes = await fetch('/api/reports');
  if (!dataRes.ok) return;
  const data = await dataRes.json();
  renderCompleted(data.completedPerWeek);
  renderTime(data.timePerGroup);
}

function renderCompleted(rows) {
  const labels = rows.map((r) => r.week).reverse();
  const counts = rows.map((r) => r.count).reverse();
  new Chart(document.getElementById('completedChart'), {
    type: 'bar',
    data: { labels, datasets: [{ label: 'Completed', data: counts }] },
    options: { plugins: { legend: { display: false } } },
  });
}

function renderTime(rows) {
  const labels = rows.map((r) => r.group);
  const minutes = rows.map((r) => r.minutes);
  new Chart(document.getElementById('timeChart'), {
    type: 'pie',
    data: { labels, datasets: [{ data: minutes }] },
    options: {},
  });
}

window.onload = init;
