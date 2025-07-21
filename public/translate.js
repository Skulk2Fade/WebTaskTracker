function applyTranslations(data) {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (data[key]) {
      el.textContent = data[key];
    }
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const key = el.getAttribute('data-i18n-placeholder');
    if (data[key]) {
      el.setAttribute('placeholder', data[key]);
    }
  });
  document.querySelectorAll('[data-i18n-aria-label]').forEach(el => {
    const key = el.getAttribute('data-i18n-aria-label');
    if (data[key]) {
      el.setAttribute('aria-label', data[key]);
    }
  });
}

async function loadTranslations(lang) {
  try {
    const res = await fetch(`locales/${lang}.json`);
    const data = await res.json();
    applyTranslations(data);
  } catch (e) {
    console.error('Translation load failed', e);
  }
}

function initI18n(selectId = 'lang-select') {
  const select = document.getElementById(selectId);
  if (!select) return;
  const defaultLang = (localStorage.getItem('lang') || navigator.language || 'en').slice(0,2);
  select.value = defaultLang;
  loadTranslations(defaultLang);
  select.addEventListener('change', () => {
    const lang = select.value;
    localStorage.setItem('lang', lang);
    loadTranslations(lang);
  });
}

document.addEventListener('DOMContentLoaded', () => initI18n());
