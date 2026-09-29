const root = document.documentElement;
const selector = document.querySelector('#themeSelect');
const themeCount = document.querySelector('#themeCount');
const familyLabels = {
  cyberdyne: 'CYBERDYNE',
  cyberpunk: 'CYBERPUNK',
  default: 'CLASSICS',
  dystopian: 'DYSTOPIAN',
  neosynth: 'NEOSYNTH',
  synthwave: 'SYNTHWAVE'
};
const themeCache = new Map();
const formatName = name => name.replaceAll('-', ' ').toUpperCase();

async function getPalette(family, name) {
  const key = `${family}/${name}`;
  if (themeCache.has(key)) return themeCache.get(key);
  const response = await fetch(`data/themes/${key}.json`);
  if (!response.ok) throw new Error(`Theme palette unavailable: ${name}`);
  const palette = await response.json();
  themeCache.set(key, palette);
  return palette;
}

function setTheme(name, palette) {
  const variables = {
    bg: '--bg', panel: '--panel', line: '--line', white: '--text', muted: '--muted',
    acid_green: '--accent', hot_pink: '--accent2', cyan: '--accent3',
    purple: '--purple', orange: '--orange', red: '--danger'
  };
  for (const [key, variable] of Object.entries(variables)) {
    root.style.setProperty(variable, `#${palette[key]}`);
  }
  root.dataset.theme = name;
  document.querySelector('meta[name="theme-color"]').content = `#${palette.bg}`;
  localStorage.setItem('roninsuite-theme', name);
}

async function bootThemes() {
  const response = await fetch('data/cybergrid.json');
  if (!response.ok) throw new Error('Cybercore theme schema unavailable');
  const schema = await response.json();
  const families = Object.entries(schema.families).filter(([family]) => family !== 'cybercore-tech');
  const count = families.reduce((total, [, names]) => total + names.length, 0);
  themeCount.textContent = String(count);
  selector.replaceChildren();
  for (const [family, names] of families) {
    const group = document.createElement('optgroup');
    group.label = familyLabels[family] || family.toUpperCase();
    for (const name of names) {
      const option = document.createElement('option');
      option.value = name;
      option.textContent = formatName(name);
      option.dataset.family = family;
      group.append(option);
    }
    selector.append(group);
  }
  const requested = new URLSearchParams(location.search).get('theme');
  const saved = localStorage.getItem('roninsuite-theme');
  const allNames = families.flatMap(([, names]) => names);
  const active = [requested, saved, 'cyberpunk-neon'].find(name => name && allNames.includes(name));
  selector.value = active;
  const family = families.find(([, names]) => names.includes(active))[0];
  setTheme(active, await getPalette(family, active));
  selector.addEventListener('change', async () => {
    const selectedFamily = selector.selectedOptions[0].dataset.family;
    try {
      setTheme(selector.value, await getPalette(selectedFamily, selector.value));
      history.replaceState(null, '', `?theme=${encodeURIComponent(selector.value)}`);
    } catch (error) {
      console.error(error);
    }
  });
}

bootThemes().catch(error => {
  console.error(error);
  selector.replaceChildren(new Option('THEMES UNAVAILABLE', ''));
});

const lightbox = document.querySelector('#lightbox');
const lightboxImage = lightbox.querySelector('img');
document.querySelectorAll('.screen-image').forEach(button => {
  button.addEventListener('click', () => {
    const image = button.querySelector('img');
    lightboxImage.src = button.dataset.full;
    lightboxImage.alt = image.alt;
    lightbox.showModal();
  });
});
lightbox.querySelector('.lightbox-close').addEventListener('click', () => lightbox.close());
lightbox.addEventListener('click', event => {
  if (event.target === lightbox) lightbox.close();
});
lightbox.addEventListener('close', () => { lightboxImage.removeAttribute('src'); });
