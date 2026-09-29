const root = document.documentElement;
const menu = document.querySelector('#themeMenu');
const picker = document.querySelector('#themePicker');
const currentLabel = document.querySelector('#currentThemeLabel');
const currentSwatch = document.querySelector('#currentSwatch');
const paletteDialog = document.querySelector('#paletteDialog');
const paletteOptions = document.querySelector('#paletteOptions');
const paletteTitle = document.querySelector('#paletteTitle');
const paletteClose = document.querySelector('#paletteClose');
const familiesLabel = {cyberdyne:'CYBERDYNE',cyberpunk:'CYBERPUNK',default:'CLASSICS',dystopian:'DYSTOPIAN',neosynth:'NEOSYNTH',synthwave:'SYNTHWAVE'};
const cache = new Map();
const nice = value => value.replaceAll('-', ' ');

async function paletteFor(family, name) {
  const key = `${family}/${name}`;
  if (!cache.has(key)) {
    const response = await fetch(`data/themes/${key}.json`);
    if (!response.ok) throw new Error(`Theme unavailable: ${name}`);
    cache.set(key, await response.json());
  }
  return cache.get(key);
}

function applyTheme(name, palette) {
  const vars = {bg:'--bg',white:'--fg',acid_green:'--acid',hot_pink:'--pink',purple:'--purple',cyan:'--cyan',orange:'--orange',red:'--red',panel:'--panel',line:'--line',muted:'--muted'};
  for (const [key, variable] of Object.entries(vars)) root.style.setProperty(variable, `#${palette[key]}`);
  root.dataset.theme = name;
  document.querySelector('meta[name="theme-color"]').content = `#${palette.bg}`;
  currentLabel.textContent = nice(name);
  currentSwatch.style.background = `#${palette.cyan}`;
  document.querySelectorAll('[data-theme-name]').forEach(button => button.setAttribute('aria-current', String(button.dataset.themeName === name)));
  document.querySelectorAll('[data-active-theme]').forEach(label => { label.textContent = root.dataset.theme === label.closest('[data-family]')?.dataset.family ? nice(name) : 'NO PALETTE ACTIVE'; });
  localStorage.setItem('roninsuite-theme', name);
}

async function choose(name, family) {
  try {
    applyTheme(name, await paletteFor(family, name));
    history.replaceState(null, '', `?theme=${encodeURIComponent(name)}`);
  } catch (error) { console.error(error); }
}

async function bootThemes() {
  const response = await fetch('data/cybergrid.json');
  if (!response.ok) throw new Error('Cybercore theme schema unavailable');
  const schema = await response.json();
  const families = Object.entries(schema.families).filter(([family]) => family !== 'cybercore-tech');
  let count = 0;
  for (const [family, names] of families) {
    count += names.length;
    const palettes = await Promise.all(names.map(name => paletteFor(family, name)));
    const heading = document.createElement('div');
    heading.className = 'theme-family';
    heading.textContent = `${familiesLabel[family] || family.toUpperCase()} · ${names.length}`;
    menu.append(heading);
    for (const [index, name] of names.entries()) {
      const palette = palettes[index];
      const button = document.createElement('button');
      button.className = 'theme-opt'; button.type = 'button'; button.setAttribute('role', 'menuitem');
      button.dataset.themeName = name;
      const swatch = document.createElement('span'); swatch.className = 'swatch-dot'; swatch.style.background = `#${palette.cyan}`;
      button.append(swatch, document.createTextNode(nice(name)));
      button.addEventListener('click', () => { choose(name, family); menu.classList.remove('open'); picker.setAttribute('aria-expanded', 'false'); });
      menu.append(button);
    }
    const familyBox = document.createElement('button');
    familyBox.type = 'button'; familyBox.className = 'family-tile'; familyBox.dataset.family = family;
    familyBox.setAttribute('aria-label', `Open ${familiesLabel[family] || family} theme family, ${names.length} palettes`);
    const bar = document.createElement('span'); bar.className = 'family-strip';
    ['bg','panel','cyan','acid_green','hot_pink','purple'].forEach(key => { const chip = document.createElement('i'); chip.style.background = `#${palettes[0][key]}`; bar.append(chip); });
    const nameLabel = document.createElement('span'); nameLabel.className = 'family-name'; nameLabel.textContent = familiesLabel[family] || family.toUpperCase();
    const countLabel = document.createElement('span'); countLabel.className = 'family-count'; countLabel.textContent = `${names.length} PALETTES`;
    const activeLabel = document.createElement('span'); activeLabel.className = 'family-active'; activeLabel.dataset.activeTheme = ''; activeLabel.textContent = 'NO PALETTE ACTIVE';
    const actionLabel = document.createElement('span'); actionLabel.className = 'family-action'; actionLabel.textContent = 'OPEN TERMINAL  ↗';
    familyBox.append(bar, nameLabel, countLabel, activeLabel, actionLabel);
    familyBox.addEventListener('click', () => openFamily(family, names, palettes));
    document.querySelector('#themeGrid').append(familyBox);
  }
  document.querySelector('#themeGrid').setAttribute('aria-label', `${families.length} Cybercore theme families containing ${count} themes`);
  const allNames = families.flatMap(([, names]) => names);
  const requested = new URLSearchParams(location.search).get('theme');
  const saved = localStorage.getItem('roninsuite-theme');
  const active = [requested, saved, 'cyberpunk-neon'].find(name => name && allNames.includes(name));
  const family = families.find(([, names]) => names.includes(active))[0];
  applyTheme(active, await paletteFor(family, active));
}

function openFamily(family, names, palettes) {
  paletteTitle.textContent = `${familiesLabel[family] || family.toUpperCase()} / ${names.length} PALETTES`;
  paletteOptions.replaceChildren();
  for (const [index, name] of names.entries()) {
    const palette = palettes[index];
    const card = document.createElement('button');
    card.type = 'button'; card.className = 'theme-card'; card.dataset.themeName = name;
    card.setAttribute('aria-label', `Apply ${nice(name)} theme`);
    const strip = document.createElement('span'); strip.className = 'strip';
    ['bg','panel','cyan','acid_green','hot_pink','purple'].forEach(key => { const chip = document.createElement('span'); chip.style.background = `#${palette[key]}`; strip.append(chip); });
    const title = document.createElement('span'); title.textContent = nice(name);
    card.append(strip, title);
    card.addEventListener('click', () => { choose(name, family); paletteDialog.close(); });
    paletteOptions.append(card);
  }
  paletteDialog.showModal();
}

picker.addEventListener('click', () => {
  const open = menu.classList.toggle('open');
  picker.setAttribute('aria-expanded', String(open));
});
document.addEventListener('click', event => {
  if (!event.target.closest('.theme-picker-wrap')) { menu.classList.remove('open'); picker.setAttribute('aria-expanded', 'false'); }
});
document.addEventListener('keydown', event => { if (event.key === 'Escape') { menu.classList.remove('open'); picker.setAttribute('aria-expanded', 'false'); } });
paletteClose.addEventListener('click', () => paletteDialog.close());
paletteDialog.addEventListener('click', event => { if (event.target === paletteDialog) paletteDialog.close(); });

bootThemes().catch(error => console.error(error));

const lightbox = document.querySelector('#lightbox');
const lightboxImage = lightbox.querySelector('img');
document.querySelectorAll('.screen-image').forEach(button => button.addEventListener('click', () => {
  lightboxImage.src = button.dataset.full;
  lightboxImage.alt = button.querySelector('img').alt;
  lightbox.showModal();
}));
lightbox.querySelector('.lightbox-close').addEventListener('click', () => lightbox.close());
lightbox.addEventListener('click', event => { if (event.target === lightbox) lightbox.close(); });
lightbox.addEventListener('close', () => lightboxImage.removeAttribute('src'));
