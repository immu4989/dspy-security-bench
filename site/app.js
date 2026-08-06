const state = { models: [], filter: "all", query: "" };
const palette = { Robust: "#72f2e7", Mixed: "#f4c86b", Vulnerable: "#ff7569", Provisional: "#8f78ff" };
const pct = value => `${Math.round(value * 100)}%`;

async function loadData() {
  const response = await fetch("data.json");
  if (!response.ok) throw new Error(`Could not load leaderboard data (${response.status})`);
  const data = await response.json();
  state.models = data.models;
  document.querySelectorAll("[data-model-count]").forEach(node => node.textContent = data.modelCount);
  document.querySelectorAll("[data-family-count]").forEach(node => node.textContent = data.familyCount);
  const robustness = data.models.map(model => model.robustness);
  document.querySelector("[data-min-robustness]").textContent = Math.round(Math.min(...robustness) * 100);
  document.querySelector("[data-max-robustness]").textContent = Math.round(Math.max(...robustness) * 100);
  renderTable();
  renderScatter();
}

function visibleModels() {
  const query = state.query.toLowerCase().trim();
  return state.models.filter(model => {
    const matchesFilter = state.filter === "all" || model.classification === state.filter;
    const matchesQuery = !query || `${model.name} ${model.family} ${model.modelId}`.toLowerCase().includes(query);
    return matchesFilter && matchesQuery;
  });
}

function renderTable() {
  const body = document.querySelector("#leaderboard-body");
  const models = visibleModels();
  body.innerHTML = models.map(model => {
    const rank = state.models.indexOf(model) + 1;
    const color = palette[model.classification] || palette.Mixed;
    const ci = `${Math.round(model.ciLow * 100)}–${Math.round(model.ciHigh * 100)}`;
    return `<tr style="--score-color:${color}">
      <td><div class="model-cell"><span class="rank">${String(rank).padStart(2, "0")}</span><div><div class="model-name">${model.name}</div><span class="status ${model.status}">${model.status}</span></div></div></td>
      <td class="family">${model.family}</td>
      <td class="score"><div class="score-line"><strong>${pct(model.robustness)}</strong><span>CI ${ci}</span></div><div class="bar"><i style="width:${model.robustness * 100}%"></i></div></td>
      <td class="score"><div class="score-line"><strong>${pct(model.capability)}</strong><span>benign</span></div><div class="bar"><i style="width:${model.capability * 100}%;opacity:.56"></i></div></td>
      <td><div class="bucket">${model.classification}</div><br><a class="evidence-link" href="${model.result}">result JSON ↗</a></td>
    </tr>`;
  }).join("");
  document.querySelector("#empty-state").hidden = models.length > 0;
}

function renderScatter() {
  const host = document.querySelector("#scatter");
  const width = 700, height = 430;
  const margin = { top: 18, right: 20, bottom: 52, left: 54 };
  const plotWidth = width - margin.left - margin.right;
  const plotHeight = height - margin.top - margin.bottom;
  const x = value => margin.left + value * plotWidth;
  const y = value => margin.top + (1 - value) * plotHeight;
  const ticks = [0, .25, .5, .75, 1];
  const grid = ticks.map(value => `
    <line class="grid-line" x1="${x(value)}" x2="${x(value)}" y1="${margin.top}" y2="${height - margin.bottom}" />
    <line class="grid-line" x1="${margin.left}" x2="${width - margin.right}" y1="${y(value)}" y2="${y(value)}" />
    <text x="${x(value)}" y="${height - 30}" text-anchor="middle">${value * 100}</text>
    <text x="${margin.left - 12}" y="${y(value) + 3}" text-anchor="end">${value * 100}</text>`).join("");
  const dots = state.models.map((model, index) => {
    const color = palette[model.classification] || palette.Mixed;
    const provisional = model.status !== "confirmed";
    return `<circle class="model-dot" tabindex="0" role="button" aria-label="${model.name}: ${pct(model.capability)} capability, ${pct(model.robustness)} robustness" data-index="${index}" cx="${x(model.capability)}" cy="${y(model.robustness)}" r="${provisional ? 6.5 : 5.5}" fill="${provisional ? "#091b25" : color}" stroke="${color}" stroke-width="${provisional ? 2 : 1}" stroke-dasharray="${provisional ? "3 2" : "none"}" style="color:${color}" />`;
  }).join("");
  host.innerHTML = `<svg viewBox="0 0 ${width} ${height}" aria-hidden="true">
    ${grid}
    <text class="axis-title" x="${margin.left + plotWidth / 2}" y="${height - 5}" text-anchor="middle">Capability →</text>
    <text class="axis-title" transform="translate(12 ${margin.top + plotHeight / 2}) rotate(-90)" text-anchor="middle">Robustness →</text>
    ${dots}
  </svg>`;
  host.querySelectorAll(".model-dot").forEach(dot => {
    dot.addEventListener("mouseenter", showTooltip);
    dot.addEventListener("mousemove", positionTooltip);
    dot.addEventListener("mouseleave", hideTooltip);
    dot.addEventListener("focus", showTooltip);
    dot.addEventListener("blur", hideTooltip);
  });
}

const tooltip = document.querySelector("#tooltip");
function showTooltip(event) {
  const model = state.models[Number(event.currentTarget.dataset.index)];
  tooltip.innerHTML = `<strong>${model.name}</strong><span>${model.family} · ${model.status}</span><span>Robustness ${pct(model.robustness)} · Capability ${pct(model.capability)}</span>`;
  tooltip.classList.add("show");
  positionTooltip(event);
}
function positionTooltip(event) {
  const rect = event.currentTarget.getBoundingClientRect();
  const clientX = event.clientX || rect.left + rect.width / 2;
  const clientY = event.clientY || rect.top;
  tooltip.style.left = `${clientX}px`;
  tooltip.style.top = `${clientY}px`;
}
function hideTooltip() { tooltip.classList.remove("show"); }

document.querySelectorAll(".filter").forEach(button => button.addEventListener("click", () => {
  state.filter = button.dataset.filter;
  document.querySelectorAll(".filter").forEach(item => item.classList.toggle("active", item === button));
  renderTable();
}));
document.querySelector("#model-search").addEventListener("input", event => {
  state.query = event.target.value;
  renderTable();
});

document.querySelector("#copy-code").addEventListener("click", async event => {
  const commands = `pip install dspy-security-bench\ndspy-security-bench init --model openai/gpt-4o-mini\ndspy-security-bench scan --config .dspy-security-bench.yaml --plan`;
  await navigator.clipboard.writeText(commands);
  event.currentTarget.textContent = "Copied ✓";
  setTimeout(() => { event.currentTarget.textContent = "Copy"; }, 1800);
});

const menuButton = document.querySelector(".menu-button");
menuButton.addEventListener("click", () => {
  const links = document.querySelector(".nav-links");
  const open = links.classList.toggle("open");
  menuButton.setAttribute("aria-expanded", String(open));
});
document.querySelectorAll(".nav-links a").forEach(link => link.addEventListener("click", () => document.querySelector(".nav-links").classList.remove("open")));
window.addEventListener("scroll", () => document.querySelector(".nav-shell").classList.toggle("scrolled", window.scrollY > 20), { passive: true });

const observer = new IntersectionObserver(entries => {
  entries.forEach(entry => { if (entry.isIntersecting) { entry.target.classList.add("visible"); observer.unobserve(entry.target); } });
}, { threshold: .12 });
document.querySelectorAll(".reveal").forEach(node => observer.observe(node));

loadData().catch(error => {
  console.error(error);
  document.querySelector("#leaderboard-body").innerHTML = `<tr><td colspan="5">Could not load leaderboard data. Serve this directory over HTTP instead of opening the file directly.</td></tr>`;
});
