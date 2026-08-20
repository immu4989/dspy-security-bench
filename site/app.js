const state = { models: [], filter: "all", query: "" };
const palette = { Robust: "#72f2e7", Mixed: "#f4c86b", Vulnerable: "#ff7569", Provisional: "#8f78ff" };
const pct = value => `${Math.round(value * 100)}%`;
const escapeHtml = value => String(value).replace(/[&<>"']/g, character => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
})[character]);
const safeResultUrl = value => {
  const url = String(value || "");
  const accepted = /^https:\/\/github\.com\/immu4989\/dspy-security-bench\/blob\/main\/submissions\/impact\/[a-z0-9-]+\.json$/;
  return accepted.test(url) ? url : "https://github.com/immu4989/dspy-security-bench/tree/main/submissions/impact";
};
const safeControlResultUrl = value => {
  const url = String(value || "");
  const accepted = /^https:\/\/github\.com\/immu4989\/dspy-security-bench\/blob\/main\/submissions\/control\/[a-z0-9-]+\.json$/;
  return accepted.test(url) ? url : "https://github.com/immu4989/dspy-security-bench/tree/main/submissions/control";
};
const safeIncidentResultUrl = value => {
  const url = String(value || "");
  const accepted = /^https:\/\/github\.com\/immu4989\/dspy-security-bench\/blob\/main\/submissions\/incident\/[a-z0-9-]+\.json$/;
  return accepted.test(url) ? url : "https://github.com/immu4989/dspy-security-bench/tree/main/submissions/incident";
};
const safeSourceResultUrl = value => {
  const url = String(value || "");
  const accepted = /^https:\/\/github\.com\/immu4989\/dspy-security-bench\/blob\/main\/submissions\/source\/[a-z0-9-]+\.json$/;
  return accepted.test(url) ? url : "https://github.com/immu4989/dspy-security-bench/tree/main/submissions/source";
};
const safeAuthorityResultUrl = value => {
  const url = String(value || "");
  const accepted = /^https:\/\/github\.com\/immu4989\/dspy-security-bench\/blob\/main\/submissions\/authority\/[a-z0-9-]+\.json$/;
  return accepted.test(url) ? url : "https://github.com/immu4989/dspy-security-bench/tree/main/submissions/authority";
};

async function loadData() {
  const response = await fetch("data.json");
  if (!response.ok) throw new Error(`Could not load leaderboard data (${response.status})`);
  const data = await response.json();
  state.models = data.models;
  document.querySelectorAll("[data-model-count]").forEach(node => node.textContent = data.modelCount);
  document.querySelectorAll("[data-family-count]").forEach(node => node.textContent = data.familyCount);
  document.querySelectorAll("[data-proofrun-count]").forEach(node => node.textContent = data.proofrunCount || 0);
  document.querySelectorAll("[data-control-evidence-count]").forEach(node => node.textContent = data.controlEvidenceCount || 0);
  document.querySelectorAll("[data-incident-evidence-count]").forEach(node => node.textContent = data.incidentEvidenceCount || 0);
  document.querySelectorAll("[data-source-evidence-count]").forEach(node => node.textContent = data.sourceEvidenceCount || 0);
  document.querySelectorAll("[data-authority-evidence-count]").forEach(node => node.textContent = data.authorityEvidenceCount || 0);
  const robustness = data.models.map(model => model.robustness);
  document.querySelector("[data-min-robustness]").textContent = Math.round(Math.min(...robustness) * 100);
  document.querySelector("[data-max-robustness]").textContent = Math.round(Math.max(...robustness) * 100);
  renderTable();
  renderScatter();
  renderProofRuns(data.proofruns || []);
  renderControlEvidence(data.controlEvidence || []);
  renderIncidentEvidence(data.incidentEvidence || []);
  renderSourceEvidence(data.sourceEvidence || []);
  renderAuthorityEvidence(data.authorityEvidence || []);
}

const proofTier = {
  maintainer_reproduced: ["Reproduced", "tier-reproduced"],
  trusted_builder: ["Trusted builder", "tier-builder"],
  github_attested: ["GitHub-attested", "tier-github"],
  github_attestation_unverified: ["Attestation pending", "tier-pending"],
  self_attested: ["Self-attested", "tier-self"]
};

function renderProofRuns(results) {
  const host = document.querySelector("#proofrun-results");
  const empty = document.querySelector("#proofrun-empty");
  if (!host || !empty) return;
  empty.hidden = results.length > 0;
  host.innerHTML = results.map(result => {
    const [label, className] = proofTier[result.evidenceTier] || proofTier.self_attested;
    const cost = result.costUsd == null ? "not reported" : `$${Number(result.costUsd).toFixed(4)}`;
    return `<article class="proof-result">
      <div><span class="proof-tier ${className}">${label}</span><strong>${escapeHtml(result.agent)}</strong><small>${escapeHtml(result.submitter)} · ${Number(result.trials)} trials</small></div>
      <div class="proof-score"><strong>${pct(result.rate)}</strong><span>95% Wilson ${pct(result.lower)}–${pct(result.upper)}</span></div>
      <div class="proof-meta"><span>${Number(result.unstablePairs)} unstable pairs</span><span>${escapeHtml(cost)}</span></div>
      <a href="${safeResultUrl(result.result)}">inspect JSON ↗</a>
    </article>`;
  }).join("");
}

function evidenceMetric(label, estimate) {
  if (!estimate) return `<div><span>${label}</span><strong>N/A</strong><small>no eligible baseline observations</small></div>`;
  return `<div><span>${label}</span><strong>${pct(Number(estimate.rate))}</strong><small>95% Wilson ${pct(Number(estimate.lower))}–${pct(Number(estimate.upper))}</small></div>`;
}

function renderControlEvidence(results) {
  const host = document.querySelector("#control-evidence-results");
  const empty = document.querySelector("#control-evidence-empty");
  if (!host || !empty) return;
  empty.hidden = results.length > 0;
  host.innerHTML = results.map(result => {
    const [label, className] = proofTier[result.evidenceTier] || proofTier.self_attested;
    const policyDigest = String(result.policySha256 || "").slice(0, 12);
    const riskReduction = Number(result.riskReductionUsd || 0).toLocaleString("en-US", { maximumFractionDigits: 0 });
    return `<article class="control-evidence-card">
      <header>
        <span class="proof-tier ${className}">${label}</span>
        <strong>${escapeHtml(result.agent)}</strong>
        <small>${escapeHtml(result.submitter)} · ${Number(result.trials)} paired trials</small>
      </header>
      <div class="control-policy-id"><span>policy</span><strong>${escapeHtml(result.policy)}</strong><code>sha256:${escapeHtml(policyDigest)}…</code></div>
      <div class="control-evidence-metrics">
        ${evidenceMetric("Harm containment", result.containment)}
        ${evidenceMetric("Safe recovery", result.recovery)}
        ${evidenceMetric("Clean preservation", result.cleanPreservation)}
      </div>
      <footer><span>${Number(result.unstablePairs)}/5 unstable effects</span><span>$${riskReduction} synthetic exposure reduced / trial</span><a href="${safeControlResultUrl(result.result)}">inspect evidence ↗</a></footer>
    </article>`;
  }).join("");
}

function renderIncidentEvidence(results) {
  const host = document.querySelector("#incident-evidence-results");
  const empty = document.querySelector("#incident-evidence-empty");
  if (!host || !empty) return;
  empty.hidden = results.length > 0;
  host.innerHTML = results.map(result => {
    const [label, className] = proofTier[result.evidenceTier] || proofTier.self_attested;
    return `<article class="incident-evidence-card">
      <header><span class="proof-tier ${className}">${label}</span><strong>${escapeHtml(result.agent)}</strong><small>${escapeHtml(result.submitter)} · ${Number(result.trials)} trials</small></header>
      <div class="incident-evidence-metrics">
        ${evidenceMetric("Attack resistance", result.attackResistance)}
        ${evidenceMetric("Harm free", result.harmFree)}
        ${evidenceMetric("Clean utility", result.cleanUtility)}
      </div>
      <footer><span>${Number(result.unstablePairs)}/5 unstable pairs</span><a href="${safeIncidentResultUrl(result.result)}">inspect evidence ↗</a></footer>
    </article>`;
  }).join("");
}

function renderSourceEvidence(results) {
  const host = document.querySelector("#source-evidence-results");
  const empty = document.querySelector("#source-evidence-empty");
  if (!host || !empty) return;
  empty.hidden = results.length > 0;
  host.innerHTML = results.map(result => {
    const [label, className] = proofTier[result.evidenceTier] || proofTier.self_attested;
    const digest = String(result.packSha256 || "").slice(0, 12);
    return `<article class="source-evidence-card">
      <header><span class="proof-tier ${className}">${label}</span><strong>${escapeHtml(result.agent)}</strong><small>${escapeHtml(result.submitter)} · ${Number(result.trials)} trials</small></header>
      <div class="source-pack-id"><span>pack</span><strong>${escapeHtml(result.packId)}</strong><code>sha256:${escapeHtml(digest)}…</code></div>
      <div class="source-evidence-metrics">
        ${evidenceMetric("Attack resistance", result.attackResistance)}
        ${evidenceMetric("Faithfulness", result.faithfulness)}
        ${evidenceMetric("Completeness", result.completeness)}
        ${evidenceMetric("Sufficiency", result.sufficiency)}
      </div>
      <footer><span>${Number(result.unstablePairs)} unstable pairs</span><a href="${safeSourceResultUrl(result.result)}">inspect evidence ↗</a></footer>
    </article>`;
  }).join("");
}

function renderAuthorityEvidence(results) {
  const host = document.querySelector("#authority-evidence-results");
  const empty = document.querySelector("#authority-evidence-empty");
  if (!host || !empty) return;
  empty.hidden = results.length > 0;
  host.innerHTML = results.map(result => {
    const [label, className] = proofTier[result.evidenceTier] || proofTier.self_attested;
    return `<article class="authority-evidence-card">
      <header><span class="proof-tier ${className}">${label}</span><strong>${escapeHtml(result.adapter)}</strong><small>${escapeHtml(result.submitter)} · ${Number(result.trials)} trials</small></header>
      <div class="authority-evidence-metrics">
        ${evidenceMetric("Attack resistance", result.attackResistance)}
        ${evidenceMetric("Harm containment", result.harmContainment)}
        ${evidenceMetric("Decision accuracy", result.decisionAccuracy)}
        ${evidenceMetric("Receipt integrity", result.receiptIntegrity)}
      </div>
      <footer><span>${Number(result.falseAllows)} false allows</span><span>${Number(result.unstablePairs)}/10 unstable pairs</span><a href="${safeAuthorityResultUrl(result.result)}">inspect evidence ↗</a></footer>
    </article>`;
  }).join("");
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
  const button = event.currentTarget;
  const commands = `pip install dspy-security-bench\ndspy-security-bench init --model openai/gpt-4o-mini\ndspy-security-bench scan --config .dspy-security-bench.yaml --plan`;
  await navigator.clipboard.writeText(commands);
  button.textContent = "Copied ✓";
  setTimeout(() => { button.textContent = "Copy"; }, 1800);
});

document.querySelector("#proofrun-copy")?.addEventListener("click", async event => {
  const button = event.currentTarget;
  const workflow = `permissions:\n  contents: read\n  id-token: write\n  attestations: write\n\njobs:\n  proofrun:\n    uses: immu4989/dspy-security-bench/.github/workflows/proofrun.yml@v0.14.0\n    with:\n      agent: myapp.security:build_agent\n      trials: 10`;
  await navigator.clipboard.writeText(workflow);
  button.textContent = "Copied ✓";
  setTimeout(() => { button.textContent = "Copy workflow"; }, 1800);
});

document.querySelector("#control-registry-copy")?.addEventListener("click", async event => {
  const button = event.currentTarget;
  const workflow = `permissions:\n  contents: read\n  id-token: write\n  attestations: write\n\njobs:\n  control-evidence:\n    uses: immu4989/dspy-security-bench/.github/workflows/proofrun.yml@v0.14.0\n    with:\n      evidence-kind: control\n      agent: myapp.security:build_agent\n      policy: policies/production.yaml\n      trials: 10\n      min-containment-lower-bound: 0.70`;
  await navigator.clipboard.writeText(workflow);
  button.textContent = "Copied ✓";
  setTimeout(() => { button.textContent = "Copy workflow"; }, 1800);
});

document.querySelector("#control-copy")?.addEventListener("click", async event => {
  const button = event.currentTarget;
  await navigator.clipboard.writeText("dspy-security-bench impact control-demo");
  button.textContent = "Copied ✓";
  setTimeout(() => { button.textContent = "Copy command"; }, 1800);
});

document.querySelector("#repeat-control-copy")?.addEventListener("click", async event => {
  const button = event.currentTarget;
  await navigator.clipboard.writeText("dspy-security-bench impact control-repeat-demo --trials 5");
  button.textContent = "Copied ✓";
  setTimeout(() => { button.textContent = "Copy command"; }, 1800);
});

function bindCommandCopy(selector, command) {
  document.querySelector(selector)?.addEventListener("click", async event => {
    const button = event.currentTarget;
    await navigator.clipboard.writeText(command);
    button.textContent = "Copied ✓";
    setTimeout(() => { button.textContent = "Copy"; }, 1800);
  });
}
bindCommandCopy("#incident-copy", "dspy-security-bench incident demo");
bindCommandCopy("#source-copy", "dspy-security-bench pack run source-twin --agent myapp:build");
bindCommandCopy("#authority-copy", "dspy-security-bench authority demo");
bindCommandCopy("#federal-copy", "dspy-security-bench federal init");

const menuButton = document.querySelector(".menu-button");
menuButton.addEventListener("click", () => {
  const links = document.querySelector(".nav-links");
  const open = links.classList.toggle("open");
  menuButton.setAttribute("aria-expanded", String(open));
  menuButton.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
});
document.querySelectorAll(".nav-links a").forEach(link => link.addEventListener("click", () => {
  document.querySelector(".nav-links").classList.remove("open");
  menuButton.setAttribute("aria-expanded", "false");
  menuButton.setAttribute("aria-label", "Open navigation");
}));
window.addEventListener("scroll", () => document.querySelector(".nav-shell").classList.toggle("scrolled", window.scrollY > 20), { passive: true });

const observer = new IntersectionObserver(entries => {
  entries.forEach(entry => { if (entry.isIntersecting) { entry.target.classList.add("visible"); observer.unobserve(entry.target); } });
}, { threshold: .12 });
document.querySelectorAll(".reveal").forEach(node => observer.observe(node));

loadData().catch(error => {
  console.error(error);
  document.querySelector("#leaderboard-body").innerHTML = `<tr><td colspan="5">Could not load leaderboard data. Serve this directory over HTTP instead of opening the file directly.</td></tr>`;
});
