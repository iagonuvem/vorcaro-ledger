const endpoints = {
  devices: "/admin/v1/devices",
  executives: "/admin/v1/executives",
  recovery: "/admin/v1/recovery/ceremonies",
  conflicts: "/admin/v1/conflicts",
  checkpoints: "/admin/v1/checkpoints",
  audit: "/admin/v1/audit",
  policies: "/admin/v1/policies"
};

const state = {
  devices: [],
  executives: [],
  ceremonies: [],
  conflicts: [],
  checkpoints: [],
  audit: [],
  policies: [],
  active_policy: null
};

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((item) => item.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((panel) => panel.classList.remove("active"));
    tab.classList.add("active");
    document.querySelector(`[data-panel="${tab.dataset.tab}"]`)?.classList.add("active");
  });
});

await refresh();

async function refresh() {
  await Promise.all([
    load("devices"),
    load("executives"),
    load("recovery"),
    load("conflicts"),
    load("checkpoints"),
    load("audit"),
    load("policies")
  ]);
  render();
}

async function load(key) {
  try {
    const response = await fetch(endpoints[key], { headers: { accept: "application/json" } });
    if (!response.ok) {
      return;
    }
    const payload = await response.json();
    Object.assign(state, payload);
  } catch (_error) {
    // The admin listener is mTLS-only; an unreachable endpoint leaves the table empty.
  }
}

function render() {
  setText("metric-devices", state.devices.length.toString());
  setText("metric-quarantined", `${state.devices.filter((device) => device.status === "quarantined").length} quarantined`);
  setText("metric-conflicts", state.conflicts.length.toString());
  setText("metric-policy", state.active_policy === null ? "none" : `v${state.active_policy.version}`);
  setText("metric-policy-hash", state.active_policy === null ? "no active hash" : shortHash(state.active_policy.document_hash));
  const latestCheckpoint = state.checkpoints[0];
  setText("metric-checkpoint", latestCheckpoint === undefined ? "0" : latestCheckpoint.sequence.toString());
  setText("metric-checkpoint-hash", latestCheckpoint === undefined ? "no anchor" : shortHash(latestCheckpoint.ledger_hash));

  rows("devices-body", state.devices, (device) => [
    mono(device.id),
    mono(device.executive_id),
    status(device.status),
    text(device.risk_score.toString()),
    mono(device.max_event_counter.toString())
  ]);
  rows("executives-body", state.executives, (executive) => [
    mono(executive.id),
    text(executive.role),
    status(executive.status),
    mono(executive.key_version.toString()),
    time(executive.created_at)
  ]);
  rows("recovery-body", state.ceremonies, (ceremony) => [
    mono(ceremony.id),
    mono(ceremony.executive_id),
    status(ceremony.status),
    mono(`${ceremony.approvals}/${ceremony.required_approvals}`),
    time(ceremony.created_at)
  ]);
  rows("conflicts-body", state.conflicts, (conflict) => [
    mono(`${conflict.object_type}:${conflict.object_id}`),
    status(conflict.status === "open" ? "conflicted" : "accepted"),
    mono(conflict.event_ids.length.toString()),
    mono(conflict.detected_at_sequence.toString()),
    conflict.resolved_at === null ? muted("open") : time(conflict.resolved_at)
  ]);
  rows("checkpoints-body", state.checkpoints, (checkpoint) => [
    mono(checkpoint.sequence.toString()),
    mono(shortHash(checkpoint.ledger_hash)),
    mono(checkpoint.key_version.toString()),
    time(checkpoint.issued_at)
  ]);
  rows("audit-body", state.audit, (entry) => [
    mono(entry.id.toString()),
    text(entry.category),
    mono(entry.actor),
    text(entry.detail.event ?? "audit"),
    time(entry.created_at)
  ]);
  rows("policies-body", state.policies, (policy) => [
    mono(policy.id),
    mono(policy.version.toString()),
    mono(shortHash(policy.document_hash)),
    policy.activated_at_sequence === null ? muted("pending") : mono(policy.activated_at_sequence.toString())
  ]);
}

function rows(id, items, cells) {
  const body = document.getElementById(id);
  if (body === null) {
    return;
  }

  body.replaceChildren();
  if (items.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.className = "empty";
    td.colSpan = 5;
    td.textContent = "No records";
    tr.append(td);
    body.append(tr);
    return;
  }

  for (const item of items) {
    const tr = document.createElement("tr");
    for (const cell of cells(item)) {
      const td = document.createElement("td");
      td.append(cell);
      tr.append(td);
    }
    body.append(tr);
  }
}

function status(value) {
  const span = document.createElement("span");
  span.className = `status ${value}`;
  span.textContent = value;
  return span;
}

function text(value) {
  return document.createTextNode(value);
}

function mono(value) {
  const span = document.createElement("span");
  span.className = "mono";
  span.textContent = value;
  return span;
}

function muted(value) {
  const span = document.createElement("span");
  span.className = "muted";
  span.textContent = value;
  return span;
}

function time(value) {
  const span = document.createElement("time");
  span.dateTime = value;
  span.title = value;
  span.textContent = value;
  return span;
}

function shortHash(value) {
  if (typeof value !== "string" || value.length <= 18) {
    return value ?? "none";
  }
  return `${value.slice(0, 11)}…${value.slice(-6)}`;
}

function setText(id, value) {
  const element = document.getElementById(id);
  if (element !== null) {
    element.textContent = value;
  }
}
