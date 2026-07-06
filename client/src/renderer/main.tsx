import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import type { EventStatus, ExecutiveWorkspaceSnapshot, Metric, ShellState, VaultStatus } from "../ipc/contract.js";
import "./styles.css";

type ScreenId = "dashboard" | "approvals" | "conflicts" | "ledger" | "sync" | "exports" | "settings";

const screens: Array<{ id: ScreenId; label: string; question: string }> = [
  { id: "dashboard", label: "Dashboard", question: "What is our position?" },
  { id: "approvals", label: "Approvals", question: "What needs my decision?" },
  { id: "conflicts", label: "Conflicts", question: "What is disputed?" },
  { id: "ledger", label: "Ledger / Audit", question: "What is proven?" },
  { id: "sync", label: "Sync & Device", question: "What is verified?" },
  { id: "exports", label: "Exports", question: "What can leave?" },
  { id: "settings", label: "Settings", question: "What is configured?" }
];

const defaultScreen = screens[0] ?? { id: "dashboard" as const, label: "Dashboard", question: "What is our position?" };

function App(): React.JSX.Element {
  const [shellState, setShellState] = useState<ShellState | null>(null);
  const [workspaceSnapshot, setWorkspaceSnapshot] = useState<ExecutiveWorkspaceSnapshot | null>(null);
  const [vaultStatus, setVaultStatus] = useState<VaultStatus | null>(null);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "failed">("loading");
  const [activeScreen, setActiveScreen] = useState<ScreenId>("dashboard");
  const [securityAcknowledged, setSecurityAcknowledged] = useState(false);

  useEffect(() => {
    let mounted = true;
    const api = window.vorcaro;

    if (!api) {
      setLoadState("failed");
      return () => {
        mounted = false;
      };
    }

    Promise.all([api.getShellState(), api.getExecutiveWorkspaceSnapshot(), api.getVaultStatus()])
      .then(([state, snapshot, vault]) => {
        if (mounted) {
          setShellState(state);
          setWorkspaceSnapshot(snapshot);
          setVaultStatus(vault);
          setLoadState("ready");
        }
      })
      .catch(() => {
        if (mounted) {
          setLoadState("failed");
        }
      });

    return () => {
      mounted = false;
    };
  }, []);

  const activeScreenMeta = useMemo(
    () => screens.find((screen) => screen.id === activeScreen) ?? defaultScreen,
    [activeScreen]
  );

  return (
    <main className="app-shell" aria-live="polite">
      <aside className="sidebar" aria-label="Primary">
        <div className="brand-block">
          <p className="eyebrow">Vorcaro</p>
          <h1>Sovereign Finance Ledger</h1>
        </div>

        <nav className="nav-list">
          {screens.map((screen) => (
            <button
              key={screen.id}
              type="button"
              className={screen.id === activeScreen ? "nav-item active" : "nav-item"}
              onClick={() => setActiveScreen(screen.id)}
            >
              <span>{screen.label}</span>
              <span className="nav-question">{screen.question}</span>
            </button>
          ))}
        </nav>

        <ShellStatus loadState={loadState} shellState={shellState} vaultStatus={vaultStatus} />
      </aside>

      <section className="workspace" aria-labelledby="screen-title">
        <header className="workspace-header">
          <div>
            <p className="eyebrow">{activeScreenMeta.question}</p>
            <h2 id="screen-title">{activeScreenMeta.label}</h2>
          </div>
          <div className="header-actions">
            <StatusBadge state="accepted" label="accepted" />
            <StatusBadge state="pending" label="pending" />
          </div>
        </header>

        {!securityAcknowledged ? (
          <SecurityBanner onAcknowledge={() => setSecurityAcknowledged(true)} />
        ) : null}

        {workspaceSnapshot ? (
          <>
            {activeScreen === "dashboard" ? <Dashboard snapshot={workspaceSnapshot} /> : null}
            {activeScreen === "approvals" ? <Approvals snapshot={workspaceSnapshot} /> : null}
            {activeScreen === "conflicts" ? <Conflicts snapshot={workspaceSnapshot} /> : null}
            {activeScreen === "ledger" ? <LedgerAudit snapshot={workspaceSnapshot} /> : null}
            {activeScreen === "sync" ? (
              <SyncDevice shellState={shellState} loadState={loadState} snapshot={workspaceSnapshot} />
            ) : null}
            {activeScreen === "exports" ? <Exports snapshot={workspaceSnapshot} /> : null}
            {activeScreen === "settings" ? (
              <Settings shellState={shellState} loadState={loadState} snapshot={workspaceSnapshot} />
            ) : null}
          </>
        ) : (
          <WorkspaceUnavailable loadState={loadState} />
        )}
      </section>
    </main>
  );
}

function ShellStatus(props: {
  loadState: "loading" | "ready" | "failed";
  shellState: ShellState | null;
  vaultStatus: VaultStatus | null;
}): React.JSX.Element {
  return (
    <section className="sidebar-panel" aria-label="Shell state">
      <div className="panel-title">
        <span>Startup boundary</span>
        <StatusBadge state={props.loadState === "failed" ? "rejected" : "pending"} label={props.vaultStatus?.state ?? "loading"} />
      </div>
      <FactGrid
        rows={[
          ["UI origin", props.shellState?.appProtocolUrl ?? "app://index.html"],
          ["Renderer network", props.shellState?.rendererNetwork ?? "disabled"],
          ["Navigation", props.shellState?.navigationPolicy ?? "app_only"],
          ["Vault", props.vaultStatus?.state ?? "loading"],
          ["Key version", props.vaultStatus?.keyVersion?.toString() ?? "none"],
          ["Integrity", integrityLabel(props.loadState, props.shellState)]
        ]}
      />
    </section>
  );
}

function WorkspaceUnavailable(props: { loadState: "loading" | "ready" | "failed" }): React.JSX.Element {
  return (
    <section className="content-card wide">
      <CardHeader title="Workspace view model" status={props.loadState === "failed" ? "rejected" : "pending"} />
      <p>
        {props.loadState === "failed"
          ? "Renderer bridge rejected the workspace snapshot. No finance view model was rendered."
          : "Workspace snapshot is loading from the main process."}
      </p>
    </section>
  );
}

function Dashboard(props: { snapshot: ExecutiveWorkspaceSnapshot }): React.JSX.Element {
  return (
    <div className="screen-grid">
      <section className="metric-grid" aria-label="Position summary">
        {props.snapshot.metrics.map((metric) => (
          <MetricCard key={metric.label} metric={metric} />
        ))}
      </section>

      <section className="content-card wide">
        <CardHeader title="Accounts" status="accepted" />
        <DataTable
          columns={["Entity", "Account", "Accepted balance", "Pending impact", "Status", "Sequence"]}
          rows={props.snapshot.accounts.map((account) => [
            account.entity,
            account.account,
            <Money key="balance">{account.acceptedBalance}</Money>,
            <span key="pending" className={account.status === "pending" ? "pending-value" : ""}>
              {account.pendingDelta}
            </span>,
            <StatusBadge key="status" state={account.status} label={account.status} />,
            <Mono key="seq">{account.sequence}</Mono>
          ])}
        />
      </section>

      <section className="content-card">
        <CardHeader title="Inflows / outflows" status="pending" />
        <DataTable
          columns={["Kind", "Counterparty", "Amount", "Status", "UTC"]}
          rows={props.snapshot.flows.map((flow) => [
            flow.kind,
            flow.counterparty,
            <Money key="amount">{flow.amount}</Money>,
            <StatusBadge key="status" state={flow.status} label={flow.status} />,
            <Mono key="utc" title={flow.utc}>
              {flow.utc}
            </Mono>
          ])}
        />
      </section>

      <section className="content-card">
        <CardHeader title="AI analysis - advisory" />
        <p className="advisory-copy">{props.snapshot.advisoryText}</p>
      </section>
    </div>
  );
}

function Approvals(props: { snapshot: ExecutiveWorkspaceSnapshot }): React.JSX.Element {
  return (
    <div className="screen-grid">
      <section className="content-card wide">
        <CardHeader title="Operations awaiting signature" status="pending" />
        <DataTable
          columns={["Operation", "Amount", "Policy", "Progress", "Status", "Base"]}
          rows={props.snapshot.approvals.map((approval) => [
            approval.object,
            <Money key="amount">{approval.amount}</Money>,
            approval.policy,
            approval.progress,
            <StatusBadge key="status" state={approval.status} label={approval.status} />,
            <Mono key="seq">{approval.sequence}</Mono>
          ])}
        />
      </section>

      <section className="content-card action-card">
        <CardHeader title="Signature consequence" />
        <p>{props.snapshot.signatureConsequence}</p>
        <button type="button" className="primary-action" disabled>
          Sign selected operation
        </button>
      </section>
    </div>
  );
}

function Conflicts(props: { snapshot: ExecutiveWorkspaceSnapshot }): React.JSX.Element {
  return (
    <div className="screen-grid">
      {props.snapshot.conflicts.map((conflict) => (
        <section className="content-card conflict-card" key={conflict.object}>
          <CardHeader title={conflict.object} status={conflict.status} />
          <div className="comparison-grid">
            <VersionPanel title="Accepted version" body={conflict.acceptedVersion} status="accepted" />
            <VersionPanel title="Conflicting version" body={conflict.conflictingVersion} status="conflicted" />
          </div>
          <div className="conflict-footer">
            <Mono>sequence {conflict.sequence}</Mono>
            <StatusBadge state={conflict.status} label={conflict.status} />
          </div>
          <section className="ai-box" aria-label="AI analysis advisory">
            {conflict.aiProposal}
          </section>
        </section>
      ))}

      <section className="content-card action-card">
        <CardHeader title="Resolution event" />
        <p>{props.snapshot.conflictResolutionConsequence}</p>
        <button type="button" className="primary-action" disabled>
          Draft resolution
        </button>
      </section>
    </div>
  );
}

function LedgerAudit(props: { snapshot: ExecutiveWorkspaceSnapshot }): React.JSX.Element {
  return (
    <div className="screen-grid">
      <section className="content-card wide">
        <CardHeader title="Ledger event history" status="accepted" />
        <DataTable
          columns={["Event", "Object", "Actor", "Status", "Sequence", "Key", "Device", "Hash", "UTC"]}
          rows={props.snapshot.ledgerRows.map((row) => [
            row.event,
            row.object,
            row.actor,
            <StatusBadge key="status" state={row.status} label={row.status} />,
            <Mono key="seq">{row.sequence}</Mono>,
            <Mono key="key">{row.keyVersion}</Mono>,
            <Mono key="device">{row.device}</Mono>,
            <Mono key="hash">{row.hash}</Mono>,
            <Mono key="utc" title={row.utc}>
              {row.utc}
            </Mono>
          ])}
        />
      </section>
    </div>
  );
}

function SyncDevice(props: {
  shellState: ShellState | null;
  loadState: "loading" | "ready" | "failed";
  snapshot: ExecutiveWorkspaceSnapshot;
}): React.JSX.Element {
  return (
    <div className="screen-grid">
      <section className="content-card">
        <CardHeader title="Sync state" status="accepted" />
        <FactGrid rows={props.snapshot.syncFacts} />
      </section>

      <section className="content-card">
        <CardHeader title="Device" status="accepted" />
        <FactGrid
          rows={[
            ...props.snapshot.deviceFacts,
            ["Vault", props.shellState?.vault ?? "locked"],
            ["Integrity", integrityLabel(props.loadState, props.shellState)]
          ]}
        />
      </section>

      <section className="content-card wide">
        <CardHeader title="Checkpoint history" status="accepted" />
        <DataTable
          columns={["Sequence", "Ledger hash", "Verified at", "Status"]}
          rows={props.snapshot.checkpoints.map((checkpoint) => [
            <Mono key="seq">{checkpoint.sequence}</Mono>,
            <Mono key="hash">{checkpoint.hash}</Mono>,
            <Mono key="verified">{checkpoint.verifiedAt}</Mono>,
            <StatusBadge key="status" state={checkpoint.status} label={checkpoint.status} />
          ])}
        />
      </section>
    </div>
  );
}

function Exports(props: { snapshot: ExecutiveWorkspaceSnapshot }): React.JSX.Element {
  return (
    <div className="screen-grid">
      <section className="content-card wide">
        <CardHeader title="Export requests" status="pending" />
        <DataTable
          columns={["Name", "Scope", "Format", "Status", "Policy"]}
          rows={props.snapshot.exportRequests.map((request) => [
            request.name,
            request.scope,
            request.format,
            <StatusBadge key="status" state={request.status} label={request.status} />,
            request.policy
          ])}
        />
      </section>

      <section className="content-card action-card danger">
        <CardHeader title="Plaintext export" status="quarantined" />
        <p>{props.snapshot.exportWarning}</p>
        <button type="button" className="primary-action" disabled>
          Request export approval
        </button>
      </section>
    </div>
  );
}

function Settings(props: {
  shellState: ShellState | null;
  loadState: "loading" | "ready" | "failed";
  snapshot: ExecutiveWorkspaceSnapshot;
}): React.JSX.Element {
  return (
    <div className="screen-grid">
      <section className="content-card">
        <CardHeader title="Security settings" />
        <FactGrid
          rows={[
            ...props.snapshot.securitySettings,
            ["Renderer network", props.shellState?.rendererNetwork ?? "disabled"],
            ["Navigation", props.shellState?.navigationPolicy ?? "app_only"]
          ]}
        />
      </section>

      <section className="content-card">
        <CardHeader title="Application" />
        <FactGrid
          rows={[
            ["UI", props.shellState?.appProtocolUrl ?? "app://index.html"],
            ["Integrity", integrityLabel(props.loadState, props.shellState)],
            ...props.snapshot.applicationSettings
          ]}
        />
      </section>
    </div>
  );
}

function SecurityBanner(props: { onAcknowledge: () => void }): React.JSX.Element {
  async function acknowledge(): Promise<void> {
    if (!window.vorcaro) {
      return;
    }

    await window.vorcaro.acknowledgeSecurityBanner({
      kind: "checkpoint_tripwire",
      acknowledgedAt: new Date().toISOString()
    });
    props.onAcknowledge();
  }

  return (
    <section className="security-banner" role="alert" aria-label="Security alert">
      <div>
        <p className="banner-title">Checkpoint tripwire slot</p>
        <p>
          Security banners remain visible until acknowledged. Acknowledgement is locally audited and does not
          resume sync by itself.
        </p>
      </div>
      <button type="button" className="secondary-action" onClick={() => void acknowledge()}>
        Acknowledge
      </button>
    </section>
  );
}

function MetricCard(props: { metric: Metric }): React.JSX.Element {
  return (
    <section className="metric-card">
      <div className="panel-title">
        <span>{props.metric.label}</span>
        {props.metric.status ? <StatusBadge state={props.metric.status} label={props.metric.status} /> : null}
      </div>
      <strong>{props.metric.value}</strong>
      <span>{props.metric.detail}</span>
    </section>
  );
}

function CardHeader(props: { title: string; status?: EventStatus }): React.JSX.Element {
  return (
    <div className="card-header">
      <h3>{props.title}</h3>
      {props.status ? <StatusBadge state={props.status} label={props.status} /> : null}
    </div>
  );
}

function VersionPanel(props: { title: string; body: string; status: EventStatus }): React.JSX.Element {
  return (
    <section className="version-panel">
      <div className="panel-title">
        <span>{props.title}</span>
        <StatusBadge state={props.status} label={props.status} />
      </div>
      <p>{props.body}</p>
    </section>
  );
}

function DataTable(props: { columns: string[]; rows: React.ReactNode[][] }): React.JSX.Element {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {props.columns.map((column) => (
              <th key={column}>{column}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {props.rows.map((row, rowIndex) => (
            <tr key={rowIndex}>
              {row.map((cell, cellIndex) => (
                <td key={`${rowIndex}-${cellIndex}`}>{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FactGrid(props: { rows: Array<[string, string]> }): React.JSX.Element {
  return (
    <dl className="fact-grid">
      {props.rows.map(([label, value]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function StatusBadge(props: { state: EventStatus; label: string }): React.JSX.Element {
  return (
    <span className={`status-badge ${props.state}`}>
      <span className="status-dot" aria-hidden="true" />
      <span>{props.label}</span>
    </span>
  );
}

function Money(props: { children: React.ReactNode }): React.JSX.Element {
  return <span className="money">{props.children}</span>;
}

function Mono(props: { children: React.ReactNode; title?: string }): React.JSX.Element {
  return (
    <span className="mono" title={props.title}>
      {props.children}
    </span>
  );
}

function integrityLabel(loadState: "loading" | "ready" | "failed", shellState: ShellState | null): string {
  if (loadState === "failed") {
    return "renderer bridge rejected";
  }

  if (!shellState) {
    return "loading";
  }

  return shellState.integrity === "verified" ? "verified" : "development unsigned";
}

const root = document.getElementById("root");

if (root) {
  createRoot(root).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>
  );
}
