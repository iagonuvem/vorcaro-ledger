import type { ExecutiveWorkspaceSnapshot } from "../ipc/contract.js";

export function getExecutiveWorkspaceSnapshot(): ExecutiveWorkspaceSnapshot {
  return {
    metrics: [
      { label: "Accepted cash position", value: "USD 12,480,000", detail: "+ USD 120,000 pending", status: "accepted" },
      { label: "Pending approvals", value: "USD 780,000", detail: "3 operations require a signature", status: "pending" },
      { label: "Open conflicts", value: "2", detail: "Governance resolution required", status: "conflicted" },
      { label: "Last verified sequence", value: "912,388", detail: "Checkpoint age 4m 12s", status: "accepted" }
    ],
    accounts: [
      {
        entity: "Vorcaro Enterprises",
        account: "Operating Treasury",
        acceptedBalance: "USD 8,420,000",
        pendingDelta: "+ USD 120,000 pending",
        status: "accepted",
        sequence: "912,388"
      },
      {
        entity: "Vorcaro Holdings",
        account: "Tax Reserve",
        acceptedBalance: "USD 2,340,000",
        pendingDelta: "none",
        status: "accepted",
        sequence: "912,376"
      },
      {
        entity: "Vorcaro Labs",
        account: "Vendor Clearing",
        acceptedBalance: "EUR 1,580,000",
        pendingDelta: "- EUR 42,000 pending",
        status: "pending",
        sequence: "912,351"
      }
    ],
    flows: [
      { kind: "Inflow", counterparty: "Atlas Bank sweep", amount: "USD 420,000", status: "accepted", utc: "2026-07-05T15:12:02Z" },
      { kind: "Outflow", counterparty: "Data center invoice", amount: "USD 780,000", status: "pending", utc: "2026-07-05T14:48:19Z" },
      { kind: "Outflow", counterparty: "Legacy vendor correction", amount: "USD 18,400", status: "rejected", utc: "2026-07-05T12:09:44Z" }
    ],
    approvals: [
      {
        object: "PAYMENT_REQUESTED / pay_9921",
        amount: "USD 780,000",
        policy: "CFO + CEO required above USD 500,000",
        progress: "1 of 2 signatures",
        status: "pending",
        sequence: "base 912,388"
      },
      {
        object: "BUDGET_OVERRIDDEN / bud_q4_ops",
        amount: "USD 1,200,000",
        policy: "Finance governance required",
        progress: "0 of 3 signatures",
        status: "pending",
        sequence: "base 912,381"
      },
      {
        object: "DATA_EXPORTED / exp_internal_audit",
        amount: "USD 0",
        policy: "Internal Audit + CFO required",
        progress: "2 of 2 signatures",
        status: "accepted",
        sequence: "912,322"
      }
    ],
    conflicts: [
      {
        object: "FORECAST_ADJUSTED / forecast_q4_cash",
        acceptedVersion: "CEO online forecast accepted at sequence 912,344.",
        conflictingVersion: "CFO offline forecast arrived from base sequence 912,190.",
        sequence: "912,367",
        status: "conflicted",
        aiProposal: "AI analysis - advisory: compare burn-rate assumptions before drafting CONFLICT_RESOLVED."
      },
      {
        object: "VENDOR_UPDATED / vendor_datacenter_017",
        acceptedVersion: "Treasury changed payment terms to net 30.",
        conflictingVersion: "Controller changed payment terms to net 45 from stale state.",
        sequence: "912,370",
        status: "conflicted",
        aiProposal: "AI analysis - advisory: policy metadata shows no payment has been approved against either version."
      }
    ],
    ledgerRows: [
      {
        event: "PAYMENT_APPROVAL_CREATED",
        object: "pay_9921",
        actor: "exec_cfo_001",
        status: "pending",
        sequence: "pending",
        keyVersion: "key v7",
        device: "dev_vorcaro_laptop_044",
        hash: "sha256:3fa8...c91d",
        utc: "2026-07-05T14:48:19Z"
      },
      {
        event: "BANK_STATEMENT_IMPORTED",
        object: "stmt_2026_07_05",
        actor: "exec_treasurer_002",
        status: "accepted",
        sequence: "912,388",
        keyVersion: "key v6",
        device: "dev_treasury_018",
        hash: "sha256:02bc...8a77",
        utc: "2026-07-05T15:12:02Z"
      },
      {
        event: "TRANSACTION_CLASSIFIED",
        object: "txn_7763",
        actor: "exec_controller_004",
        status: "rejected",
        sequence: "912,361",
        keyVersion: "key v5",
        device: "dev_finance_031",
        hash: "sha256:7d44...11b0",
        utc: "2026-07-05T12:09:44Z"
      },
      {
        event: "FORECAST_ADJUSTED",
        object: "forecast_q4_cash",
        actor: "exec_cfo_001",
        status: "conflicted",
        sequence: "912,367",
        keyVersion: "key v7",
        device: "dev_vorcaro_laptop_044",
        hash: "sha256:81aa...4fe2",
        utc: "2026-07-05T13:28:01Z"
      }
    ],
    checkpoints: [
      { sequence: "912,388", hash: "sha256:54e0...ac92", verifiedAt: "2026-07-05T15:16:14Z", status: "accepted" },
      { sequence: "912,000", hash: "sha256:9db4...12cc", verifiedAt: "2026-07-05T13:02:04Z", status: "accepted" },
      { sequence: "911,500", hash: "sha256:221c...73af", verifiedAt: "2026-07-05T10:44:28Z", status: "accepted" }
    ],
    exportRequests: [
      {
        name: "Board cash packet",
        scope: "Cash position, accounts, inflows/outflows",
        format: "Encrypted archive",
        status: "pending",
        policy: "DATA_EXPORTED requires CFO + Internal Audit"
      },
      {
        name: "Internal audit evidence",
        scope: "Ledger events 912,000-912,388",
        format: "Encrypted archive",
        status: "accepted",
        policy: "Plaintext not permitted for this role"
      }
    ],
    syncFacts: [
      ["Connection", "online, chain verified"],
      ["Last verified sequence", "912,388"],
      ["Pending events", "3"],
      ["Revocation list", "version 18"],
      ["Active policy", "version 42"]
    ],
    deviceFacts: [
      ["Device", "dev_vorcaro_laptop_044"],
      ["Certificate", "expires 2026-08-04T00:00:00Z"],
      ["Key version", "7"]
    ],
    securitySettings: [
      ["Auto-lock", "10 minutes"],
      ["Suspend behavior", "lock vault"]
    ],
    applicationSettings: [
      ["Appearance", "dark only"],
      ["Remote UI", "disabled"]
    ],
    advisoryText:
      "Analysis suggests the accepted cash position covers scheduled outflows for 42 days. Pending payment `pay_9921` is excluded from accepted totals until the server acknowledges it.",
    signatureConsequence:
      "Signing creates a local `pending` event. It is not corporate truth until a signed server acknowledgement marks it `accepted`, `rejected`, or `conflicted`.",
    conflictResolutionConsequence: "A resolution appends `CONFLICT_RESOLVED`. It never edits or hides either conflicting event.",
    exportWarning: "Plaintext export is disabled until policy permits it and a signed `DATA_EXPORTED` event is accepted."
  };
}
