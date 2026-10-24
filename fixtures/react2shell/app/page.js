import { simulateTransfer } from "./actions";
import applicationPackage from "../package.json";
import { DEMO_PAYEES, SAVINGS_BALANCE_PENCE, STARTING_BALANCE_PENCE, TRANSFER_ERRORS, formatGBP, readTransfer } from "./bank.mjs";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const transactions = [
  { name: "Demo payroll", category: "Income", date: "Today", amount: 265000, initials: "DP" },
  { name: "Cedar & Co.", category: "Groceries", date: "Today", amount: -4250, initials: "C" },
  { name: "City Rail", category: "Travel", date: "Yesterday", amount: -1840, initials: "CR" },
  { name: "The Corner Café", category: "Food & drink", date: "Yesterday", amount: -685, initials: "CC" },
  { name: "Birch Utilities", category: "Household", date: "22 Oct", amount: -7800, initials: "BU" },
];

export default async function Home({ searchParams }) {
  const { transfer, error } = readTransfer(await searchParams);
  const currentBalance = transfer?.remainingPence ?? STARTING_BALANCE_PENCE;
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  const gid = typeof process.getgid === "function" ? process.getgid() : null;

  return (
    <div className="bank-shell">
      <aside className="sidebar" aria-label="Application sidebar">
        <a className="bank-brand" href="/" aria-label="The British Bank demo home">
          <span className="brand-mark" aria-hidden="true">B.</span>
          <span>The British Bank<span className="brand-caption">Fictional banking sandbox</span></span>
        </a>
        <p className="nav-label">Your workspace</p>
        <nav aria-label="Main navigation">
          <a className="nav-overview" href="#overview"><span aria-hidden="true">01</span> Overview</a>
          <a href="#activity"><span aria-hidden="true">02</span> Activity</a>
          <a href="#transfer"><span aria-hidden="true">03</span> Transfer</a>
          <a href="#environment"><span aria-hidden="true">04</span> Environment</a>
        </nav>
        <div className="sidebar-bottom">
          <span className="customer-avatar" aria-hidden="true">JT</span>
          <div><strong>Jamie Taylor</strong><span>Fictional customer</span></div>
        </div>
      </aside>

      <main id="main-content" className="main-content">
        <header className="page-header">
          <div><p className="eyebrow">Your everyday, at a glance</p><h1>Account overview</h1></div>
          <span className="demo-label"><span aria-hidden="true" />Local demo</span>
        </header>

        <aside className="safety-note" aria-label="Local demo safety warning">
          <span className="warning-mark" aria-hidden="true">!</span>
          <div><strong>Fictional bank. Intentionally vulnerable.</strong><p>Local use only. Balances, payees and activity are dummy data. No bank is connected. Never expose this app publicly or add real secrets.</p></div>
        </aside>

        <section id="overview" className="overview-section" aria-labelledby="accounts-title">
          <div className="section-heading"><h2 id="accounts-title">Your accounts</h2><span>GBP · British pound</span></div>
          <div className="account-grid">
            <article className="account-card current-account">
              <div className="account-topline"><span>Current account</span><span className="account-symbol" aria-hidden="true">£</span></div>
              <p className="balance">{formatGBP(currentBalance)}</p>
              <div className="account-bottomline"><span>{transfer ? "Balance after demo preview" : "Fictional available balance"}</span><a href="#transfer">Simulate transfer <span aria-hidden="true">↗</span></a></div>
            </article>
            <article className="account-card savings-account">
              <div className="account-topline"><span>Savings account</span><span className="account-symbol" aria-hidden="true">£</span></div>
              <p className="balance">{formatGBP(SAVINGS_BALANCE_PENCE)}</p>
              <div className="account-bottomline"><span>Fictional savings balance</span><span className="savings-caption">A little set aside.</span></div>
            </article>
          </div>
        </section>

        <div className="content-grid">
          <section id="activity" className="activity-panel panel" aria-labelledby="activity-title">
            <div className="panel-heading"><div><p className="eyebrow">The details</p><h2 id="activity-title">Recent activity</h2></div><span className="small-note">Seeded examples</span></div>
            <div className="transaction-labels" aria-hidden="true"><span>Transaction</span><span>Amount</span></div>
            <ul className="transaction-list" aria-label="Fictional recent transactions">
              {transfer && (
                <li className="transaction preview-transaction">
                  <span className="transaction-icon" aria-hidden="true">↗</span>
                  <div className="transaction-description"><strong>{transfer.payeeName}</strong><span>Simulated transfer · URL preview</span></div>
                  <div className="transaction-value"><strong>−{formatGBP(transfer.amountPence)}</strong><span>Preview only</span></div>
                </li>
              )}
              {transactions.map((transaction) => (
                <li className="transaction" key={transaction.name}>
                  <span className="transaction-icon" aria-hidden="true">{transaction.initials}</span>
                  <div className="transaction-description"><strong>{transaction.name}</strong><span>{transaction.category} · {transaction.date}</span></div>
                  <div className="transaction-value"><strong className={transaction.amount > 0 ? "incoming" : undefined}>{transaction.amount > 0 ? "+" : ""}{formatGBP(transaction.amount)}</strong><span>GBP</span></div>
                </li>
              ))}
            </ul>
            <p className="activity-footnote">An illustrative history, not a live or persistent account ledger.</p>
          </section>

          <section id="transfer" className="transfer-panel panel" aria-labelledby="transfer-title">
            <div className="panel-heading"><div><p className="eyebrow">Try the application</p><h2 id="transfer-title">Simulate transfer</h2></div><span className="transfer-arrow" aria-hidden="true">↗</span></div>
            <p className="panel-copy">Preview a transfer to a fictional payee using a real Next.js server action.</p>
            <form action={simulateTransfer} aria-describedby="transfer-note">
              <div className="form-field">
                <label htmlFor="payee">Demo payee</label>
                <select id="payee" name="payee" defaultValue={transfer?.payeeId ?? DEMO_PAYEES[0].id} required aria-invalid={error === "invalid_payee" || undefined} aria-describedby={error ? "transfer-error" : undefined}>
                  {DEMO_PAYEES.map((payee) => <option key={payee.id} value={payee.id}>{payee.name}</option>)}
                </select>
              </div>
              <div className="form-field">
                <label htmlFor="amount">Amount in GBP</label>
                <div className="amount-input"><span aria-hidden="true">£</span><input id="amount" name="amount" type="text" inputMode="decimal" defaultValue={transfer?.amount ?? "25.00"} maxLength={12} placeholder="0.00" required autoComplete="off" aria-invalid={error === "invalid_amount" || error === "insufficient_funds" || undefined} aria-describedby={error ? "amount-hint transfer-error" : "amount-hint"} /></div>
                <p id="amount-hint" className="field-hint">Positive amounts, with up to two decimal places.</p>
              </div>
              {error && <p id="transfer-error" className="transfer-error" role="alert">{TRANSFER_ERRORS[error]}</p>}
              <button type="submit">Simulate transfer <span aria-hidden="true">→</span></button>
            </form>
            {transfer && <div className="transfer-result" role="status"><strong>Demo preview ready</strong><p>{formatGBP(transfer.amountPence)} to {transfer.payeeName}. The balance and activity above reflect this one preview.</p></div>}
            <div className="transfer-note" id="transfer-note"><p>Only this page’s URL changes. No money moves and nothing is saved to an account.</p><a href="/">Reset demo <span aria-hidden="true">↺</span></a></div>
          </section>
        </div>

        <section id="environment" className="environment-panel" aria-labelledby="environment-title">
          <div className="environment-intro"><p className="eyebrow">BreachBench / runtime evidence</p><h2 id="environment-title">Container hardening lab</h2><p>Live process identity, not a security verdict.</p><a href="/api/health">View health endpoint <span aria-hidden="true">↗</span></a></div>
          <dl className="runtime-facts">
            <div><dt>Effective UID / GID</dt><dd>{uid ?? "unavailable"} / {gid ?? "unavailable"}</dd></div>
            <div><dt>Process user</dt><dd>{uid === null ? "unavailable" : uid === 0 ? "root" : "non-root"}</dd></div>
            <div><dt>Next.js / React dependencies</dt><dd>{applicationPackage.dependencies.next} / {applicationPackage.dependencies.react}</dd></div>
            <div><dt>Node.js / platform</dt><dd>{process.version} · {process.platform}/{process.arch}</dd></div>
          </dl>
        </section>

        <footer className="page-footer"><p>The British Bank is a fictional interface for a local security lab.</p><p>Hardening does not patch React2Shell. CLI checks cover listed shells and protected writes, not network reachability.</p></footer>
      </main>
    </div>
  );
}
