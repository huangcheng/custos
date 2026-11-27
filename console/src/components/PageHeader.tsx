import type { ReactNode } from "react";

// One header rhythm for every screen: mono kicker, fluid title, lede, and
// the page's primary action level with the title's first line. The lede is a
// paragraph, so it is typed as text — block content cannot nest in a <p>.
export function PageHeader({
  kicker,
  title,
  lede,
  actions,
}: {
  kicker: string;
  title: string;
  lede: string;
  actions?: ReactNode;
}) {
  return (
    <div className="page-head">
      <div className="page-intro">
        <p className="page-kicker">{kicker}</p>
        <h1 className="page-title">{title}</h1>
        <p className="page-sub">{lede}</p>
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </div>
  );
}
