import { useMemo } from "react";

import { qrGeometry } from "../qr";

/** Render an otpauth:// URI as a scannable QR (SVG: crisp at any zoom, no
 *  canvas, no network). The secret stays available as text for manual entry —
 *  the QR is the fast path, not the only path. */
export function QrCode({ value, size = 196 }: { value: string; size?: number }) {
  // mask search is the expensive part; the matrix depends only on value
  const { span, path } = useMemo(() => qrGeometry(value), [value]);
  return (
    <svg
      role="img"
      aria-label="Authenticator enrolment QR code"
      data-testid="totp-qr"
      width={size}
      height={size}
      viewBox={`0 0 ${span} ${span}`}
      shapeRendering="crispEdges"
      className="qr"
    >
      <rect width={span} height={span} fill="#fff" />
      <path d={path} fill="#000" />
    </svg>
  );
}