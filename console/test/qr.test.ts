import assert from "node:assert/strict";
import test from "node:test";

import qrcode from "qrcode-generator";

import { qrGeometry } from "../src/qr.ts";

const URI = "otpauth://totp/Custos:operator?secret=JBSWY3DPEHPK3PXP&issuer=Custos";

test("the rendered modules are exactly the encoder's dark modules", () => {
  const qr = qrcode(0, "M");
  qr.addData(URI);
  qr.make();
  const n = qr.getModuleCount();
  let expected = 0;
  for (let y = 0; y < n; y += 1) {
    for (let x = 0; x < n; x += 1) if (qr.isDark(y, x)) expected += 1;
  }
  const geo = qrGeometry(URI);
  assert.equal(geo.dark, expected);
  assert.equal(geo.span, n + 8); // 4-module quiet zone on every side
  // every cell is a unit square offset by the quiet zone, inside the viewBox
  const cells = geo.path.match(/M(\d+) (\d+)h1v1h-1z/g) ?? [];
  assert.equal(cells.length, expected);
  for (const cell of cells) {
    const [, xs, ys] = cell.match(/M(\d+) (\d+)/) ?? [];
    const x = Number(xs);
    const y = Number(ys);
    assert.ok(x >= 4 && x < n + 4 && y >= 4 && y < n + 4, `cell out of range: ${cell}`);
  }
});

test("a different secret produces a different matrix", () => {
  const a = qrGeometry(URI);
  const b = qrGeometry(URI.replace("JBSWY3DPEHPK3PXP", "KRSXG5CTMVRXEZLU"));
  assert.notEqual(a.path, b.path);
});