import qrcode from "qrcode-generator";

/** Pure geometry for the enrolment QR — exported so a unit test can check the
 *  rendered modules against the encoder itself (an SVG that "looks like a QR"
 *  is not proof it scans). */
export function qrGeometry(value: string): { span: number; path: string; dark: number } {
  const qr = qrcode(0, "M");
  qr.addData(value);
  qr.make();
  const count = qr.getModuleCount();
  const quiet = 4; // the spec's quiet zone
  const cells: string[] = [];
  for (let y = 0; y < count; y += 1) {
    for (let x = 0; x < count; x += 1) {
      if (qr.isDark(y, x)) cells.push(`M${x + quiet} ${y + quiet}h1v1h-1z`);
    }
  }
  return { span: count + quiet * 2, path: cells.join(""), dark: cells.length };
}
