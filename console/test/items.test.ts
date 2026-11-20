import assert from "node:assert/strict";
import test from "node:test";
import {
  emptyForm,
  fieldDisplay,
  formFromItem,
  historyLabel,
  itemEditBody,
} from "../src/items.ts";
import { MASK } from "../src/plain.ts";

test("itemEditBody omits unchanged secret values", () => {
  const body = itemEditBody({
    name: "svc",
    notes: "n",
    fields: [
      { name: "TOKEN", secret: true, value: "", untouched: true },
      { name: "REGION", secret: false, value: "eu", untouched: false },
    ],
  });
  assert.deepEqual(body.fields, [
    { name: "TOKEN", secret: true },
    { name: "REGION", secret: false, value: "eu" },
  ]);
  assert.ok(!("value" in (body.fields[0] as object)));
});

test("itemEditBody includes an edited secret value", () => {
  const body = itemEditBody({
    name: "svc",
    notes: "",
    fields: [{ name: "TOKEN", secret: true, value: "cu-test-new", untouched: false }],
  });
  assert.deepEqual(body.fields, [{ name: "TOKEN", secret: true, value: "cu-test-new" }]);
});

test("itemEditBody includes notes always", () => {
  assert.equal(itemEditBody(emptyForm()).notes, "");
});

test("fieldDisplay masks secrets until revealed", () => {
  assert.equal(fieldDisplay({ secret: true, value: "cu-test-hidden" }), MASK);
  assert.equal(fieldDisplay({ secret: false, value: "eu" }), "eu");
  assert.equal(fieldDisplay({ secret: true, unavailable: true }), "unavailable");
});

test("formFromItem marks secrets untouched and keeps plain values", () => {
  const form = formFromItem({
    name: "svc",
    notes: "hello",
    fields: [
      { name: "TOKEN", secret: true },
      { name: "REGION", secret: false, value: "eu" },
    ],
  });
  assert.deepEqual(form.fields, [
    { name: "TOKEN", secret: true, value: "", untouched: true },
    { name: "REGION", secret: false, value: "eu", untouched: false },
  ]);
});

test("historyLabel shows name and timestamp only", () => {
  assert.equal(
    historyLabel({ name: "TOKEN", superseded_at: "2026-11-18T10:00:00+00:00" }),
    "TOKEN · 2026-11-18T10:00:00+00:00",
  );
});
