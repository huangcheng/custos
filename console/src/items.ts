// Item form ⇄ API body (§6). The rule that makes masked round-trips safe:
// a secret field whose value the operator did not touch is sent WITHOUT
// `value`, which the server reads as "keep the stored ciphertext".
//
// Kept free of React so node:test can pin it.

import { MASK } from "./plain.ts";

export type FieldDraft = {
  name: string;
  secret: boolean;
  value: string;
  /** true when the value came from the server masked and was not edited */
  untouched: boolean;
};

export type ItemForm = {
  name: string;
  notes: string;
  fields: FieldDraft[];
};

export function itemEditBody(form: ItemForm): {
  notes: string;
  fields: Record<string, unknown>[];
} {
  return {
    notes: form.notes, // §6: required on PUT/PATCH — absent would drop notes
    fields: form.fields.map((field) => {
      if (field.secret && field.untouched) {
        return { name: field.name, secret: true };
      }
      return { name: field.name, secret: field.secret, value: field.value };
    }),
  };
}

export function fieldDisplay(field: {
  secret: boolean;
  value?: string;
  unavailable?: boolean;
}): string {
  if (field.unavailable) return "unavailable";
  if (field.secret) return MASK;
  return field.value ?? "";
}

export function historyLabel(row: {
  name: string;
  superseded_at: string;
}): string {
  return `${row.name} · ${row.superseded_at}`;
}

export function revisionEtag(revision: number): string {
  return String(revision);
}

export function emptyForm(): ItemForm {
  return { name: "", notes: "", fields: [] };
}

export function formFromItem(item: {
  name: string;
  notes: string;
  fields: { name: string; secret: boolean; value?: string }[];
}): ItemForm {
  return {
    name: item.name,
    notes: item.notes,
    fields: item.fields.map((field) => ({
      name: field.name,
      secret: field.secret,
      value: field.secret ? "" : (field.value ?? ""),
      untouched: field.secret,
    })),
  };
}