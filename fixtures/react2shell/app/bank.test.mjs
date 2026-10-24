import test from "node:test";
import assert from "node:assert/strict";
import {
  DEMO_PAYEES, SAVINGS_BALANCE_PENCE, STARTING_BALANCE_PENCE,
  TRANSFER_ERRORS, formatGBP, readTransfer, validateTransfer,
} from "./bank.mjs";

test("GBP formatting uses integer pence, including negative and large values", () => {
  assert.equal(formatGBP(STARTING_BALANCE_PENCE), "£12,480.50");
  assert.equal(formatGBP(SAVINGS_BALANCE_PENCE), "£8,250.00");
  assert.equal(formatGBP(0), "£0.00");
  assert.equal(formatGBP(1), "£0.01");
  assert.equal(formatGBP(-109), "-£1.09");
  assert.equal(formatGBP(Number.MAX_SAFE_INTEGER), "£90,071,992,547,409.91");
  for (const invalid of [1.1, NaN, Infinity, "100", Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => formatGBP(invalid), TypeError);
  }
});

test("decimal GBP is parsed exactly and redirects can use a canonical decimal", () => {
  for (const [amount, pence, canonical] of [
    ["0.01", 1, "0.01"], ["0.29", 29, "0.29"], ["1", 100, "1.00"],
    ["1.2", 120, "1.20"], ["1.23", 123, "1.23"], ["0001.23", 123, "1.23"],
    ["12480.50", STARTING_BALANCE_PENCE, "12480.50"],
  ]) {
    const result = validateTransfer({ payee: "alex", amount });
    assert.equal(result.error, null, amount);
    assert.deepEqual(result.transfer, {
      payeeId: "alex", payeeName: "Alex Morgan", amountPence: pence,
      amount: canonical, remainingPence: STARTING_BALANCE_PENCE - pence,
    });
  }
});

test("all recipients are fixed fictional payees", () => {
  assert.equal(DEMO_PAYEES.length, 3);
  assert.ok(Object.isFrozen(DEMO_PAYEES));
  for (const payee of DEMO_PAYEES) {
    assert.ok(Object.isFrozen(payee));
    assert.match(payee.detail, /Fictional/);
    assert.equal(validateTransfer({ payee: payee.id, amount: "10" }).transfer.payeeName, payee.name);
  }
  for (const payee of ["unknown", "https://example.com", "//example.com", "__proto__", "constructor", "alex\n", ["alex"], {}, null, 1]) {
    assert.deepEqual(validateTransfer({ payee, amount: "1" }), { transfer: null, error: "invalid_payee" });
  }
});

test("nonpositive, malformed, exponent and non-string amounts are rejected", () => {
  for (const amount of [
    "", "0", "0.00", "-1", "+1", "NaN", "Infinity", "1e2", "1E2", "1e309",
    "1.234", ".50", "1.", "£1", "1,000.00", " 1 ", "1\n", "1/2", "0x10",
    "1234567890", "999999999999999999999999999999", 1, NaN, undefined, null, ["1"], {},
  ]) {
    assert.deepEqual(validateTransfer({ payee: "alex", amount }), {
      transfer: null, error: "invalid_amount",
    }, String(amount));
  }
  for (const amount of ["12480.51", "12481", "999999999.99"]) {
    assert.deepEqual(validateTransfer({ payee: "alex", amount }), {
      transfer: null, error: "insufficient_funds",
    });
  }
});

test("query previews accept only validated transfer fields and bounded error codes", () => {
  assert.deepEqual(readTransfer(), { transfer: null, error: null });
  assert.deepEqual(readTransfer({}), { transfer: null, error: null });
  assert.deepEqual(readTransfer({ greeting: "Hello, visitor!" }), { transfer: null, error: null });
  for (const error of Object.keys(TRANSFER_ERRORS)) {
    assert.deepEqual(readTransfer({ error }), { transfer: null, error });
  }
  for (const error of ["<script>alert(1)</script>", "https://evil.example", "__proto__", "constructor", "toString", ["invalid_amount"], {}, null]) {
    assert.deepEqual(readTransfer({ error }), { transfer: null, error: "invalid_request" });
  }
  assert.deepEqual(readTransfer({ error: "invalid_amount", payee: "alex", amount: "1" }), {
    transfer: null, error: "invalid_request",
  });
  assert.equal(readTransfer({ payee: ["alex", "birch"], amount: "1" }).transfer, null);
  assert.equal(readTransfer({ payee: "alex", amount: ["1", "2"] }).transfer, null);
  assert.equal(readTransfer({ payee: "alex" }).transfer, null);
  assert.equal(readTransfer({ amount: "1" }).transfer, null);
  for (const malformed of [null, [], "payee=alex&amount=1", 1]) {
    assert.deepEqual(readTransfer(malformed), { transfer: null, error: "invalid_request" });
  }
});

test("a transfer is only one deterministic page preview, never enduring state", () => {
  const parameters = { payee: "birch", amount: "25.50" };
  const first = readTransfer(parameters);
  const second = readTransfer(parameters);
  assert.deepEqual(first, second);
  assert.equal(first.transfer.remainingPence, STARTING_BALANCE_PENCE - 2550);
  first.transfer.remainingPence = 0;
  assert.equal(readTransfer(parameters).transfer.remainingPence, STARTING_BALANCE_PENCE - 2550);
  assert.deepEqual(readTransfer({}), { transfer: null, error: null });
  assert.equal(STARTING_BALANCE_PENCE, 1_248_050);
  assert.equal(SAVINGS_BALANCE_PENCE, 825_000);
  assert.equal(validateTransfer(Object.create(parameters)).transfer, null);
});
