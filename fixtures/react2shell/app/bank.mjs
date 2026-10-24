// Fictional funds and recipients: every transfer is a URL-only preview, not a payment.
export const STARTING_BALANCE_PENCE = 1_248_050;
export const SAVINGS_BALANCE_PENCE = 825_000;

export const DEMO_PAYEES = Object.freeze([
  Object.freeze({ id: "alex", name: "Alex Morgan", detail: "Fictional demo payee" }),
  Object.freeze({ id: "birch", name: "Birch Utilities", detail: "Fictional demo payee" }),
  Object.freeze({ id: "harbour", name: "Harbour Lettings", detail: "Fictional demo payee" }),
]);

export const TRANSFER_ERRORS = Object.freeze({
  invalid_request: "This demo preview is invalid. Please try again.",
  invalid_payee: "Choose one of the fictional demo payees.",
  invalid_amount: "Enter a positive GBP amount with no more than two decimal places.",
  insufficient_funds: "The amount exceeds the fictional current-account balance.",
});

export function formatGBP(pence) {
  if (!Number.isSafeInteger(pence)) throw new TypeError("GBP values must be integer pence");
  const value = BigInt(pence);
  const absolute = value < 0n ? -value : value;
  return `${value < 0n ? "-" : ""}£${(absolute / 100n).toLocaleString("en-GB")}.${String(absolute % 100n).padStart(2, "0")}`;
}

function failure(error) {
  return { transfer: null, error };
}

function isParameters(parameters) {
  return parameters !== null && typeof parameters === "object" && !Array.isArray(parameters);
}

export function validateTransfer(parameters) {
  if (!isParameters(parameters)) return failure("invalid_request");
  const payee = Object.hasOwn(parameters, "payee")
    ? DEMO_PAYEES.find(({ id }) => id === parameters.payee)
    : undefined;
  if (!payee) return failure("invalid_payee");

  const amount = Object.hasOwn(parameters, "amount") ? parameters.amount : undefined;
  if (typeof amount !== "string" || !/^\d{1,9}(?:\.\d{1,2})?$/.test(amount)) {
    return failure("invalid_amount");
  }
  const [pounds, fraction = ""] = amount.split(".");
  const pence = BigInt(pounds) * 100n + BigInt(fraction.padEnd(2, "0"));
  if (pence <= 0n) return failure("invalid_amount");
  if (pence > BigInt(STARTING_BALANCE_PENCE)) return failure("insufficient_funds");

  const amountPence = Number(pence);
  return {
    transfer: {
      payeeId: payee.id,
      payeeName: payee.name,
      amountPence,
      amount: `${pence / 100n}.${String(pence % 100n).padStart(2, "0")}`,
      remainingPence: STARTING_BALANCE_PENCE - amountPence,
    },
    error: null,
  };
}

export function readTransfer(parameters = {}) {
  if (!isParameters(parameters)) return failure("invalid_request");
  const hasTransfer = Object.hasOwn(parameters, "payee") || Object.hasOwn(parameters, "amount");
  if (Object.hasOwn(parameters, "error")) {
    const error = parameters.error;
    return failure(!hasTransfer && typeof error === "string" && Object.hasOwn(TRANSFER_ERRORS, error)
      ? error : "invalid_request");
  }
  return hasTransfer ? validateTransfer(parameters) : { transfer: null, error: null };
}
