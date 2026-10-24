"use server";

import { redirect } from "next/navigation";
import { validateTransfer } from "./bank.mjs";

export async function simulateTransfer(formData) {
  const payees = formData.getAll("payee");
  const amounts = formData.getAll("amount");
  if (payees.length !== 1 || amounts.length !== 1) {
    redirect("/?error=invalid_request");
  }

  const { transfer, error } = validateTransfer({ payee: payees[0], amount: amounts[0] });
  const query = new URLSearchParams(transfer
    ? { payee: transfer.payeeId, amount: transfer.amount }
    : { error });
  redirect("/?" + query.toString());
}

export async function greet(formData) {
  const name = String(formData.get("name") || "visitor").slice(0, 40);
  redirect("/?greeting=" + encodeURIComponent("Hello, " + name + "!"));
}
