import type { Response } from "express";

export function sendJson(response: Response, statusCode: number, body: unknown): void {
  response
    .status(statusCode)
    .type("application/json")
    .send(JSON.stringify(body, jsonReplacer));
}

export function jsonReplacer(_key: string, value: unknown): unknown {
  if (typeof value === "bigint") {
    return value.toString(10);
  }

  return value;
}
