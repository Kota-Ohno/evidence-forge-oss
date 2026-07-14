const CODE = /^[A-Z][A-Z0-9_]{2,63}$/u;

export class DiagnosticError extends Error {
  readonly code: string;
  constructor(code: string, message: string, options?: ErrorOptions) {
    if (!CODE.test(code)) throw new Error("Diagnostic code must be 3-64 uppercase identifier characters");
    super(message, options);
    this.name = "DiagnosticError";
    this.code = code;
  }
}

export function diagnosticError(code: string, message: string, options?: ErrorOptions): DiagnosticError {
  return new DiagnosticError(code, message, options);
}

export function diagnosticCode(error: unknown, fallback: string): string {
  if (!CODE.test(fallback)) throw new Error("Fallback diagnostic code is invalid");
  return error instanceof DiagnosticError ? error.code : fallback;
}
