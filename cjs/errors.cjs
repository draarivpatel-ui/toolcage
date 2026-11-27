// Typed errors and stable machine-readable validation codes.

class ToolCageError extends Error {
  constructor(code, message, details) {
    super(message);
    this.name = 'ToolCageError';
    this.code = code;
    if (details !== undefined) this.details = deepFreezeCopy(details);
  }
}

function failure(code, message, path = '$') {
  return { code, message, path };
}

function invalidResult(errors) {
  return { ok: false, errors };
}

function deepFreezeCopy(value) {
  if (Array.isArray(value)) {
    return Object.freeze(value.map((entry) => deepFreezeCopy(entry)));
  }
  if (value !== null && typeof value === 'object') {
    const copy = {};
    for (const key of Object.keys(value)) copy[key] = deepFreezeCopy(value[key]);
    return Object.freeze(copy);
  }
  return value;
}

function errorMessage(error) {
  if (error instanceof Error && typeof error.message === 'string') return error.message;
  return String(error);
}

exports.ToolCageError = ToolCageError;
exports.failure = failure;
exports.invalidResult = invalidResult;
exports.deepFreezeCopy = deepFreezeCopy;
exports.errorMessage = errorMessage;
