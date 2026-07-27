'use strict';

class AppError extends Error {
  constructor(code, message, { httpStatus = 400 } = {}) {
    super(message);
    this.code = code;
    this.httpStatus = httpStatus;
  }
}

module.exports = { AppError };
