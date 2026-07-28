'use strict';

class AppError extends Error {
  constructor(code, message, { httpStatus = 400, retryAfterSeconds } = {}) {
    super(message);
    this.code = code;
    this.httpStatus = httpStatus;
    // 429'larda `Retry-After` başlığı için. İstemciye "ne zaman" demeden
    // "çok sık" demek, onu daha sık denemeye iter.
    if (retryAfterSeconds !== undefined) this.retryAfterSeconds = retryAfterSeconds;
  }
}

module.exports = { AppError };
