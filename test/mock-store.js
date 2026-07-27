'use strict';

// SADECE TEST içindir. Gerçek dağıtımda services/auth-service.js içindeki
// `createSessionStoreAdapter(db)` fonksiyonu @fitfak/database'in DatabaseManager/collection
// API'sine göre AYNI arayüzü uygular (bkz. o dosyadaki yorum). Burada tutulan her şey
// process belleğinde yaşar ve process kapanınca kaybolur -- bu tam olarak neden bunun bir
// "mock" olduğu ve gerçek bir DatabaseManager'ın (şifreli-disk kalıcılığı olan) yerini
// ASLA almaması gerektiğidir.
function createMockStore() {
  const sessions = new Map(); // sessionId -> session
  const refreshTokens = new Map(); // hash -> record

  return {
    async createSession(rec) {
      sessions.set(rec.sessionId, { ...rec });
    },
    async getSessionById(sessionId) {
      return sessions.get(sessionId) || null;
    },
    async touchSession(sessionId, { lastSeenAt, ip, userAgent }) {
      const s = sessions.get(sessionId);
      if (!s) return;
      s.lastSeenAt = lastSeenAt;
      if (ip) s.ip = ip;
      if (userAgent) s.userAgent = userAgent;
    },
    async addAudienceToSession(sessionId, clientId) {
      const s = sessions.get(sessionId);
      if (!s) return;
      const current = s.audiences || ['self'];
      if (!current.includes(clientId)) s.audiences = [...current, clientId];
    },
    async revokeSession(sessionId, reason) {
      const s = sessions.get(sessionId);
      if (!s) return;
      s.revoked = true;
      s.revokedReason = reason;
    },
    async listSessionsForUser(userId) {
      return [...sessions.values()].filter((s) => s.userId === userId);
    },
    async insertRefreshToken(rec) {
      refreshTokens.set(rec.hash, { ...rec });
    },
    async findRefreshTokenByHash(hash) {
      return refreshTokens.get(hash) || null;
    },
    async markRefreshTokenUsed(hash, { usedAt }) {
      const r = refreshTokens.get(hash);
      if (r) { r.used = true; r.usedAt = usedAt; }
    },
    // sadece testler/debug için iç durumu gözlemleme yardımcıları:
    _debugAllSessions: () => [...sessions.values()],
    _debugAllRefreshTokens: () => [...refreshTokens.values()],
  };
}

module.exports = { createMockStore };
