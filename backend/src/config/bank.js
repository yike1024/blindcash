// config/bank.js — bank-side protocol constants
//
// v3 §2.3: cut-and-choose default N=100 (1% cheat probability).
// For live demos you can lower this to 10 to make the 4-move flow finish
// faster — but the outline requires documentation to explicitly mark this as
// "demo only; production uses N=100".
//
// v3 §2.1: domain separation tag for H("blindcash-v1" ‖ data). This tag is
// mixed into the hash-to-scalar function (crypto/server/hashToScalar.js)
// so the same (R', serial, amount) tuple cannot be replayed against a
// different protocol/chain.

/**
 * Cut-and-choose candidate count. N=100 → 1% cheat probability.
 * Override to 10 ONLY for demo runs (set BC_DEMO_N=10 in env).
 */
export const CUT_AND_CHOOSE_N = Number(process.env.BC_DEMO_N) || 100;

/**
 * Withdrawal session TTL in milliseconds. After this, a pending/submitted
 * session is eligible for lazy-cleanup refund on the user's next init/submit.
 * Default: 5 minutes — long enough for a demo, short enough to bound the
 * "abandoned but balance held" window.
 */
export const SESSION_TTL_MS = Number(process.env.BC_SESSION_TTL_MS) || 5 * 60 * 1000;

/**
 * Domain separation tag for the blind-signing hash. Mixed into H(tag ‖ data)
 * to prevent cross-protocol signature reuse.
 *
 * NOTE: changing this tag invalidates every previously-issued token.
 */
export const TOKEN_DOMAIN_TAG = 'blindcash-v1';

/**
 * Bank keys singleton row id. The bank_keys table is constrained by
 * CHECK(id = 1) — there is exactly one signing keypair per bank.
 */
export const BANK_KEY_ROW_ID = 1;
