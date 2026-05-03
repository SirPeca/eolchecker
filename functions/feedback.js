// =========================================
// EOL & CVE Checker — functions/feedback.js  v9
//
// Secure feedback endpoint — POST /feedback
//
// Security measures (audience: pentesters):
//  1. Input sanitization — strip all HTML/JS, length limits
//  2. Honeypot field — bots fill it, humans don't
//  3. Rate limiting — same KV namespace, 5 feedbacks/IP/hour
//  4. Content validation — must have meaningful text
//  5. No reflection — never echo user input back in response
//  6. Structured storage — KV with TTL, no persistent DB
//  7. CSP-safe — no inline scripts, all via Worker
//  8. Anti-spam patterns — detect obvious injection attempts
// =========================================

const FEEDBACK_RATE_LIMIT  = 5;
const FEEDBACK_WINDOW      = 3600; // 1 hour
const FEEDBACK_TTL         = 86400 * 30; // 30 days retention
const MAX_MESSAGE_LEN      = 500;
const MIN_MESSAGE_LEN      = 10;
const MAX_TECH_LEN         = 80;

// Patterns that indicate injection/abuse attempts
// If matched → silently accept but don't store (tar pit)
const ABUSE_PATTERNS = [
  /<script/i,
  /javascript:/i,
  /on\w+\s*=/i,          // onload=, onclick=, etc.
  /union\s+select/i,     // SQL injection
  /\bexec\s*\(/i,        // code execution
  /\beval\s*\(/i,
  /\$\{.*\}/,            // template injection
  /\.\.\//,              // path traversal
  /%[0-9a-f]{2}/i,       // URL encoding attempts
  /\x00/,                // null bytes
  /data:text\/html/i,    // data URI
];

function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type':              'application/json',
      'Cache-Control':             'no-store',
      'Access-Control-Allow-Origin': '*',
      'X-Content-Type-Options':   'nosniff',
      'X-Frame-Options':           'DENY',
    }
  });
}

function sanitize(s, maxLen = 200) {
  return String(s || '')
    .replace(/[<>&"'`]/g, '')          // strip HTML special chars
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '') // strip control chars
    .trim()
    .slice(0, maxLen);
}

function hasAbusePattern(text) {
  return ABUSE_PATTERNS.some(p => p.test(text));
}

async function checkFeedbackRateLimit(env, ip) {
  if (!env?.RATE_LIMIT) return { limited: false };
  const key = `fb_rl:${ip}`;
  try {
    const raw   = await env.RATE_LIMIT.get(key);
    const count = raw ? parseInt(raw) : 0;
    if (count >= FEEDBACK_RATE_LIMIT) return { limited: true };
    await env.RATE_LIMIT.put(key, String(count + 1), { expirationTtl: FEEDBACK_WINDOW });
    return { limited: false };
  } catch { return { limited: false }; }
}

export async function onRequest(context) {
  const req = context.request;
  const env = context.env;

  // Only accept POST
  if (req.method !== 'POST') {
    return jsonResp({ success: false, error: 'Method not allowed.' }, 405);
  }

  // CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, {
      headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'POST', 'Access-Control-Allow-Headers': 'Content-Type' }
    });
  }

  const ip = req.headers.get('CF-Connecting-IP') || 'unknown';

  // Rate limit
  const rl = await checkFeedbackRateLimit(env, ip);
  if (rl.limited) {
    // Don't tell them they're rate limited — just say thanks
    return jsonResp({ success: true, message: 'Thank you for your feedback.' });
  }

  // Parse body
  let body;
  try {
    body = await req.json();
  } catch {
    return jsonResp({ success: false, error: 'Invalid JSON body.' }, 400);
  }

  // § HONEYPOT: if 'website' field is filled, it's a bot — silently accept
  if (body.website && String(body.website).trim().length > 0) {
    return jsonResp({ success: true, message: 'Thank you for your feedback.' });
  }

  // Sanitize all inputs — never trust, never reflect
  const tech    = sanitize(body.tech    || '', MAX_TECH_LEN);
  const version = sanitize(body.version || '', 40);
  const rating  = ['positive', 'negative', 'neutral'].includes(body.rating) ? body.rating : 'neutral';
  const message = sanitize(body.message || '', MAX_MESSAGE_LEN);

  // Validate message
  if (message.length < MIN_MESSAGE_LEN) {
    return jsonResp({ success: false, error: 'Message too short. Minimum 10 characters.' }, 400);
  }

  // § ABUSE CHECK: if injection pattern detected, silently accept but don't store
  const combined = `${tech} ${version} ${message}`;
  if (hasAbusePattern(combined)) {
    // Log the attempt for monitoring, but don't reveal detection
    console.log(JSON.stringify({
      event:     'feedback_abuse_detected',
      ip,
      timestamp: Date.now(),
      tech:      tech.slice(0, 20),
    }));
    return jsonResp({ success: true, message: 'Thank you for your feedback.' });
  }

  // Store feedback in KV
  if (env?.RATE_LIMIT) {
    try {
      const feedbackKey = `feedback:${Date.now()}:${Math.random().toString(36).slice(2,8)}`;
      const entry = {
        tech,
        version,
        rating,
        message,
        ts: new Date().toISOString(),
        // Never store IP — privacy by design
      };
      await env.RATE_LIMIT.put(feedbackKey, JSON.stringify(entry), {
        expirationTtl: FEEDBACK_TTL
      });

      // Increment feedback counter
      const countRaw = await env.RATE_LIMIT.get('feedback:total');
      const count    = (countRaw ? parseInt(countRaw) : 0) + 1;
      await env.RATE_LIMIT.put('feedback:total', String(count));

    } catch (e) {
      console.log(JSON.stringify({ event: 'feedback_store_error', error: e.message }));
      // Don't expose storage errors to client
    }
  }

  console.log(JSON.stringify({
    event:   'feedback_received',
    rating,
    tech:    tech.slice(0, 20),
    ts:      Date.now()
  }));

  // Never echo back user content
  return jsonResp({ success: true, message: 'Thank you for your feedback.' });
}
