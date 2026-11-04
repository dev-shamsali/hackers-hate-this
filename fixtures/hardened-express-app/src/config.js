'use strict';
// Environment configuration, validated once at boot (fail fast). No secret has a default here.
const { z } = require('zod');

const intFrom = (def, min, max) => z.coerce.number().int().min(min).max(max).default(def);

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('production'),
  PORT: intFrom(3000, 1, 65535),
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  JWT_ISSUER: z.string().min(1).default('app-api'),
  JWT_AUDIENCE: z.string().min(1).default('app-clients'),
  JWT_EXPIRES_IN: z.string().min(1).default('1h'),
  BCRYPT_ROUNDS: intFrom(12, 4, 15),
  PASSWORD_MIN_LENGTH: intFrom(8, 1, 72),
  DB_HOST: z.string().min(1).default('db'),
  DB_PORT: intFrom(3306, 1, 65535),
  DB_NAME: z.string().min(1).default('shop'),
  DB_USER: z.string().min(1).refine((u) => u.toLowerCase() !== 'root', 'DB_USER must not be root'),
  DB_PASSWORD: z.string().min(1),
  MONGO_URI: z.string().min(1).optional(),
  CORS_ORIGINS: z.string().default('').transform((s) => s.split(',').map((x) => x.trim()).filter(Boolean)),
  TRUST_PROXY: intFrom(0, 0, 10),
  UPLOAD_DIR: z.string().min(1).default('data/uploads'),
  PREVIEW_ALLOWED_HOSTS: z.string().default('').transform((s) => s.split(',').map((x) => x.trim().toLowerCase()).filter(Boolean)),
}).superRefine((c, ctx) => {
  if (c.NODE_ENV === 'production') {
    if (c.BCRYPT_ROUNDS < 10) ctx.addIssue({ code: 'custom', path: ['BCRYPT_ROUNDS'], message: 'must be >= 10 in production' });
    if (c.PASSWORD_MIN_LENGTH < 8) ctx.addIssue({ code: 'custom', path: ['PASSWORD_MIN_LENGTH'], message: 'must be >= 8 in production' });
    if (!c.MONGO_URI) ctx.addIssue({ code: 'custom', path: ['MONGO_URI'], message: 'required in production' });
    if (c.CORS_ORIGINS.includes('*')) ctx.addIssue({ code: 'custom', path: ['CORS_ORIGINS'], message: 'wildcard not allowed' });
  }
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  // Names and reasons only, never values.
  const msg = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
  throw new Error('Invalid environment configuration: ' + msg);
}
module.exports = Object.freeze(parsed.data);
