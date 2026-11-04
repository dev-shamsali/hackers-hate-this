# File Upload Security

Applies only if upload code exists (`multer`, `formidable`, `busboy`, `express-fileupload`, Nest `FileInterceptor`, Next.js `request.formData()`, presigned URL generation, `fs.writeFile` of user data).

## Threats
RCE via executable upload (php/js/jsp/sh in web root), stored XSS (HTML/SVG served from app origin), path traversal (`../` in filename, zip slip), DoS (huge files, zip/archive bombs, decompression, image pixel flood, parser CPU), malware distribution, content sniffing, SSRF via URL-fetching "import from URL", overwrite of existing files, information leak via predictable public URLs/EXIF GPS.

## Controls checklist
1. **Size limits** at every layer: Nginx `client_max_body_size`, parser `limits: { fileSize, files: n, fields, parts }`, per-user quota. Multer: `limits.fileSize` set; memoryStorage with large limit = memory DoS (use disk/stream).
2. **Allowlist types**: extension allowlist (`.png .jpg .pdf`), never denylist. Client `Content-Type` is attacker-controlled: do not trust `file.mimetype`. Verify **magic bytes** server-side (`file-type` package: `fileTypeFromBuffer/Stream`; compare detected mime to allowlist and extension).
3. **Filename**: ignore the user filename for storage; generate `crypto.randomUUID()` + allowlisted extension derived from detected type. If original name shown, store as metadata, escape on output, strip control chars, length cap. Reject null bytes. Never `path.join(dir, file.originalname)`.
4. **Storage location**: outside web root and outside app dir (`/var/app-data/uploads`), no execute permission (`noexec` mount where possible; Nginx `location /uploads { ... }` no script handlers). Prefer object storage (S3/GCS) with private bucket; public/private separation: private by default, serve through authenticated endpoint or short-lived signed URLs; public bucket only for intentionally public assets with separate domain.
5. **Serving**: `Content-Type` from stored detected type, `X-Content-Type-Options: nosniff`, `Content-Disposition: attachment` for non-images, separate cookieless domain for user content, CSP `sandbox` on user-content responses. Authorization check on every download (IDOR via file id).
6. **SVG**: it is XML/JS capable. Either disallow, serve as `attachment`/from sandbox domain with `Content-Security-Policy: sandbox; default-src 'none'`, or sanitize server-side (DOMPurify w/ SVG profile) and rasterize to PNG. Never inline user SVG in HTML.
7. **Images**: re-encode with `sharp` (strips metadata/EXIF, normalizes), limit dimensions (`limitInputPixels`), run in worker with timeout. ImageMagick: patch/policy.xml restrictions (ImageTragick class).
8. **Documents (PDF/Office)**: may contain macros/JS/links; treat as untrusted; serve as attachment; scan; convert in sandbox (container, no network, resource limits, seccomp) if processing is required.
9. **Archives**: reject unless required; if extracting: validate each entry path (`path.resolve(dest, entry)` must start with `dest + sep`), reject symlinks, limit entry count, total uncompressed size, ratio (zip bomb), nesting depth.
10. **Malware scanning**: ClamAV (`clamd`) scan on upload before making file available (quarantine bucket -> scan -> release); async via job queue for large files; mark status `pending|clean|infected`. Cloud-native scanners (GuardDuty S3 protection etc.) if on AWS. Recommend as required for user-to-user sharing; optional for private single-user storage.
11. **Presigned URLs**: restrict `Content-Type`, `content-length-range` (POST policy), key prefix with user/tenant id, short expiry (<=5 min), server picks the key; post-upload verify (HEAD size/type, re-validate magic bytes) before marking usable.
12. **URL import**: SSRF controls (nextjs-security.md item 8).
13. **Rate limit + auth** on upload endpoints; per-user quotas; audit log.
14. **Cleanup**: temp files removed on error (`finally`), orphan cleanup job.
15. **Race/overwrite**: write with `flag: 'wx'`; unique names.

## Multer example (Express)
```ts
const upload = multer({ storage: multer.diskStorage({ destination: '/var/app-data/uploads',
    filename: (_r, _f, cb) => cb(null, crypto.randomUUID()) }),
  limits: { fileSize: 5*1024*1024, files: 1, fields: 5 },
  fileFilter: (_r, f, cb) => ['image/png','image/jpeg'].includes(f.mimetype) ? cb(null,true) : cb(new Error('type')) });
// after upload: const t = await fileTypeFromFile(req.file.path); if (!t || !['image/png','image/jpeg'].includes(t.mime)) { await fs.unlink(req.file.path); return res.status(415).end(); }
// then rename with extension t.ext, store DB row with owner, serve via authenticated route.
```
Check multer version vs advisories (older 1.x had DoS issues; verify with npm audit).

## Tests
Upload `shell.php` renamed `.png` => rejected by magic-byte check; `../../etc/passwd` filename => stored under uuid; 6MB file => 413; SVG with `<script>` => rejected or neutralized; zip with `../` entry => rejected; other user's file id => 404; response has `nosniff`.
