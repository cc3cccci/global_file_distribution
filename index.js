import htmlContent from './index.html';

const ACCESS_CODE_PREFIX = '.config/access_codes/';
const ACCESS_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const ACCESS_CODE_MAX_ACTIVE = 25;
const ACCESS_CODE_MAX_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;
const AUTH_RATE_WINDOW_MS = 15 * 60 * 1000;
const AUTH_RATE_MAX_FAILURES = 12;
const authFailureBuckets = new Map();

export default {
  async fetch(request, env, ctx) {
    // 处理 CORS 预检请求
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, HEAD, POST, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    try {
      // 检查 R2 绑定配置
      if (!env.BUCKET) {
        return new Response('Cloudflare R2 Bucket binding "BUCKET" is missing. Please check your wrangler.toml configuration.', { 
          status: 500,
          headers: { 'Content-Type': 'text/plain; charset=utf-8' }
        });
      }

      const url = new URL(request.url);
      const pathname = url.pathname;

      // 路由：静态前端页面
      if (pathname === '/' || pathname === '/index.html') {
        return new Response(htmlContent, {
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      }

      // 路由：访问密码验证
      if (pathname === '/api/auth' && request.method === 'POST') {
        if (!env.AUTH_PASSWORD || !env.SECRET_KEY) {
          return jsonResponse({ error: 'Server authentication is not configured' }, 503);
        }

        const clientKey = getAuthClientKey(request);
        if (isAuthRateLimited(clientKey)) {
          return jsonResponse({ error: 'Too many attempts. Please try again later.' }, 429);
        }

        const body = await request.json();
        const credential = String(body.credential || body.password || '').trim();
        if (credential && timingSafeEqual(credential, env.AUTH_PASSWORD)) {
          clearAuthFailures(clientKey);
          return jsonResponse({ success: true, role: 'admin' });
        }

        const accessRecord = await findActiveAccessCode(env, credential);
        if (accessRecord) {
          clearAuthFailures(clientKey);
          const sessionToken = await createViewerSession(accessRecord, env);
          const secure = url.protocol === 'https:' ? '; Secure' : '';
          const cookie = `AetherViewer=${encodeURIComponent(sessionToken)}; Path=/; HttpOnly; SameSite=Strict${secure}`;
          return jsonResponse({
            success: true,
            role: 'viewer',
            token: sessionToken,
            expiresAt: accessRecord.expiresAt
          }, 200, { 'Set-Cookie': cookie });
        }

        recordAuthFailure(clientKey);
        return jsonResponse({ error: 'Invalid credential' }, 401);
      }

      if (pathname === '/api/logout' && request.method === 'POST') {
        const secure = url.protocol === 'https:' ? '; Secure' : '';
        return jsonResponse({ success: true }, 200, {
          'Set-Cookie': `AetherViewer=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`
        });
      }

      // 以下 API 均涉及数据访问，需要进行安全认证（下载接口有单独的签名鉴权）
      
      // 路由：流式文件下载与安全签名校验
      if (pathname === '/api/download') {
        if (!['GET', 'HEAD'].includes(request.method)) {
          return new Response('Method Not Allowed', { status: 405 });
        }
        const keyParam = url.searchParams.get('key');
        if (!keyParam) {
          return corsResponse(new Response('Missing file key', { status: 400 }));
        }
        const key = decodeURIComponent(keyParam);

        // 验证下载凭证：预签名链接、兼容旧版管理员 token，或可撤销的只读会话。
        const signature = url.searchParams.get('signature');
        const expires = url.searchParams.get('expires');
        const token = url.searchParams.get('token');

        let isAuthorized = false;

        if (signature && expires && env.SECRET_KEY) {
          // 方式 1: 预签名链接验证
          const isValidSig = await verifySignature(key, expires, signature, env.SECRET_KEY || 'default-salt');
          if (isValidSig) {
            isAuthorized = true;
          }
        } else if (token && env.AUTH_PASSWORD && timingSafeEqual(token, env.AUTH_PASSWORD)) {
          // 方式 2: 控制面板直连下载验证
          isAuthorized = true;

          // 防盗链保护仅在直连下载时生效（分享链已自带加密时效，不限制 Referer 以便于多场景分享）
          if (!checkReferer(request, env)) {
            return corsResponse(new Response('Forbidden: Hotlinking is not allowed', { status: 403 }));
          }
        } else {
          const authContext = await authenticateRequest(request, env);
          if (authContext?.role === 'viewer' && isViewerVisibleKey(key) && !key.endsWith('/')) {
            isAuthorized = true;
          } else if (authContext?.role === 'admin') {
            isAuthorized = true;
          }
        }

        if (!isAuthorized) {
          return corsResponse(new Response('Unauthorized: Link expired or invalid credentials', { status: 403 }));
        }

        // 从 R2 读取文件
        const object = await env.BUCKET.get(key);
        if (!object) {
          return corsResponse(new Response('File Not Found', { status: 404 }));
        }

        // 流式读取，不占用 Worker 内存，防止 128MB 限制导致崩溃
        const headers = new Headers();
        headers.set('Content-Type', object.httpMetadata?.contentType || 'application/octet-stream');
        headers.set('Content-Length', object.size.toString());
        // 设置 Content-Disposition 保证浏览器强制下载并正确解码中文文件名
        headers.set('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(key)}`);
        if (object.httpEtag) {
          headers.set('ETag', object.httpEtag);
        }
        headers.set('Cache-Control', 'private, no-store');

        return corsResponse(new Response(object.body, {
          headers
        }));
      }

      // 路由：永久公开共享链接流式下载 (免鉴权，适用于软路由等外部设备)
      if (pathname.startsWith('/f/')) {
        const key = decodeURIComponent(pathname.substring(3));
        if (!key) {
          return new Response('Missing filename', { status: 400 });
        }
        
        // 校验该文件是否已被公开分享
        const publicFiles = await getPublicFiles(env);
        if (!publicFiles.includes(key)) {
          return new Response('Forbidden: This file is not public', { status: 403 });
        }
        
        // 从 R2 获取文件
        const object = await env.BUCKET.get(key);
        if (!object) {
          return new Response('File Not Found', { status: 404 });
        }
        
        const headers = new Headers();
        headers.set('Content-Type', object.httpMetadata?.contentType || 'application/octet-stream');
        headers.set('Content-Length', object.size.toString());
        headers.set('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(key)}`);
        if (object.httpEtag) {
          headers.set('ETag', object.httpEtag);
        }
        // 设置不缓存，确保每次拉取都从 R2 实时获取最新版本
        headers.set('Cache-Control', 'no-cache, no-store, must-revalidate');
        
        return new Response(object.body, {
          headers
        });
      }

      // 路由：VPS 推送 SSL 证书（使用独立 Token，与管理员密码分离）
      // POST /api/cert-push
      // Header:  X-Cert-Token: <CERT_PUSH_TOKEN>
      // Body:    { domain, fullchain?, privkey?, cert? }  —— PEM 字符串，传哪个存哪个
      if (pathname === '/api/cert-push' && request.method === 'POST') {
        const token = request.headers.get('X-Cert-Token');
        if (!token || token !== env.CERT_PUSH_TOKEN) {
          return corsResponse(new Response(JSON.stringify({ error: 'Unauthorized: invalid cert push token' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' }
          }));
        }

        let body;
        try {
          body = await request.json();
        } catch (e) {
          return corsResponse(new Response('Invalid JSON body', { status: 400 }));
        }

        const { domain, fullchain, privkey, cert } = body;
        if (!domain || typeof domain !== 'string' || domain.trim() === '') {
          return corsResponse(new Response('Missing or invalid domain field', { status: 400 }));
        }

        // 简单校验 domain 格式，防止路径穿越
        const safeDomain = domain.trim().replace(/[^a-zA-Z0-9.\-_*]/g, '');
        if (safeDomain !== domain.trim()) {
          return corsResponse(new Response('Invalid domain: contains illegal characters', { status: 400 }));
        }

        const pushedAt = new Date().toISOString();
        const results = [];

        const uploads = [
          { content: fullchain, filename: 'fullchain.pem' },
          { content: privkey,   filename: 'privkey.pem'   },
          { content: cert,      filename: 'cert.pem'       },
        ];

        for (const { content, filename } of uploads) {
          if (content == null || content === '') continue;
          if (typeof content !== 'string') {
            results.push({ filename, status: 'skipped', reason: 'content must be a PEM string' });
            continue;
          }

          const key = `certs/${safeDomain}/${filename}`;
          await env.BUCKET.put(key, content, {
            httpMetadata: { contentType: 'application/x-pem-file' },
            customMetadata: {
              domain: safeDomain,
              pushed_at: pushedAt,
              pushed_by: 'vps-hook',
            }
          });
          results.push({ key, status: 'ok' });
        }

        if (results.filter(r => r.status === 'ok').length === 0) {
          return corsResponse(new Response(JSON.stringify({
            success: false,
            error: 'No certificate content provided (fullchain / privkey / cert are all empty)',
            results
          }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          }));
        }

        return corsResponse(new Response(JSON.stringify({ success: true, domain: safeDomain, pushed_at: pushedAt, results }), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：下游 VPS 拉取 SSL 证书（复用 CERT_PUSH_TOKEN，限制只读 certs/ 目录）
      // GET /api/cert-pull?domain=<domain>&file=<filename>
      // Header: X-Cert-Token: <CERT_PUSH_TOKEN>
      if (pathname === '/api/cert-pull' && request.method === 'GET') {
        const token = request.headers.get('X-Cert-Token');
        if (!token || token !== env.CERT_PUSH_TOKEN) {
          return corsResponse(new Response('Unauthorized', { status: 401 }));
        }

        const domain = url.searchParams.get('domain');
        const file = url.searchParams.get('file');

        // 白名单：只允许下载这三个标准证书文件
        const allowedFiles = ['fullchain.pem', 'privkey.pem', 'cert.pem'];
        if (!domain || !file || !allowedFiles.includes(file)) {
          return corsResponse(new Response('Invalid parameters', { status: 400 }));
        }

        // domain 安全校验（防路径穿越）
        const safeDomain = domain.trim().replace(/[^a-zA-Z0-9.\-_*]/g, '');
        if (safeDomain !== domain.trim()) {
          return corsResponse(new Response('Invalid domain', { status: 400 }));
        }

        const key = `certs/${safeDomain}/${file}`;
        const object = await env.BUCKET.get(key);
        if (!object) {
          return corsResponse(new Response(`Certificate not found: ${key}`, { status: 404 }));
        }

        return corsResponse(new Response(object.body, {
          headers: {
            'Content-Type': 'application/x-pem-file',
            'Content-Disposition': `attachment; filename="${file}"`,
            'Cache-Control': 'no-cache, no-store, must-revalidate'
          }
        }));
      }

      // 管理 API 与客户只读 API 使用严格分离的权限边界。
      const authContext = await authenticateRequest(request, env);
      if (!authContext) {
        return corsResponse(new Response(JSON.stringify({ error: 'Unauthorized' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      const viewerAllowed = isViewerAllowedRoute(pathname, request.method);
      if (authContext.role === 'viewer' && !viewerAllowed) {
        return jsonResponse({ error: 'Read-only access' }, 403);
      }

      // 管理临时访问码：摘要用于登录校验，密文仅供管理员列表解密查看。
      if (pathname === '/api/access-codes' && request.method === 'GET') {
        if (authContext.role !== 'admin') return jsonResponse({ error: 'Forbidden' }, 403);
        const records = await loadAccessCodeRecords(env);
        records.sort((a, b) => b.createdAt - a.createdAt);
        const accessCodes = await Promise.all(
          records.map(record => toAdminAccessRecord(record, env.SECRET_KEY))
        );
        return jsonResponse({
          accessCodes
        }, 200, { 'Cache-Control': 'no-store' });
      }

      if (pathname === '/api/access-codes' && request.method === 'POST') {
        if (authContext.role !== 'admin') return jsonResponse({ error: 'Forbidden' }, 403);
        const body = await request.json();
        const expiresAt = Number(body.expiresAt);
        const now = Date.now();
        if (!Number.isFinite(expiresAt) || expiresAt <= now || expiresAt - now > ACCESS_CODE_MAX_LIFETIME_MS) {
          return jsonResponse({ error: 'Expiry must be within the next 30 days' }, 400);
        }

        const existing = await loadAccessCodeRecords(env);
        const activeCount = existing.filter(record => isAccessRecordActive(record, now)).length;
        if (activeCount >= ACCESS_CODE_MAX_ACTIVE) {
          return jsonResponse({ error: `At most ${ACCESS_CODE_MAX_ACTIVE} active access codes are allowed` }, 409);
        }

        let code;
        let codeHash;
        for (let attempt = 0; attempt < 5; attempt++) {
          const candidate = generateAccessCode();
          const candidateHash = await hashAccessCode(candidate, env.SECRET_KEY);
          if (!existing.some(record => timingSafeEqual(record.codeHash, candidateHash))) {
            code = candidate;
            codeHash = candidateHash;
            break;
          }
        }
        if (!code) return jsonResponse({ error: 'Unable to generate a unique access code' }, 503);
        const id = crypto.randomUUID();
        const encryptedCode = await encryptAccessCode(code, id, env.SECRET_KEY);
        const record = {
          schemaVersion: 2,
          id,
          codeHash,
          codeCiphertext: encryptedCode.ciphertext,
          codeIv: encryptedCode.iv,
          codeHint: code.slice(-4),
          label: String(body.label || '').trim().slice(0, 60),
          createdAt: now,
          expiresAt: Math.floor(expiresAt),
          revokedAt: null
        };
        await saveAccessCodeRecord(env, record);
        return jsonResponse({
          accessCode: code,
          record: { ...toPublicAccessRecord(record), accessCode: code, codeRecoverable: true }
        }, 201, { 'Cache-Control': 'no-store' });
      }

      if (pathname === '/api/access-codes' && request.method === 'DELETE') {
        if (authContext.role !== 'admin') return jsonResponse({ error: 'Forbidden' }, 403);
        const id = url.searchParams.get('id');
        if (!id || !/^[0-9a-f-]{36}$/i.test(id)) return jsonResponse({ error: 'Invalid access code id' }, 400);
        const record = await getAccessCodeRecord(env, id);
        if (!record) return jsonResponse({ error: 'Access code not found' }, 404);
        record.revokedAt = Date.now();
        await saveAccessCodeRecord(env, record);
        return jsonResponse({ success: true, record: toPublicAccessRecord(record) });
      }

      // 管理员下载使用短时签名，避免把主密码放入 URL。
      if (pathname === '/api/download-ticket' && request.method === 'GET') {
        if (authContext.role !== 'admin') return jsonResponse({ error: 'Forbidden' }, 403);
        if (!env.SECRET_KEY) return jsonResponse({ error: 'SECRET_KEY is not configured' }, 503);
        const key = url.searchParams.get('key') || '';
        if (!key || key.endsWith('/')) return jsonResponse({ error: 'Invalid file key' }, 400);
        const object = await env.BUCKET.head(key);
        if (!object) return jsonResponse({ error: 'File not found' }, 404);
        const expires = Date.now() + 2 * 60 * 1000;
        const signature = await generateSignature(key, expires, env.SECRET_KEY);
        return jsonResponse({
          url: `/api/download?key=${encodeURIComponent(key)}&expires=${expires}&signature=${signature}`
        });
      }

      // 路由：获取公开分享文件列表
      if (pathname === '/api/public-list' && request.method === 'GET') {
        const list = await getPublicFiles(env);
        return corsResponse(new Response(JSON.stringify({ publicFiles: list }), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：切换公开分享状态
      if (pathname === '/api/public-toggle' && request.method === 'POST') {
        const { key, isPublic } = await request.json();
        if (!key) {
          return corsResponse(new Response('Missing file key', { status: 400 }));
        }
        
        let list = await getPublicFiles(env);
        if (isPublic) {
          if (!list.includes(key)) {
            list.push(key);
          }
        } else {
          list = list.filter(item => item !== key);
        }
        
        await savePublicFiles(env, list);
        return corsResponse(new Response(JSON.stringify({ success: true, publicFiles: list }), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：获取文件列表
      if (pathname === '/api/list' && request.method === 'GET') {
        const objects = await listAllObjects(env.BUCKET);
        const visibleObjects = authContext.role === 'viewer'
          ? objects.filter(obj => isViewerVisibleKey(obj.key))
          : objects;
        const files = visibleObjects.map(obj => ({
          key: obj.key,
          size: obj.size,
          uploaded: obj.uploaded.toISOString()
        }));
        return corsResponse(new Response(JSON.stringify({ files }), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：生成 10 分钟预签名分享链接
      if (pathname === '/api/share' && request.method === 'GET') {
        if (!env.SECRET_KEY) return jsonResponse({ error: 'SECRET_KEY is not configured' }, 503);
        const keyParam = url.searchParams.get('key');
        if (!keyParam) {
          return corsResponse(new Response('Missing file key', { status: 400 }));
        }
        const key = decodeURIComponent(keyParam);
        
        // 生成 10 分钟有效期 (Date.now() + 600,000 毫秒)
        const expires = Date.now() + 10 * 60 * 1000;
        const signature = await generateSignature(key, expires, env.SECRET_KEY);
        
        const shareUrl = `${url.origin}/api/download?key=${encodeURIComponent(key)}&expires=${expires}&signature=${signature}`;
        
        return corsResponse(new Response(JSON.stringify({ url: shareUrl }), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：初始化分片上传
      if (pathname === '/api/upload-init' && request.method === 'POST') {
        const { filename, contentType, overwrite = false } = await request.json();
        if (!filename) {
          return corsResponse(new Response('Missing filename', { status: 400 }));
        }
        if (filename.startsWith('.') || filename.includes('/../') || filename.endsWith('/..')) {
          return jsonResponse({ error: 'Invalid filename' }, 400);
        }
        if (!overwrite && await env.BUCKET.head(filename)) {
          return jsonResponse({ error: 'File already exists' }, 409);
        }
        
        // 调用 R2 原始分片接口
        const upload = await env.BUCKET.createMultipartUpload(filename, {
          httpMetadata: { contentType: contentType || 'application/octet-stream' }
        });

        return corsResponse(new Response(JSON.stringify({
          uploadId: upload.uploadId,
          key: upload.key
        }), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：上传分片
      if (pathname === '/api/upload-part' && request.method === 'POST') {
        const keyParam = url.searchParams.get('key');
        const uploadId = url.searchParams.get('uploadId');
        const partNumberStr = url.searchParams.get('partNumber');

        if (!keyParam || !uploadId || !partNumberStr) {
          return corsResponse(new Response('Missing parameters', { status: 400 }));
        }

        const key = decodeURIComponent(keyParam);
        const partNumber = parseInt(partNumberStr);
        
        // 恢复分片上传流对象
        const upload = env.BUCKET.resumeMultipartUpload(key, uploadId);
        
        // 核心：直接把网络流管道接给 R2 写入，不缓存内存
        const part = await upload.uploadPart(partNumber, request.body);

        return corsResponse(new Response(JSON.stringify({
          partNumber,
          etag: part.etag
        }), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：完成分片合并
      if (pathname === '/api/upload-complete' && request.method === 'POST') {
        const keyParam = url.searchParams.get('key');
        const uploadId = url.searchParams.get('uploadId');

        if (!keyParam || !uploadId) {
          return corsResponse(new Response('Missing parameters', { status: 400 }));
        }

        const key = decodeURIComponent(keyParam);
        const { parts } = await request.json(); // 前端需传回已成功的分片列表

        if (!Array.isArray(parts)) {
          return corsResponse(new Response('Invalid parts list', { status: 400 }));
        }

        // 排序确保分片顺序正确
        const sortedParts = parts.sort((a, b) => a.partNumber - b.partNumber);

        const upload = env.BUCKET.resumeMultipartUpload(key, uploadId);
        await upload.complete(sortedParts);

        return corsResponse(new Response(JSON.stringify({ success: true }), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：删除文件与文件夹（级联删除）
      if (pathname === '/api/delete' && request.method === 'DELETE') {
        const keyParam = url.searchParams.get('key');
        if (!keyParam) {
          return corsResponse(new Response('Missing file key', { status: 400 }));
        }
        const key = decodeURIComponent(keyParam);

        if (key.endsWith('/')) {
          const listResult = await env.BUCKET.list({ prefix: key });
          const keysToDelete = listResult.objects.map(obj => obj.key);
          if (keysToDelete.length > 0) {
            await env.BUCKET.delete(keysToDelete);
          }
        } else {
          await env.BUCKET.delete(key);
        }

        return corsResponse(new Response(JSON.stringify({ success: true }), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：创建空文件夹占位符
      if (pathname === '/api/create-folder' && request.method === 'POST') {
        const { path } = await request.json();
        if (!path || !path.endsWith('/') || path.startsWith('.') || path.split('/').includes('..')) {
          return corsResponse(new Response('Invalid folder path', { status: 400 }));
        }
        if (await env.BUCKET.head(path)) return jsonResponse({ error: 'Folder already exists' }, 409);
        await env.BUCKET.put(path, new ArrayBuffer(0), {
          httpMetadata: { contentType: 'application/x-directory' }
        });
        return corsResponse(new Response(JSON.stringify({ success: true }), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：移动与重命名文件
      if (pathname === '/api/rename' && request.method === 'POST') {
        const { fromKey, toKey } = await request.json();
        if (!fromKey || !toKey) {
          return corsResponse(new Response('Missing parameters', { status: 400 }));
        }
        if (toKey.startsWith('.') || toKey.split('/').includes('..')) {
          return jsonResponse({ error: 'Invalid target path' }, 400);
        }
        if (fromKey !== toKey && await env.BUCKET.head(toKey)) {
          return jsonResponse({ error: 'Target already exists' }, 409);
        }

        const object = await env.BUCKET.get(fromKey);
        if (!object) {
          return corsResponse(new Response('Source file not found', { status: 404 }));
        }

        await env.BUCKET.put(toKey, object.body, {
          httpMetadata: object.httpMetadata,
          customMetadata: object.customMetadata
        });

        await env.BUCKET.delete(fromKey);

        // 同步标签映射
        let allTags = await getFileTags(env);
        if (allTags[fromKey]) {
          allTags[toKey] = allTags[fromKey];
          delete allTags[fromKey];
          await saveFileTags(env, allTags);
        }

        // 同步公开分享状态
        let publicFilesList = await getPublicFiles(env);
        if (publicFilesList.includes(fromKey)) {
          publicFilesList = publicFilesList.map(item => item === fromKey ? toKey : item);
          await savePublicFiles(env, publicFilesList);
        }

        return corsResponse(new Response(JSON.stringify({ success: true }), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：获取同步配置
      if (pathname === '/api/sync-config' && request.method === 'GET') {
        const configObject = await env.BUCKET.get('.config/sync_list.json');
        if (!configObject) {
          const defaultConfig = [
            {
              url: 'https://github.com/v2fly/geoip/releases/latest/download/geoip.dat',
              key: 'geoip.dat'
            }
          ];
          await env.BUCKET.put('.config/sync_list.json', JSON.stringify(defaultConfig), {
            httpMetadata: { contentType: 'application/json' }
          });
          return corsResponse(new Response(JSON.stringify(defaultConfig), {
            headers: { 'Content-Type': 'application/json' }
          }));
        }
        const configText = await configObject.text();
        return corsResponse(new Response(configText, {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：更新同步配置
      if (pathname === '/api/sync-config' && request.method === 'POST') {
        const syncList = await request.json();
        if (!Array.isArray(syncList)) {
          return corsResponse(new Response(JSON.stringify({ error: 'Invalid config format' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          }));
        }
        await env.BUCKET.put('.config/sync_list.json', JSON.stringify(syncList), {
          httpMetadata: { contentType: 'application/json' }
        });
        return corsResponse(new Response(JSON.stringify({ success: true }), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：立即执行同步
      if (pathname === '/api/sync-now' && request.method === 'POST') {
        const singleKey = url.searchParams.get('key');
        const results = await performGithubSync(env, singleKey);
        return corsResponse(new Response(JSON.stringify({ success: true, results }), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：获取某订阅的历史版本列表
      if (pathname === '/api/sync-history' && request.method === 'GET') {
        const key = url.searchParams.get('key');
        if (!key) {
          return corsResponse(new Response('Missing subscription key', { status: 400 }));
        }
        
        const historyPrefix = `.history/${key}/`;
        const listResult = await env.BUCKET.list({ prefix: historyPrefix });
        
        const historyList = [];
        for (const obj of listResult.objects) {
          const headObj = await env.BUCKET.head(obj.key);
          historyList.push({
            key: obj.key,
            size: obj.size,
            uploaded: obj.uploaded.toISOString(),
            pinned: headObj && headObj.customMetadata ? headObj.customMetadata.pinned === 'true' : false
          });
        }
        
        historyList.sort((a, b) => new Date(b.uploaded).getTime() - new Date(a.uploaded).getTime());

        return corsResponse(new Response(JSON.stringify(historyList), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：删除指定历史版本
      if (pathname === '/api/sync-history' && request.method === 'DELETE') {
        const { historyKey } = await request.json();
        if (!historyKey || !historyKey.startsWith('.history/')) {
          return corsResponse(new Response('Invalid history key', { status: 400 }));
        }
        
        const headObj = await env.BUCKET.head(historyKey);
        if (headObj && headObj.customMetadata && headObj.customMetadata.pinned === 'true') {
          return corsResponse(new Response('Cannot delete a pinned version. Unpin it first.', { status: 400 }));
        }

        await env.BUCKET.delete(historyKey);
        return corsResponse(new Response(JSON.stringify({ success: true }), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：锁定/解锁历史版本
      if (pathname === '/api/sync-history/pin' && request.method === 'POST') {
        const { historyKey, pinned } = await request.json();
        if (!historyKey || !historyKey.startsWith('.history/')) {
          return corsResponse(new Response('Invalid history key', { status: 400 }));
        }

        const object = await env.BUCKET.get(historyKey);
        if (!object) {
          return corsResponse(new Response('History version not found', { status: 404 }));
        }

        const customMetadata = { ...(object.customMetadata || {}) };
        if (pinned) {
          customMetadata.pinned = 'true';
        } else {
          delete customMetadata.pinned;
        }

        await env.BUCKET.put(historyKey, object.body, {
          httpMetadata: object.httpMetadata,
          customMetadata: customMetadata
        });

        return corsResponse(new Response(JSON.stringify({ success: true }), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：测试同步订阅链接
      if (pathname === '/api/sync-test' && request.method === 'POST') {
        const { url } = await request.json();
        if (!url) {
          return corsResponse(new Response('Missing URL', { status: 400 }));
        }
        try {
          const res = await fetch(url, {
            method: 'GET',
            headers: { 'User-Agent': 'AetherStorage-Sync-Agent/1.0' }
          });
          return corsResponse(new Response(JSON.stringify({
            ok: res.ok,
            status: res.status,
            statusText: res.statusText,
            contentType: res.headers.get('Content-Type') || 'unknown',
            contentLength: res.headers.get('Content-Length') || 'unknown'
          }), {
            headers: { 'Content-Type': 'application/json' }
          }));
        } catch (e) {
          return corsResponse(new Response(JSON.stringify({
            ok: false,
            error: e.message
          }), {
            headers: { 'Content-Type': 'application/json' }
          }));
        }
      }

      // 路由：获取所有文件的标签映射
      if (pathname === '/api/tags' && request.method === 'GET') {
        let tags = await getFileTags(env);
        if (authContext.role === 'viewer') {
          tags = Object.fromEntries(Object.entries(tags).filter(([key]) => isViewerVisibleKey(key)));
        }
        return corsResponse(new Response(JSON.stringify(tags), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：更新单个或批量文件的标签（POST body: { key, tags: ["重要", "工作"] } 或 { fileTags }）
      if (pathname === '/api/tags' && request.method === 'POST') {
        const body = await request.json();
        let allTags = await getFileTags(env);
        if (body.key) {
          const { key, tags } = body;
          if (!tags || tags.length === 0) {
            delete allTags[key];
          } else {
            allTags[key] = tags;
          }
        } else if (body.fileTags) {
          allTags = body.fileTags;
        } else {
          return corsResponse(new Response('Missing key or fileTags', { status: 400 }));
        }
        await saveFileTags(env, allTags);
        return corsResponse(new Response(JSON.stringify({ success: true, tags: allTags }), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：获取标签定义列表
      if (pathname === '/api/tag-defs' && request.method === 'GET') {
        const defs = await getTagDefs(env);
        return corsResponse(new Response(JSON.stringify(defs), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：保存标签定义列表
      if (pathname === '/api/tag-defs' && request.method === 'POST') {
        const defs = await request.json();
        if (!Array.isArray(defs)) {
          return corsResponse(new Response('Invalid format', { status: 400 }));
        }
        await saveTagDefs(env, defs);
        return corsResponse(new Response(JSON.stringify({ success: true, defs }), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 默认 404
      return corsResponse(new Response('Not Found', { status: 404 }));

    } catch (err) {
      console.error('Unhandled request error:', err);
      return jsonResponse({ error: 'Internal server error' }, 500);
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(performGithubSync(env));
  }
};

// 获取公开文件列表
async function getPublicFiles(env) {
  try {
    const object = await env.BUCKET.get('.config/public_files.json');
    if (!object) return [];
    return await object.json();
  } catch (e) {
    console.error('Failed to get public files:', e.message);
    return [];
  }
}

// 保存公开文件列表
async function savePublicFiles(env, list) {
  await env.BUCKET.put('.config/public_files.json', JSON.stringify(list), {
    httpMetadata: { contentType: 'application/json' }
  });
}

// 获取文件标签映射 { "filename": ["重要", "工作"] }
async function getFileTags(env) {
  try {
    const object = await env.BUCKET.get('.config/file_tags.json');
    if (!object) return {};
    return await object.json();
  } catch (e) {
    console.error('Failed to get file tags:', e.message);
    return {};
  }
}

// 保存文件标签映射
async function saveFileTags(env, tags) {
  await env.BUCKET.put('.config/file_tags.json', JSON.stringify(tags), {
    httpMetadata: { contentType: 'application/json' }
  });
}

// 获取标签定义（含颜色）
async function getTagDefs(env) {
  const defaults = [
    { name: '重要', color: '#ef4444', emoji: '🔴', builtin: true },
    { name: '工作', color: '#f59e0b', emoji: '🟡', builtin: true },
    { name: '生活', color: '#22c55e', emoji: '🟢', builtin: true },
    { name: '临时', color: '#3b82f6', emoji: '🔵', builtin: true },
    { name: '收藏', color: '#a855f7', emoji: '🟣', builtin: true },
  ];
  try {
    const object = await env.BUCKET.get('.config/tag_defs.json');
    if (!object) {
      await saveTagDefs(env, defaults);
      return defaults;
    }
    return await object.json();
  } catch (e) {
    return defaults;
  }
}

// 保存标签定义
async function saveTagDefs(env, defs) {
  await env.BUCKET.put('.config/tag_defs.json', JSON.stringify(defs), {
    httpMetadata: { contentType: 'application/json' }
  });
}

// 后端鉴权校验
function verifyAdminAuth(request, env) {
  const authHeader = request.headers.get('Authorization');
  return Boolean(env.AUTH_PASSWORD && authHeader && timingSafeEqual(authHeader, env.AUTH_PASSWORD));
}

async function authenticateRequest(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  if (env.AUTH_PASSWORD && authHeader && timingSafeEqual(authHeader, env.AUTH_PASSWORD)) {
    return { role: 'admin' };
  }

  let sessionToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  if (!sessionToken) {
    sessionToken = getCookieValue(request.headers.get('Cookie') || '', 'AetherViewer');
  }
  if (!sessionToken || !env.SECRET_KEY) return null;
  return validateViewerSession(sessionToken, env);
}

function isViewerAllowedRoute(pathname, method) {
  if (method !== 'GET') return false;
  return pathname === '/api/list' || pathname === '/api/tags' || pathname === '/api/tag-defs';
}

function isViewerVisibleKey(key) {
  if (!key || typeof key !== 'string') return false;
  return !key.startsWith('.config/') && !key.startsWith('.history/') && !key.startsWith('certs/');
}

async function listAllObjects(bucket, options = {}) {
  const objects = [];
  let cursor;
  do {
    const page = await bucket.list({ ...options, cursor });
    objects.push(...page.objects);
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  return objects;
}

async function loadAccessCodeRecords(env) {
  const objects = await listAllObjects(env.BUCKET, { prefix: ACCESS_CODE_PREFIX });
  const records = [];
  for (const object of objects) {
    try {
      const stored = await env.BUCKET.get(object.key);
      if (!stored) continue;
      const record = await stored.json();
      if (record && record.id && record.codeHash) records.push(record);
    } catch (error) {
      console.error('Failed to load access code record:', object.key, error.message);
    }
  }
  return records;
}

async function getAccessCodeRecord(env, id) {
  try {
    const object = await env.BUCKET.get(`${ACCESS_CODE_PREFIX}${id}.json`);
    return object ? await object.json() : null;
  } catch {
    return null;
  }
}

async function saveAccessCodeRecord(env, record) {
  await env.BUCKET.put(`${ACCESS_CODE_PREFIX}${record.id}.json`, JSON.stringify(record), {
    httpMetadata: { contentType: 'application/json', cacheControl: 'no-store' }
  });
}

function isAccessRecordActive(record, now = Date.now()) {
  return Boolean(
    record &&
    Number.isFinite(Number(record.expiresAt)) &&
    now < Number(record.expiresAt) &&
    !record.revokedAt
  );
}

function toPublicAccessRecord(record) {
  const now = Date.now();
  const status = record.revokedAt ? 'revoked' : now >= Number(record.expiresAt) ? 'expired' : 'active';
  return {
    id: record.id,
    codeHint: record.codeHint || '',
    label: record.label || '',
    createdAt: Number(record.createdAt),
    expiresAt: Number(record.expiresAt),
    revokedAt: record.revokedAt ? Number(record.revokedAt) : null,
    status
  };
}

async function toAdminAccessRecord(record, secret) {
  const publicRecord = toPublicAccessRecord(record);
  if (!record.codeCiphertext || !record.codeIv || !secret) {
    return { ...publicRecord, accessCode: null, codeRecoverable: false };
  }
  try {
    const accessCode = await decryptAccessCode(record.codeCiphertext, record.codeIv, record.id, secret);
    return { ...publicRecord, accessCode, codeRecoverable: true };
  } catch (error) {
    console.error('Failed to decrypt access code record:', record.id, error.message);
    return { ...publicRecord, accessCode: null, codeRecoverable: false };
  }
}

function normalizeAccessCode(value) {
  return String(value || '').replace(/[\s-]/g, '').toUpperCase();
}

function generateAccessCode() {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, byte => ACCESS_CODE_ALPHABET[byte % ACCESS_CODE_ALPHABET.length]).join('');
}

async function hashAccessCode(code, secret) {
  return generateSignature('access-code', normalizeAccessCode(code), secret);
}

async function deriveAccessCodeEncryptionKey(secret) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.digest(
    'SHA-256',
    encoder.encode(`aether-access-code:${secret}`)
  );
  return crypto.subtle.importKey('raw', keyMaterial, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function encryptAccessCode(code, id, secret) {
  const encoder = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveAccessCodeEncryptionKey(secret);
  const ciphertext = await crypto.subtle.encrypt({
    name: 'AES-GCM',
    iv,
    additionalData: encoder.encode(`access-code:${id}`)
  }, key, encoder.encode(code));
  return {
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    iv: bytesToBase64(iv)
  };
}

async function decryptAccessCode(ciphertext, iv, id, secret) {
  const encoder = new TextEncoder();
  const key = await deriveAccessCodeEncryptionKey(secret);
  const plaintext = await crypto.subtle.decrypt({
    name: 'AES-GCM',
    iv: base64ToBytes(iv),
    additionalData: encoder.encode(`access-code:${id}`)
  }, key, base64ToBytes(ciphertext));
  return new TextDecoder().decode(plaintext);
}

function bytesToBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function findActiveAccessCode(env, credential) {
  const code = normalizeAccessCode(credential);
  if (!/^[A-HJ-NP-Z2-9]{8}$/.test(code) || !env.SECRET_KEY) return null;
  const codeHash = await hashAccessCode(code, env.SECRET_KEY);
  const records = await loadAccessCodeRecords(env);
  return records.find(record => isAccessRecordActive(record) && timingSafeEqual(record.codeHash, codeHash)) || null;
}

async function createViewerSession(record, env) {
  const expiresAt = Number(record.expiresAt);
  const signature = await generateSignature(`viewer:${record.id}`, expiresAt, env.SECRET_KEY);
  return `${record.id}.${expiresAt}.${signature}`;
}

async function validateViewerSession(token, env) {
  const match = /^([0-9a-f-]{36})\.(\d{10,14})\.([0-9a-f]{64})$/i.exec(token);
  if (!match) return null;
  const [, id, expiresText, signature] = match;
  const expiresAt = Number(expiresText);
  if (!Number.isFinite(expiresAt) || Date.now() >= expiresAt) return null;
  const expected = await generateSignature(`viewer:${id}`, expiresAt, env.SECRET_KEY);
  if (!timingSafeEqual(signature, expected)) return null;
  const record = await getAccessCodeRecord(env, id);
  if (!record || !isAccessRecordActive(record) || Number(record.expiresAt) !== expiresAt) return null;
  return { role: 'viewer', accessCodeId: id, expiresAt };
}

function timingSafeEqual(a, b) {
  const left = String(a || '');
  const right = String(b || '');
  let mismatch = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i++) {
    mismatch |= (left.charCodeAt(i % Math.max(left.length, 1)) || 0) ^
      (right.charCodeAt(i % Math.max(right.length, 1)) || 0);
  }
  return mismatch === 0;
}

function getCookieValue(cookieHeader, name) {
  for (const part of cookieHeader.split(';')) {
    const [key, ...valueParts] = part.trim().split('=');
    if (key === name) return decodeURIComponent(valueParts.join('='));
  }
  return '';
}

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return corsResponse(new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...extraHeaders }
  }));
}

function getAuthClientKey(request) {
  return request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'local';
}

function isAuthRateLimited(clientKey) {
  const entry = authFailureBuckets.get(clientKey);
  if (!entry) return false;
  if (Date.now() - entry.startedAt >= AUTH_RATE_WINDOW_MS) {
    authFailureBuckets.delete(clientKey);
    return false;
  }
  return entry.failures >= AUTH_RATE_MAX_FAILURES;
}

function recordAuthFailure(clientKey) {
  const now = Date.now();
  const entry = authFailureBuckets.get(clientKey);
  if (!entry || now - entry.startedAt >= AUTH_RATE_WINDOW_MS) {
    authFailureBuckets.set(clientKey, { failures: 1, startedAt: now });
  } else {
    entry.failures += 1;
  }
  if (authFailureBuckets.size > 1000) {
    for (const [key, bucket] of authFailureBuckets) {
      if (now - bucket.startedAt >= AUTH_RATE_WINDOW_MS) authFailureBuckets.delete(key);
    }
  }
}

function clearAuthFailures(clientKey) {
  authFailureBuckets.delete(clientKey);
}

// 跨域响应包装
function corsResponse(response) {
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', '*');
  headers.set('Access-Control-Allow-Methods', 'GET, HEAD, POST, DELETE, OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

// 防盗链 Referer 校验
function checkReferer(request, env) {
  const allowed = env.ALLOWED_REFERER;
  if (!allowed || allowed.trim() === '') {
    return true; // 没有配置防盗链，放行
  }
  const referer = request.headers.get('Referer');
  if (!referer) {
    return true; // 允许无 Referer 直接访问（例如浏览器直达下载，wget，curl）
  }
  try {
    const refUrl = new URL(referer);
    return refUrl.hostname.includes(allowed) || referer.includes(allowed);
  } catch (e) {
    return false;
  }
}

// 基于 Web Crypto HMAC-SHA256 生成签名
async function generateSignature(key, expires, secret) {
  const encoder = new TextEncoder();
  const secretKeyData = encoder.encode(secret);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    secretKeyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const message = `${key}:${expires}`;
  const signatureBuffer = await crypto.subtle.sign(
    'HMAC',
    cryptoKey,
    encoder.encode(message)
  );
  const hashArray = Array.from(new Uint8Array(signatureBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// 校验 HMAC-SHA256 签名及时效
async function verifySignature(key, expires, signature, secret) {
  const now = Date.now();
  if (now > parseInt(expires)) {
    return false; // 已过期
  }
  const expectedSig = await generateSignature(key, expires, secret);
  return signature === expectedSig;
}

// 执行 GitHub 自动同步拉取逻辑
// 执行 GitHub 自动同步拉取逻辑
async function performGithubSync(env, singleKey = null) {
  let syncList = [];
  try {
    const configObject = await env.BUCKET.get('.config/sync_list.json');
    if (configObject) {
      syncList = await configObject.json();
    } else {
      syncList = [
        {
          url: 'https://github.com/v2fly/geoip/releases/latest/download/geoip.dat',
          key: 'geoip.dat',
          versioning: false,
          maxVersions: 3
        }
      ];
      await env.BUCKET.put('.config/sync_list.json', JSON.stringify(syncList), {
        httpMetadata: { contentType: 'application/json' }
      });
    }
  } catch (e) {
    console.error('Failed to load sync list config:', e.message);
    return [{ error: 'Failed to load config: ' + e.message }];
  }

  // 如果指定了单个 key，则只过滤出该 key 进行同步
  if (singleKey) {
    syncList = syncList.filter(item => item.key === singleKey);
    if (syncList.length === 0) {
      return [{ key: singleKey, status: 'failed', error: 'Subscription key not found' }];
    }
  }

  const results = [];
  for (const item of syncList) {
    try {
      if (!item.url || !item.key) continue;

      // 1. 获取主文件的 R2 元数据，获取 remote_etag / remote_last_modified 做条件更新判定
      const existingObj = await env.BUCKET.head(item.key);
      const headers = {
        'User-Agent': 'AetherStorage-Sync-Agent/1.0'
      };

      if (existingObj && existingObj.customMetadata) {
        if (existingObj.customMetadata.remote_etag) {
          headers['If-None-Match'] = existingObj.customMetadata.remote_etag;
        }
        if (existingObj.customMetadata.remote_last_modified) {
          headers['If-Modified-Since'] = existingObj.customMetadata.remote_last_modified;
        }
      }

      const res = await fetch(item.url, { headers });

      if (res.status === 304) {
        results.push({ key: item.key, status: 'not_modified' });
        continue;
      }

      if (!res.ok) {
        throw new Error(`HTTP error! status: ${res.status}`);
      }

      const remoteEtag = res.headers.get('ETag') || '';
      const remoteLastModified = res.headers.get('Last-Modified') || '';

      // 2. 归档历史版本（开启 versioning 且存在旧文件时）
      if (item.versioning && existingObj) {
        const keyParts = item.key.split('/');
        const filename = keyParts.pop();
        const folderPrefix = keyParts.length > 0 ? keyParts.join('/') + '/' : '';
        
        const dotIdx = filename.lastIndexOf('.');
        const baseName = dotIdx !== -1 ? filename.substring(0, dotIdx) : filename;
        const ext = dotIdx !== -1 ? filename.substring(dotIdx) : '';
        
        const oldSyncTime = existingObj.customMetadata?.sync_time || new Date().toISOString();
        const formattedTime = oldSyncTime.replace(/[-T:]/g, '_').substring(0, 19);
        
        const historyKey = `.history/${item.key}/${folderPrefix}${baseName}_v${formattedTime}${ext}`;

        const oldFullObj = await env.BUCKET.get(item.key);
        if (oldFullObj) {
          await env.BUCKET.put(historyKey, oldFullObj.body, {
            httpMetadata: oldFullObj.httpMetadata,
            customMetadata: {
              ...(oldFullObj.customMetadata || {}),
              archived_at: new Date().toISOString()
            }
          });
        }
      }

      // 3. 流式写入主对象
      await env.BUCKET.put(item.key, res.body, {
        httpMetadata: {
          contentType: res.headers.get('Content-Type') || 'application/octet-stream'
        },
        customMetadata: {
          remote_etag: remoteEtag,
          remote_last_modified: remoteLastModified,
          sync_time: new Date().toISOString()
        }
      });

      // 4. 超额历史清理（若开启了版本控制）
      if (item.versioning) {
        const maxV = Number(item.maxVersions) || 3;
        const historyPrefix = `.history/${item.key}/`;
        const objectsList = await env.BUCKET.list({ prefix: historyPrefix });
        
        const unpinnedVersions = [];
        for (const obj of objectsList.objects) {
          const headObj = await env.BUCKET.head(obj.key);
          if (headObj) {
            const isPinned = headObj.customMetadata?.pinned === 'true';
            if (!isPinned) {
              unpinnedVersions.push({
                key: obj.key,
                uploaded: obj.uploaded
              });
            }
          }
        }

        unpinnedVersions.sort((a, b) => b.uploaded.getTime() - a.uploaded.getTime());

        if (unpinnedVersions.length > maxV) {
          const toDelete = unpinnedVersions.slice(maxV);
          for (const dObj of toDelete) {
            await env.BUCKET.delete(dObj.key);
          }
        }
      }

      results.push({ key: item.key, status: 'success' });
    } catch (err) {
      console.error(`Sync failed for ${item.key}:`, err.message);
      results.push({ key: item.key, status: 'failed', error: err.message });
    }
  }
  return results;
}
