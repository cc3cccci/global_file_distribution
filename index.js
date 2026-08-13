import htmlContent from './index.html';

export default {
  async fetch(request, env, ctx) {
    // 处理 CORS 预检请求
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, HEAD, POST, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, Range, X-Cert-Token',
          'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Accept-Ranges, ETag, Content-Disposition, Content-Type',
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
        const body = await request.json();
        if (body.password === env.AUTH_PASSWORD) {
          return corsResponse(new Response(JSON.stringify({ success: true }), {
            headers: { 'Content-Type': 'application/json' }
          }));
        }
        return corsResponse(new Response(JSON.stringify({ error: 'Unauthorized' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 以下 API 均涉及数据访问，需要进行安全认证（下载接口有单独的签名鉴权）
      
      // 路由：流式文件下载与安全签名校验（支持 Range / 预览 inline / HEAD）
      if (pathname === '/api/download' && (request.method === 'GET' || request.method === 'HEAD')) {
        const keyParam = url.searchParams.get('key');
        if (!keyParam) {
          return corsResponse(new Response('Missing file key', { status: 400 }));
        }
        const key = decodeURIComponent(keyParam);

        // 验证下载凭证（支持两种方式：1. 带有有效 signature 的预签名链接；2. 拥有管理员 token）
        const signature = url.searchParams.get('signature');
        const expires = url.searchParams.get('expires');
        const token = url.searchParams.get('token');

        let isAuthorized = false;

        if (signature && expires) {
          const isValidSig = await verifySignature(key, expires, signature, env.SECRET_KEY || 'default-salt');
          if (isValidSig) {
            isAuthorized = true;
          }
        } else if (token && token === env.AUTH_PASSWORD) {
          isAuthorized = true;
          if (!checkReferer(request, env)) {
            return corsResponse(new Response('Forbidden: Hotlinking is not allowed', { status: 403 }));
          }
        }

        if (!isAuthorized) {
          return corsResponse(new Response('Unauthorized: Link expired or invalid credentials', { status: 403 }));
        }

        const inline = url.searchParams.get('inline') === '1';
        return corsResponse(await serveR2Object(env, request, key, {
          disposition: inline ? 'inline' : 'attachment',
          cacheControl: 'private, max-age=60'
        }));
      }

      // 路由：永久公开共享链接流式下载 (免鉴权，适用于软路由等外部设备)
      if (pathname.startsWith('/f/') && (request.method === 'GET' || request.method === 'HEAD')) {
        const key = decodeURIComponent(pathname.substring(3));
        if (!key) {
          return new Response('Missing filename', { status: 400 });
        }

        const publicFiles = await getPublicFiles(env);
        if (!publicFiles.includes(key)) {
          return new Response('Forbidden: This file is not public', { status: 403 });
        }

        const forceDownload = url.searchParams.get('dl') === '1';
        return corsResponse(await serveR2Object(env, request, key, {
          disposition: forceDownload ? 'attachment' : 'auto',
          cacheControl: 'no-cache, no-store, must-revalidate'
        }));
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

      // 除下载接口外，其他 API 都必须使用 Authorization 头校验登录状态
      if (!verifyAdminAuth(request, env)) {
        return corsResponse(new Response(JSON.stringify({ error: 'Unauthorized' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        }));
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

      // 路由：获取文件列表（自动翻页，避免超过 1000 个对象时截断）
      if (pathname === '/api/list' && request.method === 'GET') {
        const files = await listAllObjects(env);
        return corsResponse(new Response(JSON.stringify({ files }), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：证书看板（按域名聚合 certs/ 目录）
      if (pathname === '/api/certs' && request.method === 'GET') {
        const objects = await listAllObjects(env, 'certs/', ['customMetadata']);
        const domains = {};
        for (const obj of objects) {
          const parts = obj.key.split('/');
          if (parts.length < 3 || parts[0] !== 'certs') continue;
          const domain = parts[1];
          const filename = parts.slice(2).join('/');
          if (!domains[domain]) {
            domains[domain] = { domain, files: [], pushed_at: obj.uploaded, size: 0 };
          }
          domains[domain].files.push({
            filename,
            key: obj.key,
            size: obj.size,
            uploaded: obj.uploaded,
            pushed_at: obj.customMetadata?.pushed_at || obj.uploaded
          });
          domains[domain].size += obj.size;
          const pushed = obj.customMetadata?.pushed_at || obj.uploaded;
          if (pushed > domains[domain].pushed_at) domains[domain].pushed_at = pushed;
        }
        const certs = Object.values(domains).sort((a, b) => a.domain.localeCompare(b.domain));
        return corsResponse(new Response(JSON.stringify({ certs }), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：生成预签名分享链接（ttl 秒：10m / 1h / 6h / 1d / 7d）
      if (pathname === '/api/share' && request.method === 'GET') {
        const keyParam = url.searchParams.get('key');
        if (!keyParam) {
          return corsResponse(new Response('Missing file key', { status: 400 }));
        }
        const key = decodeURIComponent(keyParam);
        const ALLOWED_TTL = [600, 3600, 21600, 86400, 604800];
        let ttl = parseInt(url.searchParams.get('ttl') || '600', 10);
        if (!ALLOWED_TTL.includes(ttl)) ttl = 600;

        const expires = Date.now() + ttl * 1000;
        const signature = await generateSignature(key, expires, env.SECRET_KEY || 'default-salt');
        const shareUrl = `${url.origin}/api/download?key=${encodeURIComponent(key)}&expires=${expires}&signature=${signature}`;

        return corsResponse(new Response(JSON.stringify({
          url: shareUrl,
          expires,
          ttl,
          expiresAt: new Date(expires).toISOString()
        }), {
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：初始化分片上传
      if (pathname === '/api/upload-init' && request.method === 'POST') {
        const { filename, contentType } = await request.json();
        if (!filename) {
          return corsResponse(new Response('Missing filename', { status: 400 }));
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
          const listed = await listAllObjects(env, key);
          const keysToDelete = listed.map(obj => obj.key);
          for (let i = 0; i < keysToDelete.length; i += 1000) {
            await env.BUCKET.delete(keysToDelete.slice(i, i + 1000));
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
        if (!path || !path.endsWith('/')) {
          return corsResponse(new Response('Invalid folder path', { status: 400 }));
        }
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
        const tags = await getFileTags(env);
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
      return corsResponse(new Response(`Error: ${err.message}`, { status: 500 }));
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
  return authHeader === env.AUTH_PASSWORD;
}

// 跨域响应包装
function corsResponse(response) {
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', '*');
  headers.set('Access-Control-Allow-Methods', 'GET, HEAD, POST, DELETE, OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, Range, X-Cert-Token');
  headers.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges, ETag, Content-Disposition, Content-Type');
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function guessContentType(key) {
  const ext = (key.split('.').pop() || '').toLowerCase();
  const map = {
    png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
    webp: 'image/webp', svg: 'image/svg+xml', avif: 'image/avif', ico: 'image/x-icon', bmp: 'image/bmp',
    mp4: 'video/mp4', webm: 'video/webm', mkv: 'video/x-matroska', mov: 'video/quicktime', m4v: 'video/mp4',
    mp3: 'audio/mpeg', wav: 'audio/wav', flac: 'audio/flac', ogg: 'audio/ogg', m4a: 'audio/mp4', opus: 'audio/opus',
    pdf: 'application/pdf',
    txt: 'text/plain; charset=utf-8', md: 'text/markdown; charset=utf-8', log: 'text/plain; charset=utf-8',
    json: 'application/json', js: 'text/javascript; charset=utf-8', css: 'text/css; charset=utf-8',
    html: 'text/html; charset=utf-8', xml: 'application/xml', csv: 'text/csv; charset=utf-8',
    yaml: 'text/yaml; charset=utf-8', yml: 'text/yaml; charset=utf-8', toml: 'text/plain; charset=utf-8',
    pem: 'application/x-pem-file', conf: 'text/plain; charset=utf-8', ini: 'text/plain; charset=utf-8',
    sh: 'text/x-sh; charset=utf-8'
  };
  return map[ext] || 'application/octet-stream';
}

function isPreviewableType(key) {
  const ct = guessContentType(key);
  return ct.startsWith('image/') || ct.startsWith('video/') || ct.startsWith('audio/') ||
    ct === 'application/pdf' || ct.startsWith('text/') || ct === 'application/json' || ct === 'application/xml';
}

async function listAllObjects(env, prefix = '', include) {
  const files = [];
  let cursor;
  do {
    const listed = await env.BUCKET.list({
      prefix,
      cursor,
      limit: 1000,
      ...(include ? { include } : {})
    });
    for (const obj of listed.objects) {
      files.push({
        key: obj.key,
        size: obj.size,
        uploaded: obj.uploaded.toISOString(),
        customMetadata: obj.customMetadata || undefined
      });
    }
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor);
  return files;
}

async function serveR2Object(env, request, key, { disposition = 'attachment', cacheControl = 'private, max-age=60' } = {}) {
  const filename = key.split('/').pop() || key;
  const guessedType = guessContentType(key);
  let mode = disposition;
  if (mode === 'auto') {
    mode = isPreviewableType(key) ? 'inline' : 'attachment';
  }

  if (request.method === 'HEAD') {
    const head = await env.BUCKET.head(key);
    if (!head) return new Response('File Not Found', { status: 404 });
    const headers = new Headers();
    head.writeHttpMetadata(headers);
    if (!headers.get('Content-Type') || headers.get('Content-Type') === 'application/octet-stream') {
      headers.set('Content-Type', guessedType);
    }
    headers.set('Content-Length', head.size.toString());
    headers.set('Accept-Ranges', 'bytes');
    headers.set('Cache-Control', cacheControl);
    headers.set('Content-Disposition', `${mode}; filename*=UTF-8''${encodeURIComponent(filename)}`);
    if (head.httpEtag) headers.set('ETag', head.httpEtag);
    return new Response(null, { status: 200, headers });
  }

  const object = await env.BUCKET.get(key, {
    range: request.headers,
    onlyIf: request.headers
  });

  if (object === null) {
    return new Response('File Not Found', { status: 404 });
  }

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  if (!headers.get('Content-Type') || headers.get('Content-Type') === 'application/octet-stream') {
    headers.set('Content-Type', guessedType);
  }
  headers.set('Accept-Ranges', 'bytes');
  headers.set('Cache-Control', cacheControl);
  headers.set('Content-Disposition', `${mode}; filename*=UTF-8''${encodeURIComponent(filename)}`);
  if (object.httpEtag) headers.set('ETag', object.httpEtag);

  if (!object.body) {
    return new Response(null, { status: 304, headers });
  }

  if (request.headers.has('range') && object.range) {
    const offset = object.range.offset || 0;
    const length = object.range.length != null ? object.range.length : (object.size - offset);
    const end = offset + length - 1;
    headers.set('Content-Range', `bytes ${offset}-${end}/${object.size}`);
    headers.set('Content-Length', String(length));
    return new Response(object.body, { status: 206, headers });
  }

  headers.set('Content-Length', object.size.toString());
  return new Response(object.body, { status: 200, headers });
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
