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
      
      // 路由：流式文件下载与安全签名校验
      if (pathname === '/api/download') {
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
          // 方式 1: 预签名链接验证
          const isValidSig = await verifySignature(key, expires, signature, env.SECRET_KEY || 'default-salt');
          if (isValidSig) {
            isAuthorized = true;
          }
        } else if (token && token === env.AUTH_PASSWORD) {
          // 方式 2: 控制面板直连下载验证
          isAuthorized = true;

          // 防盗链保护仅在直连下载时生效（分享链已自带加密时效，不限制 Referer 以便于多场景分享）
          if (!checkReferer(request, env)) {
            return corsResponse(new Response('Forbidden: Hotlinking is not allowed', { status: 403 }));
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
        headers.set('Cache-Control', 'public, max-age=31536000');

        return corsResponse(new Response(object.body, {
          headers
        }));
      }

      // 除下载接口外，其他 API 都必须使用 Authorization 头校验登录状态
      if (!verifyAdminAuth(request, env)) {
        return corsResponse(new Response(JSON.stringify({ error: 'Unauthorized' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        }));
      }

      // 路由：获取文件列表
      if (pathname === '/api/list' && request.method === 'GET') {
        const listResult = await env.BUCKET.list();
        const files = listResult.objects.map(obj => ({
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
        const keyParam = url.searchParams.get('key');
        if (!keyParam) {
          return corsResponse(new Response('Missing file key', { status: 400 }));
        }
        const key = decodeURIComponent(keyParam);
        
        // 生成 10 分钟有效期 (Date.now() + 600,000 毫秒)
        const expires = Date.now() + 10 * 60 * 1000;
        const signature = await generateSignature(key, expires, env.SECRET_KEY || 'default-salt');
        
        const shareUrl = `${url.origin}/api/download?key=${encodeURIComponent(key)}&expires=${expires}&signature=${signature}`;
        
        return corsResponse(new Response(JSON.stringify({ url: shareUrl }), {
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

      // 路由：删除文件
      if (pathname === '/api/delete' && request.method === 'DELETE') {
        const keyParam = url.searchParams.get('key');
        if (!keyParam) {
          return corsResponse(new Response('Missing file key', { status: 400 }));
        }
        const key = decodeURIComponent(keyParam);

        await env.BUCKET.delete(key);

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
        const results = await performGithubSync(env);
        return corsResponse(new Response(JSON.stringify({ success: true, results }), {
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

// ==========================================
// 辅助函数定义
// ==========================================

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
async function performGithubSync(env) {
  let syncList = [];
  try {
    const configObject = await env.BUCKET.get('.config/sync_list.json');
    if (configObject) {
      syncList = await configObject.json();
    } else {
      syncList = [
        {
          url: 'https://github.com/v2fly/geoip/releases/latest/download/geoip.dat',
          key: 'geoip.dat'
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

  const results = [];
  for (const item of syncList) {
    try {
      if (!item.url || !item.key) continue;
      
      const res = await fetch(item.url, {
        headers: {
          'User-Agent': 'AetherStorage-Sync-Agent/1.0'
        }
      });
      
      if (!res.ok) {
        throw new Error(`HTTP error! status: ${res.status}`);
      }
      
      // 流式写入 R2 存储桶，防止 Workers 内存溢出
      await env.BUCKET.put(item.key, res.body, {
        httpMetadata: {
          contentType: res.headers.get('Content-Type') || 'application/octet-stream'
        }
      });
      
      results.push({ key: item.key, status: 'success' });
    } catch (err) {
      console.error(`Sync failed for ${item.key}:`, err.message);
      results.push({ key: item.key, status: 'failed', error: err.message });
    }
  }
  return results;
}
