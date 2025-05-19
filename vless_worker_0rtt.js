//未实验修改版

if (earlyDataContext.hasEarlyData) {
    console.log(`0-RTT status: Enabled with ${earlyDataContext.size} bytes early data (max: ${maxEarlyData})`);
  } else {
    console.log(`0-RTT status: ${enableZeroRTT ? 'Enabled but no early data received' : 'Disabled'}`);
  }let userID = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
let socks5Config = {
  host: '你的socks5代理ip地址',
  port: 1080,
  username: '',
  password: ''
};

import { connect } from 'cloudflare:sockets';

// WebSocket 状态常量
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

// 0-RTT 配置
const ZERO_RTT_CONFIG = {
  headerName: 'sec-websocket-protocol' // 早期数据传输头
};

export default {
  async fetch(request, env, ctx) {
    try {
      // 从环境变量获取配置
      userID = env.UUID || userID;
      if (env.SOCKS5_HOST) {
        socks5Config.host = env.SOCKS5_HOST;
        socks5Config.port = parseInt(env.SOCKS5_PORT || '1080');
        socks5Config.username = env.SOCKS5_USERNAME || '';
        socks5Config.password = env.SOCKS5_PASSWORD || '';
      }
      
      // 检查是否为 WebSocket 升级请求
      const upgradeHeader = request.headers.get('Upgrade');
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
        const url = new URL(request.url);
        
        // 处理根路径请求
        if (url.pathname === '/') {
          return createHomePage();
        }
        
        // 处理 UUID 路径请求，返回配置信息
        if (url.pathname === `/${userID}`) {
          const host = request.headers.get('Host');
          const vlessConfig = createVLESSConfig(userID, host);
          return new Response(vlessConfig, {
            status: 200,
            headers: { 
              'Content-Type': 'text/plain;charset=utf-8',
              'Cache-Control': 'no-cache'
            },
          });
        }
        
        return new Response('Not Found', { status: 404 });
      }
      
      // 处理 WebSocket 升级请求，支持 0-RTT
      return await handleVLESSWebSocket(request);
    } catch (err) {
      console.error('Main error:', err);
      return new Response(err.toString(), { status: 500 });
    }
  },
};

// 创建主页响应
function createHomePage() {
  const html = `
<!DOCTYPE html>
<html>
<head>
    <title>VLESS Proxy Server</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 600px; margin: 0 auto; }
        .feature { background: #f5f5f5; padding: 15px; margin: 10px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>VLESS Proxy Server</h1>
        <div class="feature">
            <h3>✨ 功能特性</h3>
            <ul>
                <li>支持 VLESS over WebSocket</li>
                <li>支持 WS-0RTT 降低延迟</li>
                <li>支持 SOCKS5 代理</li>
                <li>自动重试机制</li>
            </ul>
        </div>
        <div class="feature">
            <h3>📝 使用说明</h3>
            <p>访问 <code>/UUID</code> 获取配置链接</p>
            <p><strong>0-RTT 控制：</strong></p>
            <ul>
                <li>标准路径: <code>/</code> (不使用 0-RTT)</li>
                <li>0-RTT 路径: <code>/?ed=2048</code> (启用 0-RTT，最大早期数据 2048 字节)</li>
                <li>自定义大小: <code>/?ed=1024</code> (可调整 1-4096)</li>
            </ul>
        </div>
    </div>
</body>
</html>`;
  return new Response(html, {
    headers: { 'Content-Type': 'text/html;charset=utf-8' }
  });
}

// 创建 VLESS 配置（支持可选的 0-RTT）
function createVLESSConfig(uuid, host) {
  // 创建基础配置
  const baseParams = new URLSearchParams({
    encryption: 'none',
    security: 'tls',
    sni: host,
    type: 'ws',
    host: host,
    path: '/'
  });
  
  // 生成两个配置：标准版和 0-RTT 版
  const standardConfig = `vless://${uuid}@${host}:443?${baseParams.toString()}#${host}-Standard`;
  
  // 0-RTT 版本：在路径中添加 ?ed=2048
  const zeroRTTParams = new URLSearchParams(baseParams);
  const zeroRTTPath = '/?ed=2048';
  zeroRTTParams.set('path', zeroRTTPath);
  const zeroRTTConfig = `vless://${uuid}@${host}:443?${zeroRTTParams.toString()}#${host}-0RTT`;
  
  return `标准配置（无 0-RTT）：
${standardConfig}

0-RTT 配置（降低延迟）：
${zeroRTTConfig}

使用说明：
- 标准配置：普通连接，兼容性最好
- 0-RTT 配置：启用 WebSocket 0-RTT，可降低连接延迟
- 可以手动修改 ed 参数（1-4096）来调整早期数据大小`;
}

// 处理 VLESS WebSocket 连接，支持 0-RTT
async function handleVLESSWebSocket(request) {
  const wsPair = new WebSocketPair();
  const [clientWS, serverWS] = Object.values(wsPair);

  serverWS.accept();

  // 增强的早期数据处理
  const earlyDataContext = createEarlyDataContext(request);
  const wsReadable = createWebSocketReadableStream(serverWS, earlyDataContext);
  let remoteSocket = null;
  let isFirstChunk = true;

  wsReadable.pipeTo(new WritableStream({
    async write(chunk) {
      try {
        // 如果已经建立远程连接，直接转发数据
        if (remoteSocket && !isFirstChunk) {
          await forwardToRemote(remoteSocket, chunk);
          return;
        }

        // 处理第一个数据块（包含 VLESS 头和可能的早期数据）
        if (isFirstChunk) {
          isFirstChunk = false;
          await handleFirstChunk(chunk, serverWS, (socket) => {
            remoteSocket = socket;
          });
        }
      } catch (error) {
        console.error('Write error:', error);
        await closeConnections(serverWS, remoteSocket, 1011, 'Write error');
      }
    },
    
    async close() {
      await closeConnections(serverWS, remoteSocket);
    },
    
    async abort(reason) {
      console.error('Stream aborted:', reason);
      await closeConnections(serverWS, remoteSocket, 1011, 'Stream aborted');
    }
  })).catch(async err => {
    console.error('WebSocket stream error:', err);
    await closeConnections(serverWS, remoteSocket, 1011, 'Stream error');
  });

  return new Response(null, {
    status: 101,
    webSocket: clientWS,
  });
}

// 创建早期数据上下文（支持 URL 参数控制）
function createEarlyDataContext(request, maxEarlyDataSize = 0) {
  const context = {
    hasEarlyData: false,
    earlyData: null,
    size: 0
  };

  // 只有当 maxEarlyDataSize > 0 时才处理早期数据
  if (maxEarlyDataSize === 0) {
    return context;
  }

  const protocolHeader = request.headers.get(ZERO_RTT_CONFIG.headerName) || '';
  
  if (protocolHeader) {
    try {
      // 解码 Base64Url 早期数据
      const decoded = base64urlDecode(protocolHeader);
      if (decoded && decoded.length > 0 && decoded.length <= maxEarlyDataSize) {
        context.hasEarlyData = true;
        context.earlyData = decoded;
        context.size = decoded.length;
        console.log(`0-RTT enabled: Received ${context.size} bytes of early data (max: ${maxEarlyDataSize})`);
      } else if (decoded && decoded.length > maxEarlyDataSize) {
        console.warn(`0-RTT: Early data too large: ${decoded.length} > ${maxEarlyDataSize}, ignoring`);
      }
    } catch (e) {
      console.warn('0-RTT: Failed to decode early data:', e.message);
    }
  }

  return context;
}

// Base64Url 解码
function base64urlDecode(str) {
  // 替换 URL 安全字符
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  
  // 添加填充
  while (base64.length % 4) {
    base64 += '=';
  }
  
  try {
    const decoded = atob(base64);
    return new Uint8Array(Array.from(decoded, c => c.charCodeAt(0)));
  } catch (e) {
    throw new Error('Invalid base64url string');
  }
}

// 创建 WebSocket 可读流，支持条件性早期数据
function createWebSocketReadableStream(ws, earlyDataContext) {
  let earlyDataSent = false;
  
  return new ReadableStream({
    start(controller) {
      // 只有当启用 0-RTT 且有早期数据时才处理
      if (earlyDataContext.hasEarlyData && !earlyDataSent) {
        controller.enqueue(earlyDataContext.earlyData.buffer);
        earlyDataSent = true;
        console.log('0-RTT: Early data enqueued');
      }
      
      ws.addEventListener('message', event => {
        if (event.data) {
          controller.enqueue(event.data);
        }
      });
      
      ws.addEventListener('close', () => {
        try {
          controller.close();
        } catch (e) {
          // 控制器可能已经关闭
        }
      });
      
      ws.addEventListener('error', err => {
        console.error('WebSocket error:', err);
        try {
          controller.error(err);
        } catch (e) {
          // 控制器可能已经关闭
        }
      });
    }
  });
}

// 处理第一个数据块
async function handleFirstChunk(chunk, serverWS, setRemoteSocket) {
  // 解析 VLESS 协议头
  const result = parseVLESSHeader(chunk, userID);
  if (result.hasError) {
    throw new Error(result.message);
  }

  // 构造响应头
  const vlessRespHeader = new Uint8Array([result.vlessVersion[0], 0]);
  const rawClientData = chunk.slice(result.rawDataIndex);

  // 优化的连接建立策略
  const connectionStrategy = {
    direct: () => connectDirect(result.addressRemote, result.portRemote),
    socks5: () => connectViaSocks5(result.addressRemote, result.portRemote)
  };

  try {
    // 尝试直连
    const tcpSocket = await connectionStrategy.direct();
    setRemoteSocket(tcpSocket);
    
    // 立即发送客户端数据
    if (rawClientData.length > 0) {
      await forwardToRemote(tcpSocket, rawClientData);
    }
    
    // 建立双向数据转发
    await establishBidirectionalPipe(tcpSocket, serverWS, vlessRespHeader);
    
    console.log(`Connected to ${result.addressRemote}:${result.portRemote} directly`);
    
  } catch (directError) {
    console.warn('Direct connection failed, trying SOCKS5:', directError.message);
    
    // 直连失败，尝试 SOCKS5 代理
    if (!socks5Config.host) {
      throw new Error('No SOCKS5 proxy configured and direct connection failed');
    }
    
    try {
      const tcpSocket = await connectionStrategy.socks5();
      setRemoteSocket(tcpSocket);
      
      // 发送客户端数据
      if (rawClientData.length > 0) {
        await forwardToRemote(tcpSocket, rawClientData);
      }
      
      // 建立双向数据转发
      await establishBidirectionalPipe(tcpSocket, serverWS, vlessRespHeader);
      
      console.log(`Connected to ${result.addressRemote}:${result.portRemote} via SOCKS5`);
      
    } catch (socks5Error) {
      console.error('SOCKS5 connection failed:', socks5Error);
      throw new Error(`All connection methods failed: ${socks5Error.message}`);
    }
  }
}

// 直连函数
async function connectDirect(address, port) {
  return await connect({
    hostname: address,
    port: port
  });
}

// 通过 SOCKS5 代理连接（优化版）
async function connectViaSocks5(address, port) {
  const sock = await connect({
    hostname: socks5Config.host,
    port: socks5Config.port
  });

  const writer = sock.writable.getWriter();
  const reader = sock.readable.getReader();

  try {
    // SOCKS5 握手
    await socks5Handshake(writer, reader);
    
    // 认证（如果需要）
    if (socks5Config.username && socks5Config.password) {
      await socks5Authenticate(writer, reader);
    }
    
    // 建立连接
    await socks5Connect(writer, reader, address, port);
    
    return sock;
  } finally {
    writer.releaseLock();
    reader.releaseLock();
  }
}

// SOCKS5 握手
async function socks5Handshake(writer, reader) {
  const auth = socks5Config.username && socks5Config.password ? 0x02 : 0x00;
  const init = new Uint8Array([0x05, 0x01, auth]);
  await writer.write(init);

  const { value: initRes } = await reader.read();
  if (!initRes || initRes[0] !== 0x05 || initRes[1] !== auth) {
    throw new Error('SOCKS5 handshake failed');
  }
}

// SOCKS5 认证
async function socks5Authenticate(writer, reader) {
  const username = new TextEncoder().encode(socks5Config.username);
  const password = new TextEncoder().encode(socks5Config.password);
  
  const authReq = new Uint8Array(3 + username.length + password.length);
  authReq[0] = 0x01; // 版本
  authReq[1] = username.length;
  authReq.set(username, 2);
  authReq[2 + username.length] = password.length;
  authReq.set(password, 3 + username.length);
  
  await writer.write(authReq);

  const { value: authRes } = await reader.read();
  if (!authRes || authRes[0] !== 0x01 || authRes[1] !== 0x00) {
    throw new Error('SOCKS5 authentication failed');
  }
}

// SOCKS5 连接请求
async function socks5Connect(writer, reader, address, port) {
  const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(address);
  const encodedAddr = isIP ? 
    address.split('.').map(Number) : 
    new TextEncoder().encode(address);
  
  const addrLen = isIP ? 4 : encodedAddr.length;
  const connectReq = new Uint8Array(6 + addrLen + 1);
  
  let offset = 0;
  connectReq[offset++] = 0x05; // 版本
  connectReq[offset++] = 0x01; // CONNECT 命令
  connectReq[offset++] = 0x00; // 保留字段
  connectReq[offset++] = isIP ? 0x01 : 0x03; // 地址类型
  
  if (isIP) {
    connectReq.set(encodedAddr, offset);
    offset += 4;
  } else {
    connectReq[offset++] = addrLen;
    connectReq.set(encodedAddr, offset);
    offset += addrLen;
  }
  
  // 端口（大端序）
  connectReq[offset++] = port >> 8;
  connectReq[offset] = port & 0xff;
  
  await writer.write(connectReq);

  const { value: connectRes } = await reader.read();
  if (!connectRes || connectRes[0] !== 0x05 || connectRes[1] !== 0x00) {
    throw new Error(`SOCKS5 connection failed: ${connectRes ? connectRes[1] : 'no response'}`);
  }
}

// 转发数据到远程服务器
async function forwardToRemote(remoteSocket, data) {
  const writer = remoteSocket.writable.getWriter();
  try {
    await writer.write(data);
  } finally {
    writer.releaseLock();
  }
}

// 建立双向数据管道
async function establishBidirectionalPipe(remoteSocket, serverWS, vlessHeader) {
  let headerSent = false;
  
  // 远程到 WebSocket 的管道
  const remotePipe = remoteSocket.readable.pipeTo(new WritableStream({
    write(chunk) {
      if (serverWS.readyState === WS_READY_STATE_OPEN) {
        if (!headerSent) {
          // 发送 VLESS 响应头和第一块数据
          const combined = new Uint8Array(vlessHeader.byteLength + chunk.byteLength);
          combined.set(vlessHeader, 0);
          combined.set(new Uint8Array(chunk), vlessHeader.byteLength);
          serverWS.send(combined.buffer);
          headerSent = true;
        } else {
          serverWS.send(chunk);
        }
      }
    },
    close() {
      if (serverWS.readyState === WS_READY_STATE_OPEN) {
        serverWS.close(1000, 'Remote closed');
      }
    },
    abort(reason) {
      console.error('Remote to WebSocket pipe aborted:', reason);
      if (serverWS.readyState === WS_READY_STATE_OPEN) {
        serverWS.close(1011, 'Remote aborted');
      }
    }
  }));
  
  // 监听远程连接关闭
  remoteSocket.closed.catch(error => {
    console.error('Remote socket closed with error:', error);
  }).finally(() => {
    if (serverWS.readyState === WS_READY_STATE_OPEN) {
      serverWS.close(1000, 'Remote connection closed');
    }
  });
  
  return remotePipe;
}

// 关闭连接
async function closeConnections(serverWS, remoteSocket, code = 1000, reason = 'Normal closure') {
  // 关闭 WebSocket
  if (serverWS && serverWS.readyState === WS_READY_STATE_OPEN) {
    try {
      serverWS.close(code, reason);
    } catch (e) {
      console.warn('Error closing WebSocket:', e);
    }
  }
  
  // 关闭远程套接字
  if (remoteSocket) {
    try {
      await remoteSocket.close();
    } catch (e) {
      console.warn('Error closing remote socket:', e);
    }
  }
}

// 解析 VLESS 协议头（优化版）
function parseVLESSHeader(buffer, userID) {
  const minHeaderSize = 1 + 16 + 1 + 1 + 2 + 1 + 1; // 最小头部大小
  if (buffer.byteLength < minHeaderSize) {
    return { hasError: true, message: `Header too small: ${buffer.byteLength} < ${minHeaderSize}` };
  }
  
  const view = new DataView(buffer);
  let offset = 0;
  
  // 版本
  const version = new Uint8Array(buffer.slice(offset, offset + 1));
  offset += 1;
  
  // UUID 验证
  const uuid = formatUUID(new Uint8Array(buffer.slice(offset, offset + 16)));
  offset += 16;
  
  if (uuid !== userID) {
    return { hasError: true, message: `Invalid UUID: ${uuid}` };
  }
  
  // 附加信息长度
  const optionsLength = view.getUint8(offset);
  offset += 1 + optionsLength;
  
  // 命令
  const command = view.getUint8(offset);
  offset += 1;
  
  if (command !== 1) {
    return { hasError: true, message: `Unsupported command: ${command}` };
  }
  
  // 端口
  const port = view.getUint16(offset);
  offset += 2;
  
  // 地址解析
  const addressType = view.getUint8(offset);
  offset += 1;
  
  let address = '';
  
  switch (addressType) {
    case 1: // IPv4
      if (buffer.byteLength < offset + 4) {
        return { hasError: true, message: 'IPv4 address incomplete' };
      }
      address = Array.from(new Uint8Array(buffer.slice(offset, offset + 4))).join('.');
      offset += 4;
      break;
      
    case 3: // 域名
      if (buffer.byteLength < offset + 1) {
        return { hasError: true, message: 'Domain length missing' };
      }
      const domainLength = view.getUint8(offset);
      offset += 1;
      if (buffer.byteLength < offset + domainLength) {
        return { hasError: true, message: 'Domain address incomplete' };
      }
      address = new TextDecoder().decode(buffer.slice(offset, offset + domainLength));
      offset += domainLength;
      break;
      
    case 4: // IPv6
      if (buffer.byteLength < offset + 16) {
        return { hasError: true, message: 'IPv6 address incomplete' };
      }
      const ipv6Parts = [];
      for (let i = 0; i < 8; i++) {
        ipv6Parts.push(view.getUint16(offset + i * 2).toString(16));
      }
      address = ipv6Parts.join(':').replace(/(^|:)0+(\w)/g, '$1$2');
      offset += 16;
      break;
      
    default:
      return { hasError: true, message: `Unsupported address type: ${addressType}` };
  }
  
  return {
    hasError: false,
    addressRemote: address,
    portRemote: port,
    rawDataIndex: offset,
    vlessVersion: version
  };
}

// 格式化 UUID
function formatUUID(bytes) {
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}
