const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const HOST = process.env.HOST || '0.0.0.0';
const PORT = process.env.PORT || 8000;
const DIR  = process.argv[2]  || process.cwd();

const ext_to_mime = {
  '.css': 'text/css',
  '.html': 'text/html',
  '.ico': 'image/x-icon',
  '.jpg': 'image/jpeg',
  '.js': 'text/javascript',
  '.json': 'application/json',
  '.mp3': 'audio/mpeg',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ttf': 'application/x-font-ttf',
  '.wav': 'audio/wav',
};

function get_mime(file) {
  const ext = path.parse(file).ext;
  return ext_to_mime[ext] || 'text/plain';
}

const client_js = `
  const ws = new WebSocket('ws://localhost:${PORT}/websocket');
  ws.onmessage = event => {
    if (event.data == 'reload') {
      location.reload();
    }
  };
`;

async function server_request_callback(req, res) {
  if (req.method != 'GET') {
    res.statusCode = 404;
    res.end('Not Found');
    return;
  }
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = path.normalize(url.pathname).replace(/^\.\.\/+/, '');
  let file = path.join(DIR, pathname);
  try {
    let stats = await fs.promises.stat(file);
    if (stats.isDirectory()) {
      file += '/index.html';
      stats = await fs.promises.stat(file);
    } 
  } catch {
    res.statusCode = 404;
    res.end('404 Not Found');
    return;
  }
  try {
    const mime = get_mime(file)
    let buffer = await fs.promises.readFile(file);
    if (mime == 'text/html') {
      buffer = Buffer.from(buffer.toString().replace('</body>', `<script>${client_js}</script></body>`));
    }
    res.setHeader('Content-type', mime);
    res.end(buffer);
  } catch (err) {
    res.statusCode = 500;
    res.end(`500 Server Error: ${err}`);
  }
}

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function server_upgrade_callback(req, socket) {
  const key = req.headers['sec-websocket-key'];
  const accept = crypto.createHash('sha1').update(key + WS_GUID, 'binary').digest('base64');
  const http_response = [
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${accept}`
  ].concat('\r\n').join('\r\n');
  socket.write(http_response);
}

function parse_frame(frame_buffer) {
  const op_code = parse_frame_op_code(frame_buffer);
  const {len, mask_key, offset} = parse_frame_payload_info(frame_buffer);
  const data = parse_frame_masked_payload(frame_buffer, len, mask_key, offset);
  return { op_code, data };
}

const op_codes = [];
op_codes[0x1] = 'text';
op_codes[0x8] = 'close';
op_codes[0x9] = 'ping';
op_codes[0xA] = 'pong';

function parse_frame_op_code(frame_buffer) {
  const byte_0 = frame_buffer.readUInt8(0);
  return op_codes[byte_0 & 0xF] || null;
}

function parse_frame_payload_info(frame_buffer) {
  const byte_1 = frame_buffer.readUInt8(1);
  let offset = 2;
  let len = byte_1 & 0x7F;
  switch (len) {
    case 126:
      len = frame_buffer.readUInt16BE(2);
      offset += 2;
      break;
    case 127:
      len = frame_buffer.readBigUInt64BE(2);
      offset += 8;
      break;
    default:
      // :)
  }
  let mask_key = null;
  const is_masked = Boolean((byte_1 >>> 7) & 0x1);
  if (is_masked) {
    mask_key = frame_buffer.readUInt32BE(offset);
    offset += 4;
  }
  return {len, mask_key, offset};
}

function parse_frame_masked_payload(frame_buffer, len, mask_key, offset) {
  const original_data = frame_buffer.subarray(offset, offset + len);
  const transformed_data = Buffer.alloc(len);
  for (let i = 0; i < original_data.byteLength; ++i) {
    const j = i % 4;
    const shift_no_bits = j === 3 ? 0 : (3 - j) << 3;
    const mask_byte = (shift_no_bits === 0 ? mask_key : mask_key >>> shift_no_bits) & 0xFF;
    const transformed_byte = mask_byte ^ original_data.readUInt8(i);
    transformed_data.writeUInt8(transformed_byte, i);
  }
  return transformed_data;
}

function new_frame(op_code, data_buffer) {
  const byte_count = Buffer.byteLength(data_buffer);
  let len = byte_count;
  let offset = 2;
  if (byte_count > 65535) { 
    offset += 8;
    len = 127;
  } else if (byte_count > 125) {
    offset += 2;
    len = 126;
  }
  const frame_buffer = Buffer.alloc(offset + byte_count);
  const byte_1 = new_frame_byte_1(op_code);
  frame_buffer.writeUInt8(byte_1, 0); 
  frame_buffer[1] = len;
  if (len === 126) {
    frame_buffer.writeUInt16BE(byte_count, 2);
  } else if (len === 127) { // write actual payload length as a 64-bit unsigned integer
    frame_buffer.writeBigUInt64BE(BigInt(byte_count), 2);
  }
  data_buffer.copy(frame_buffer, offset);
  return frame_buffer;
}

function new_frame_byte_1(op_code) {
  // always fin=1 (no fragmentation)
  switch (op_code) {
    case 'text':
      return 0x81;
    case 'close':
      return 0x88;
    case 'ping':
      return 0x89;
    case 'pong':
      return 0x8A;
    default:
      throw new Error(`byte 1: op code ${op_code} not implemented`); 
  }
}

let clients = new Map();

function init_socket(req, socket) {
  clients.set(req.headers['sec-websocket-key'], socket);
  socket.on(
    'data', 
    (frame_buffer) => socket_data_callback(socket, frame_buffer)
  );
  // good enough
  clients.forEach((s, k) => {
    if (s.destroyed) {
      clients.delete(k);
    }
  });
}

function socket_data_callback(socket, frame_buffer) {
  // naivly assumes exactly 1 frame, with no fragmentation, is delivered on each data event.
  frame = parse_frame(frame_buffer)
  switch (frame.op_code) {
    case 'text':
      // noop
      break;
    case 'close':
      socket.write(new_frame('close', frame.data));
      socket.destroySoon();
      break;
    case 'ping':
      socket.write(new_frame('pong', frame.data));
      break;
    case 'pong':
      socket.write(new_frame('ping', frame.data));
      break;
  }
}

function server_listening_callback() {
  console.log(`Server started on ${HOST} port ${PORT}`);
}

let watch_timeout = null;

function watch_callback() {
  clearTimeout(watch_timeout);
  watch_timeout = setTimeout(() => {
    clients.forEach((socket, k) => {
      if(!socket.destroyed) {
        socket.write(new_frame('text', Buffer.from('reload')));
      }
    })
  }, 100);
}

const server = new http.Server();

server.on('request', server_request_callback);
server.on('upgrade', server_upgrade_callback);
server.on('upgrade', init_socket);
server.on('listening', server_listening_callback);

server.listen(PORT, HOST);

fs.watch(DIR, watch_callback);
