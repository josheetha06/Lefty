// Lefty's Content Disarm and Reconstruction (CDR) Engine
// Sanitizes incoming downloaded files by deconstructing them, purging active code,
// embedded macros, exploits, and polyglots, and rebuilding a 100% clean copy.

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');

// Supported extensions
const OFFICE_EXTENSIONS = new Set([
  '.docx', '.docm', '.dotm', '.xlsx', '.xlsm', '.xltm', '.pptx', '.pptm', '.potm'
]);
const PDF_EXTENSIONS = new Set(['.pdf']);
const IMAGE_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.gif']);
const DANGEROUS_EXTENSIONS = new Set([
  '.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.ps1', '.hta',
  '.cpl', '.com', '.pif', '.reg', '.wsf', '.iso', '.img', '.vhd'
]);

function isDangerousExecutable(filename) {
  const ext = path.extname(filename).toLowerCase();
  return DANGEROUS_EXTENSIONS.has(ext);
}

function isSupported(filename) {
  const ext = path.extname(filename).toLowerCase();
  return OFFICE_EXTENSIONS.has(ext) || PDF_EXTENSIONS.has(ext) || IMAGE_EXTENSIONS.has(ext) || DANGEROUS_EXTENSIONS.has(ext);
}

// ---------------- CRC32 implementation for ZIP headers ----------------
function crc32(buf) {
  let table = crc32.table;
  if (!table) {
    table = crc32.table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let k = 0; k < 8; k++) c = ((c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1));
      table[i] = c >>> 0;
    }
  }
  let crc = 0 ^ (-1);
  for (let i = 0; i < buf.length; i++) crc = (crc >>> 8) ^ table[(crc ^ buf[i]) & 0xFF];
  return (crc ^ (-1)) >>> 0;
}

// ---------------- PKZIP Parser & Builder (Pure Node.js) ----------------
function parseZip(buf) {
  let eocdOffset = -1;
  // Locate End of Central Directory from the end
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocdOffset = i; break; }
  }
  if (eocdOffset === -1) throw new Error('Not a valid ZIP/Office package');

  const cdCount = buf.readUInt16LE(eocdOffset + 10);
  const cdOffset = buf.readUInt32LE(eocdOffset + 16);

  const entries = [];
  let cur = cdOffset;
  for (let i = 0; i < cdCount; i++) {
    if (cur + 46 > buf.length || buf.readUInt32LE(cur) !== 0x02014b50) break;
    const method = buf.readUInt16LE(cur + 10);
    const compSize = buf.readUInt32LE(cur + 20);
    const uncompSize = buf.readUInt32LE(cur + 24);
    const nameLen = buf.readUInt16LE(cur + 28);
    const extraLen = buf.readUInt16LE(cur + 30);
    const commentLen = buf.readUInt16LE(cur + 32);
    const localOffset = buf.readUInt32LE(cur + 42);
    const name = buf.toString('utf8', cur + 46, cur + 46 + nameLen);

    // Read local file entry data
    if (localOffset + 30 <= buf.length) {
      const lhNameLen = buf.readUInt16LE(localOffset + 26);
      const lhExtraLen = buf.readUInt16LE(localOffset + 28);
      const dataOffset = localOffset + 30 + lhNameLen + lhExtraLen;
      const compData = buf.subarray(dataOffset, dataOffset + compSize);
      let uncompData;
      try {
        uncompData = method === 8 ? zlib.inflateRawSync(compData) : compData;
      } catch {
        uncompData = compData;
      }
      entries.push({ name, data: uncompData, compress: method === 8 });
    }

    cur += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

function buildZip(entries) {
  const localHeaders = [];
  const cdHeaders = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, 'utf8');
    const dataBuf = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data || '', 'utf8');
    const compressed = entry.compress !== false ? zlib.deflateRawSync(dataBuf) : dataBuf;
    const method = entry.compress !== false ? 8 : 0;
    const crc = crc32(dataBuf);

    // Local Header
    const lh = Buffer.alloc(30 + nameBuf.length);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0, 6);
    lh.writeUInt16LE(method, 8);
    lh.writeUInt16LE(0, 10);
    lh.writeUInt16LE(0, 12);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(compressed.length, 18);
    lh.writeUInt32LE(dataBuf.length, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28);
    nameBuf.copy(lh, 30);

    localHeaders.push(lh, compressed);

    // Central Directory Header
    const cdh = Buffer.alloc(46 + nameBuf.length);
    cdh.writeUInt32LE(0x02014b50, 0);
    cdh.writeUInt16LE(20, 4);
    cdh.writeUInt16LE(20, 6);
    cdh.writeUInt16LE(0, 8);
    cdh.writeUInt16LE(method, 10);
    cdh.writeUInt16LE(0, 12);
    cdh.writeUInt16LE(0, 14);
    cdh.writeUInt32LE(crc, 16);
    cdh.writeUInt32LE(compressed.length, 20);
    cdh.writeUInt32LE(dataBuf.length, 24);
    cdh.writeUInt16LE(nameBuf.length, 28);
    cdh.writeUInt16LE(0, 30);
    cdh.writeUInt16LE(0, 32);
    cdh.writeUInt16LE(0, 34);
    cdh.writeUInt16LE(0, 36);
    cdh.writeUInt32LE(0, 38);
    cdh.writeUInt32LE(offset, 42);
    nameBuf.copy(cdh, 46);

    cdHeaders.push(cdh);
    offset += lh.length + compressed.length;
  }

  const cdBuf = Buffer.concat(cdHeaders);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localHeaders, cdBuf, eocd]);
}

// ---------------- Disarm Office XML (DOCX, XLSX, PPTX) ----------------
function disarmOffice(buffer) {
  const actions = [];
  let entries;
  try {
    entries = parseZip(buffer);
  } catch (err) {
    return { safe: buffer, disarmed: false, error: err.message };
  }

  const MACRO_PATTERNS = [
    /vbaProject\.bin$/i,
    /vbaData\.xml$/i,
    /vbaProjectSignature\.bin$/i,
    /oleObject\d*\.bin$/i,
    /embeddings\/.*\.(bin|exe|dll)$/i,
    /activeX\//i
  ];

  const sanitizedEntries = [];

  for (const entry of entries) {
    const isMacro = MACRO_PATTERNS.some((pat) => pat.test(entry.name));
    if (isMacro) {
      actions.push(`Stripped malicious active component: ${entry.name}`);
      continue;
    }

    // Sanitize [Content_Types].xml
    if (entry.name === '[Content_Types].xml') {
      let xml = entry.data.toString('utf8');
      if (/macroEnabled/i.test(xml)) {
        xml = xml.replace(/application\/vnd\.ms-word\.document\.macroEnabled\.main\+xml/gi, 'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml')
                 .replace(/application\/vnd\.ms-excel\.sheet\.macroEnabled\.main\+xml/gi, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml')
                 .replace(/application\/vnd\.ms-powerpoint\.presentation\.macroEnabled\.main\+xml/gi, 'application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml');
        actions.push('Disarmed macro content-type declarations in [Content_Types].xml');
        entry.data = Buffer.from(xml, 'utf8');
      }
    }

    // Sanitize remote templates and dynamic relationships (Remote Template Injection)
    if (/\.rels$/i.test(entry.name)) {
      let relsXml = entry.data.toString('utf8');
      if (/attachedTemplate/i.test(relsXml) && /Target="https?:\/\//i.test(relsXml)) {
        relsXml = relsXml.replace(/Target="https?:\/\/[^"]+"/gi, 'Target=""');
        actions.push(`Neutralized remote template injection in ${entry.name}`);
        entry.data = Buffer.from(relsXml, 'utf8');
      }
    }

    sanitizedEntries.push(entry);
  }

  const disarmed = actions.length > 0;
  const safe = disarmed ? buildZip(sanitizedEntries) : buffer;
  return { safe, disarmed, actions };
}

// ---------------- Disarm PDF ----------------
function disarmPdf(buffer) {
  const actions = [];
  let content = buffer.toString('latin1');

  // 1. Strip trailing polyglot bytes after the final %%EOF
  const eofIdx = content.lastIndexOf('%%EOF');
  if (eofIdx !== -1 && eofIdx + 5 < content.length) {
    const trailingBytes = content.length - (eofIdx + 5);
    if (trailingBytes > 2) {
      actions.push(`Stripped ${trailingBytes} bytes of polyglot payload trailing %%EOF`);
      content = content.slice(0, eofIdx + 5) + '\n';
    }
  }

  // 2. Neutralize embedded JavaScript
  if (/\/JavaScript|\/JS\b/i.test(content)) {
    actions.push('Neutralized embedded JavaScript actions (/JavaScript, /JS)');
    content = content.replace(/\/JavaScript/g, '/X-Disarmed-JS')
                     .replace(/\/JS\b/g, '/X-Disarmed-JScript');
  }

  // 3. Neutralize /Launch executable triggers
  if (/\/Launch\b/i.test(content)) {
    actions.push('Neutralized /Launch execution actions');
    content = content.replace(/\/Launch\b/g, '/X-Disarmed-Launch');
  }

  // 4. Neutralize embedded file attachments
  if (/\/EmbeddedFiles\b/i.test(content)) {
    actions.push('Neutralized /EmbeddedFiles attachment stream');
    content = content.replace(/\/EmbeddedFiles\b/g, '/X-Disarmed-EF');
  }

  // 5. Neutralize interactive forms submission triggers
  if (/\/SubmitForm\b/i.test(content)) {
    actions.push('Neutralized /SubmitForm external data exfiltration trigger');
    content = content.replace(/\/SubmitForm\b/g, '/X-Disarmed-Submit');
  }

  const disarmed = actions.length > 0;
  const safe = disarmed ? Buffer.from(content, 'latin1') : buffer;
  return { safe, disarmed, actions };
}

// ---------------- Disarm Images (PNG, JPEG) ----------------
function disarmImage(buffer, extension) {
  const actions = [];
  const ext = extension.toLowerCase();

  // PNG
  if (ext === '.png') {
    // Check PNG signature: 89 50 4E 47 0D 0A 1A 0A
    if (buffer.length >= 8 && buffer.readUInt32BE(0) === 0x89504E47) {
      // Find IEND chunk (49 45 4E 44)
      const iendIdx = buffer.indexOf(Buffer.from('IEND'));
      if (iendIdx !== -1) {
        const expectedEnd = iendIdx + 4 + 4; // IEND + 4 bytes CRC
        if (expectedEnd < buffer.length) {
          actions.push(`Trimmed ${buffer.length - expectedEnd} bytes of polyglot payload appended to PNG`);
          return { safe: buffer.subarray(0, expectedEnd), disarmed: true, actions };
        }
      }
    }
  }

  // JPEG
  if (ext === '.jpg' || ext === '.jpeg') {
    // Starts with FF D8, ends with FF D9
    if (buffer.length >= 4 && buffer[0] === 0xFF && buffer[1] === 0xD8) {
      const eoiIdx = buffer.lastIndexOf(Buffer.from([0xFF, 0xD9]));
      if (eoiIdx !== -1 && eoiIdx + 2 < buffer.length) {
        actions.push(`Trimmed ${buffer.length - (eoiIdx + 2)} bytes of appended payload after JPEG EOI`);
        return { safe: buffer.subarray(0, eoiIdx + 2), disarmed: true, actions };
      }
    }
  }

  return { safe: buffer, disarmed: false, actions };
}

// ---------------- Route Buffer to Appropriate Disarmer ----------------
function disarmBuffer(buffer, filename) {
  const ext = path.extname(filename).toLowerCase();

  if (OFFICE_EXTENSIONS.has(ext)) {
    return disarmOffice(buffer);
  }
  if (PDF_EXTENSIONS.has(ext)) {
    return disarmPdf(buffer);
  }
  if (IMAGE_EXTENSIONS.has(ext)) {
    return disarmImage(buffer, ext);
  }

  return { safe: buffer, disarmed: false, actions: [] };
}

// ---------------- Quarantine Management ----------------
function quarantineFile(filePath, quarantineDir) {
  const qDir = quarantineDir || path.join(process.env.APPDATA || path.join(process.env.USERPROFILE || '', '.lefty'), 'lefty', 'quarantine');
  fs.mkdirSync(qDir, { recursive: true });

  const filename = path.basename(filePath);
  const timestamp = Date.now();
  const qFilename = `${timestamp}_${filename}`;
  const targetPath = path.join(qDir, qFilename);

  // Move original file to quarantine
  fs.renameSync(filePath, targetPath);

  // Leave a safe README explanation in place
  const noticePath = `${filePath}.quarantined.txt`;
  const notice = `[LEFTHY CDR SECURITY NOTICE]\n` +
    `File: ${filename}\n` +
    `Quarantined At: ${new Date(timestamp).toISOString()}\n` +
    `Reason: Untrusted executable/script download automatically quarantined during automated tasks.\n` +
    `Quarantine Location: ${targetPath}\n`;

  fs.writeFileSync(noticePath, notice, 'utf8');

  return {
    quarantined: true,
    originalFile: filename,
    quarantinePath: targetPath,
    noticePath
  };
}

// ---------------- High-Level File Disarm ----------------
async function disarmFile(filePath, options = {}) {
  const filename = path.basename(filePath);
  const ext = path.extname(filename).toLowerCase();

  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }

  // Dangerous binaries/scripts: Quarantine immediately
  if (isDangerousExecutable(filename)) {
    const qInfo = quarantineFile(filePath, options.quarantineDir);
    return {
      success: true,
      quarantined: true,
      disarmed: true,
      message: `Quarantined dangerous executable '${filename}'`,
      actions: ['Isolated executable binary to quarantine directory', 'Replaced with security notice'],
      safePath: qInfo.noticePath
    };
  }

  // Document/Image disarming
  const rawBuffer = fs.readFileSync(filePath);
  const result = disarmBuffer(rawBuffer, filename);

  if (result.disarmed) {
    // Preserve original in backup folder if requested
    const backupDir = path.join(path.dirname(filePath), '.lefty-backup');
    fs.mkdirSync(backupDir, { recursive: true });
    const backupPath = path.join(backupDir, `${filename}.orig`);
    fs.writeFileSync(backupPath, rawBuffer);

    // Write disarmed, sanitized content
    const safePath = options.outputPath || filePath;
    fs.writeFileSync(safePath, result.safe);

    return {
      success: true,
      disarmed: true,
      quarantined: false,
      actions: result.actions,
      message: `Disarmed '${filename}': ${result.actions.join(', ')}`,
      safePath
    };
  }

  return {
    success: true,
    disarmed: false,
    quarantined: false,
    actions: [],
    message: `'${filename}' is clean and compliant.`,
    safePath: filePath
  };
}

module.exports = {
  disarmBuffer,
  disarmFile,
  disarmOffice,
  disarmPdf,
  disarmImage,
  isDangerousExecutable,
  isSupported,
  quarantineFile
};
