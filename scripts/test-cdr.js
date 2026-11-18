// Tests for Lefty's Content Disarm and Reconstruction (CDR) Engine

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const cdr = require('../src/cdr');

async function run() {
  console.log('Running CDR Engine tests...\n');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lefty-cdr-test-'));

  try {
    // 1. PDF Disarming Test
    const maliciousPdf = Buffer.from(
      '%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert("exploit")) >> >>\nendobj\n2 0 obj\n<< /Type /Action /S /Launch /F (calc.exe) >>\nendobj\n%%EOF\nEVIL_POLYGLOT_PAYLOAD_HERE_1234567890'
    );
    const pdfRes = cdr.disarmPdf(maliciousPdf);
    assert.strictEqual(pdfRes.disarmed, true);
    assert.strictEqual(pdfRes.actions.length >= 2, true);
    const safePdfStr = pdfRes.safe.toString('latin1');
    assert.strictEqual(safePdfStr.includes('/JavaScript'), false);
    assert.strictEqual(safePdfStr.includes('/Launch'), false);
    assert.strictEqual(safePdfStr.includes('EVIL_POLYGLOT'), false);
    assert.strictEqual(safePdfStr.includes('/X-Disarmed-JS'), true);
    assert.strictEqual(safePdfStr.includes('/X-Disarmed-Launch'), true);
    console.log('ok   PDF disarmed: JavaScript, Launch actions, and polyglots stripped');

    // 2. Office Document (DOCX/DOCM) Disarming Test
    // Construct a mock DOCM zip buffer with a vbaProject.bin macro and [Content_Types].xml
    const zlib = require('zlib');
    function crc32(buf) {
      let c = 0 ^ (-1);
      for (let i = 0; i < buf.length; i++) {
        let b = (c ^ buf[i]) & 0xFF;
        for (let k = 0; k < 8; k++) b = ((b & 1) ? (0xEDB88320 ^ (b >>> 1)) : (b >>> 1));
        c = (c >>> 8) ^ b;
      }
      return (c ^ (-1)) >>> 0;
    }
    function makeZip(entries) {
      const local = [];
      const cd = [];
      let offset = 0;
      for (const e of entries) {
        const nameBuf = Buffer.from(e.name, 'utf8');
        const dataBuf = Buffer.from(e.data);
        const comp = zlib.deflateRawSync(dataBuf);
        const crc = crc32(dataBuf);

        const lh = Buffer.alloc(30 + nameBuf.length);
        lh.writeUInt32LE(0x04034b50, 0);
        lh.writeUInt16LE(20, 4);
        lh.writeUInt16LE(8, 8);
        lh.writeUInt32LE(crc, 14);
        lh.writeUInt32LE(comp.length, 18);
        lh.writeUInt32LE(dataBuf.length, 22);
        lh.writeUInt16LE(nameBuf.length, 26);
        nameBuf.copy(lh, 30);
        local.push(lh, comp);

        const cdh = Buffer.alloc(46 + nameBuf.length);
        cdh.writeUInt32LE(0x02014b50, 0);
        cdh.writeUInt16LE(20, 4);
        cdh.writeUInt16LE(20, 6);
        cdh.writeUInt16LE(8, 10);
        cdh.writeUInt32LE(crc, 16);
        cdh.writeUInt32LE(comp.length, 20);
        cdh.writeUInt32LE(dataBuf.length, 24);
        cdh.writeUInt16LE(nameBuf.length, 28);
        cdh.writeUInt32LE(offset, 42);
        nameBuf.copy(cdh, 46);
        cd.push(cdh);

        offset += lh.length + comp.length;
      }
      const cdBuf = Buffer.concat(cd);
      const eocd = Buffer.alloc(22);
      eocd.writeUInt32LE(0x06054b50, 0);
      eocd.writeUInt16LE(entries.length, 8);
      eocd.writeUInt16LE(entries.length, 10);
      eocd.writeUInt32LE(cdBuf.length, 12);
      eocd.writeUInt32LE(offset, 16);
      return Buffer.concat([...local, cdBuf, eocd]);
    }

    const mockDocm = makeZip([
      { name: '[Content_Types].xml', data: '<Types><Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/></Types>' },
      { name: 'word/document.xml', data: '<w:document><w:body><w:p><w:r><w:t>Quarterly Report</w:t></w:r></w:p></w:body></w:document>' },
      { name: 'word/vbaProject.bin', data: 'VBA_MACRO_SHELLCODE_BINARY_DATA' }
    ]);

    const officeRes = cdr.disarmOffice(mockDocm);
    assert.strictEqual(officeRes.disarmed, true);
    assert.strictEqual(officeRes.actions.some(a => a.includes('vbaProject.bin')), true);
    assert.strictEqual(officeRes.actions.some(a => a.includes('macro')), true);

    // Re-verify disarmed office file contents
    const cleanOfficeRes = cdr.disarmOffice(officeRes.safe);
    assert.strictEqual(cleanOfficeRes.disarmed, false); // should be completely clean now
    console.log('ok   Office XML disarmed: VBA project purged and macro content-types sanitized');

    // 3. Image Polyglot Disarming Test (PNG)
    // Create a valid PNG header + IHDR + IEND + appended payload
    const pngHeader = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    const iendChunk = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]);
    const maliciousPayload = Buffer.from('HIDDEN_EXECUTABLE_OR_PHP_SHELL_PAYLOAD');
    const dirtyPng = Buffer.concat([pngHeader, iendChunk, maliciousPayload]);

    const imgRes = cdr.disarmImage(dirtyPng, '.png');
    assert.strictEqual(imgRes.disarmed, true);
    assert.strictEqual(imgRes.safe.length, pngHeader.length + iendChunk.length);
    assert.strictEqual(imgRes.safe.indexOf(maliciousPayload), -1);
    console.log('ok   PNG disarmed: appended polyglot overlay cleanly trimmed');

    // 4. Executable Quarantine Test
    const testExe = path.join(tmpDir, 'malicious_installer.exe');
    fs.writeFileSync(testExe, 'MZ_DUMMY_BINARY_DATA');
    const qRes = await cdr.disarmFile(testExe, { quarantineDir: path.join(tmpDir, 'quarantine') });
    assert.strictEqual(qRes.quarantined, true);
    assert.strictEqual(fs.existsSync(testExe), false); // original moved
    assert.strictEqual(fs.existsSync(qRes.safePath), true); // notice created
    console.log('ok   Executable quarantine: malicious binary isolated and replaced with notice');

    // 5. Clean File Passthrough
    const cleanTxt = path.join(tmpDir, 'report.pdf');
    fs.writeFileSync(cleanTxt, '%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n');
    const cleanRes = await cdr.disarmFile(cleanTxt);
    assert.strictEqual(cleanRes.disarmed, false);
    assert.strictEqual(cleanRes.quarantined, false);
    console.log('ok   Clean document verified without unnecessary modifications');

    console.log('\nAll CDR Engine checks passed.');
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
}

run().catch((err) => {
  console.error('CDR Engine test failed:', err);
  process.exit(1);
});
