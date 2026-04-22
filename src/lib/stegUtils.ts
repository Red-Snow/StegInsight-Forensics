/**
 * Developed by Farman Khan (Red-Snow)
 * GitHub: https://github.com/Red-Snow
 */

import { AnalysisResult, Finding } from '../types';

export const PNG_FOOTER = [0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]; 
export const JPEG_FOOTER = [0xFF, 0xD9];
export const MP4_MOOV = [0x6d, 0x6f, 0x6f, 0x76]; // 'moov'

export function formatSize(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

export async function analyzeFile(file: File): Promise<AnalysisResult> {
  const arrayBuffer = await file.arrayBuffer();
  const bytes = new Uint8Array(arrayBuffer);
  const findings: Finding[] = [];
  let likelihood = 0;

  // Calculate base entropy
  const entropyData = calculateEntropyMetadata(bytes);
  const entropy = entropyData.entropy;
  
  // New: Sliding window entropy for detecting localized hidden data
  const slidingEntropyData = calculateSlidingEntropy(bytes);

  // 1. Structural Analysis (Checking for trailing data)
  if (file.type.startsWith('image/')) {
    likelihood += checkImageTrailingData(bytes, file.type, findings);
  }

  // 1.5 Signature Analysis for Steganography Tools
  likelihood += checkSignatureMarkers(bytes, file.type.toLowerCase(), findings);

  // 2. Format Specific Deep Scan
  if (file.type.startsWith('image/')) {
    likelihood += analyzeImageAdvanced(bytes, file.type, findings);
  } else if (file.type.startsWith('video/')) {
    likelihood += analyzeVideoAdvanced(bytes, findings);
  } else if (file.type.startsWith('audio/')) {
    likelihood += analyzeAudioAdvanced(bytes, findings);
  } else if (file.type === 'application/pdf') {
    likelihood += analyzePdfAdvanced(bytes, findings);
  } else if (file.type === 'text/plain' || file.name.endsWith('.txt')) {
    likelihood += analyzeTextAdvanced(new TextDecoder().decode(bytes), findings);
  }

  // 3. Statistical Analysis (Chi-Squared Test for LSB)
  const chiStat = performChiSquared(bytes);
  
  // High variance (Chi-Square > 6) means structure exists in LSBs indicating standard Steg techniques.
  // Low variance (Chi-Square < 0.5) implies mathematical whitening, often used in Steghide.
  // Video and Audio naturally have random LSBs so we'll only severely penalize text/image,
  // OR severe uniformity.
  const isVideoOrAudio = file.type.startsWith('video/') || file.type.startsWith('audio/');
  if (chiStat < 0.2) { 
    findings.push({
      type: 'critical',
      message: 'Unnatural LSB Uniformity (Cryptographic Masking)',
      details: `Bit distribution is mathematically perfectly balanced (Chi-Stat=${chiStat.toFixed(3)}). This perfect parity strongly indicates encrypted payload injection (e.g., OpenPuff).`
    });
    likelihood += 45;
  } else if (!isVideoOrAudio && chiStat > 6.63) {
    findings.push({
      type: 'warning',
      message: 'High-confidence statistical bias',
      details: `LSB terminal distribution deviates significantly from natural noise (Chi-Stat=${chiStat.toFixed(2)}).`
    });
    likelihood += 30;
  }
  
  // 3.5 DeepSound / Audio Specific Signature Checks
  if (file.name.toLowerCase().endsWith('.wav') || file.type.includes('wav')) {
      const deepSoundScore = checkDeepSoundSignature(bytes, findings);
      likelihood += deepSoundScore;
  }
  
  // 4. Steghide Heuristics
  const isSteghideFormat = ['image/jpeg', 'image/bmp', 'audio/wav', 'audio/x-wav'].includes(file.type.toLowerCase()) || file.name.endsWith('.au');
  if (isSteghideFormat && entropy > 7.9) {
      if (chiStat < 2.0) { // High randomness (unbiased) characteristic of Graph-Theoretic masking
          findings.push({
            type: 'critical',
            message: 'Steghide Graph-Theoretic Masking',
            details: `High payload density (H>7.9) with surprisingly normal first-order statistics (p<0.1) in a supported carrier strongly indicates Steghide usage. RECOMMENDED ACTION: Attempt cracking with 'stegseek' or 'steghide --extract'.`
          });
          likelihood += 65;
      } else {
          findings.push({
            type: 'warning',
            message: 'Possible Steghide Target',
            details: `Format and density align with Steghide profiles, though statistical preservation is imperfect. RECOMMENDED ACTION: Verify with 'stegseek' dictionary attack.`
          });
          likelihood += 30;
      }
  }

  likelihood = Math.min(100, Math.max(0, likelihood));

  return {
    fileType: file.type || 'unknown',
    fileSize: file.size,
    fileName: file.name,
    likelihood,
    findings,
    metadata: {
      entropy: entropy.toFixed(4),
      chiSquared: chiStat.toFixed(4),
      byteDistribution: entropyData.byteDistribution,
      slidingEntropy: slidingEntropyData
    },
    suggestions: generateRecommendations(file.type || 'unknown', likelihood, findings, entropy)
  };
}

function generateRecommendations(mimeType: string, likelihood: number, findings: Finding[], entropy: number): string[] {
  const suggestions: string[] = [];
  const lowerMime = mimeType.toLowerCase();
  
  const hasTrailing = findings.some(f => f.message.toLowerCase().includes('trailing') || f.message.toLowerCase().includes('appended'));
  const isOpenPuff = findings.some(f => f.message.toLowerCase().includes('openpuff') || f.message.toLowerCase().includes('padding') || f.message.toLowerCase().includes('uniformity'));
  const isSteghide = findings.some(f => f.message.toLowerCase().includes('steghide'));
  const isLsb = findings.some(f => f.message.toLowerCase().includes('lsb'));
  const isDeepSound = findings.some(f => f.message.toLowerCase().includes('deepsound'));

  if (likelihood < 20) {
    suggestions.push("File structure and statistics appear nominal. No immediate forensic action required.");
    if (entropy > 7.9 && (lowerMime.includes('video') || lowerMime.includes('audio'))) {
       suggestions.push("Note: The high byte entropy observed is mathematically consistent with natural media compression (e.g. standard H.264/AAC wrappers).");
    }
    if (lowerMime.includes('image')) {
       suggestions.push("Visual bit-plane inspection is recommended as a final manual verification step.");
    }
  } else {
    // Infiltrated or Suspicious tailored suggestions
    if (isOpenPuff) {
       suggestions.push("Cryptographic packaging detected (e.g., OpenPuff). Extraction requires the original encryption keys or brute-force attempts on the carrier structure.");
    }
    if (hasTrailing) {
       suggestions.push("Appended payload identified. Recommended action: Use 'binwalk -e <filename>' or 'foremost -i <filename>' in a Linux forensics environment to automatically strip and extract the trailing bytes.");
    }
    if (isSteghide) {
       suggestions.push("Steghide graph-theoretic masking suspected. Recommended action: Run 'stegseek <filename> wordlist.txt' to attempt rapid dictionary cracking.");
    }
    if (isLsb && lowerMime.includes('image')) {
       suggestions.push("Review the visual Bit-Plane Analyzer map for localized snowy patterns, which usually map the physical dimensions of the concealed hidden data.");
    }
    if (isDeepSound || lowerMime.includes('audio')) {
       suggestions.push("If DeepSound or silent bit-stream injection is suspected in the audio carrier, process the file with the native DeepSound application to scan for password-protected secrets.");
    }
    
    // Add a generic fallback if we didn't add specific tool ones but likelihood is high
    if (suggestions.length === 0) {
       suggestions.push("Anomalies detected. Subject the file to advanced forensic sandboxing to safely isolate embedded structures.");
    }
  }
  
  return suggestions;
}

// MP4 Structural Steganography Scanner (e.g. OpenPuff)
function analyzeMP4StructuralAnomalies(bytes: Uint8Array, findings: Finding[]): number {
  let score = 0;
  let offset = 0;
  
  while (offset < bytes.length && bytes[offset] === 0) offset++;

  try {
    const decoder = new TextDecoder();
    while (offset + 8 <= bytes.length) {
      // Correctly compute 32-bit Unsigned Integer (JavaScript bitwise converts >= 2GB to negative)
      let size = (bytes[offset] * 16777216) + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3];
      const type = decoder.decode(bytes.slice(offset + 4, offset + 8));

      // MP4 boxes use printable ASCII. If it hits encrypted payload or garbage headers, it breaks
      if (!/^[\x20-\x7E]{4}$/.test(type)) {
         break;
      }

      let headerSize = 8;
      if (size === 1) { 
        if (offset + 16 > bytes.length) break;
        let bigSize = 0n;
        for (let i = 0; i < 8; i++) {
          bigSize = (bigSize << 8n) | BigInt(bytes[offset + 8 + i]);
        }
        size = Number(bigSize);
        headerSize = 16;
      } else if (size === 0) {
        size = bytes.length - offset;
      }

      if (size < headerSize) break;
      const payloadSize = size - headerSize;
      
      // Target OpenPuff specific vectors:
      // Scrutinize ALL atoms except the massive native media data stream ('mdat')
      if (type !== 'mdat' && payloadSize > 256) {
          const sampleSize = Math.min(payloadSize, 512 * 1024);
          const payloadSample = bytes.slice(offset + headerSize, offset + headerSize + sampleSize);
          const atomEntropy = calculateEntropy(payloadSample);
          
          if (atomEntropy > 7.95) {
             findings.push({
               type: 'critical',
               message: `Encrypted Payload in '${type}' box`,
               details: `Atom '${type}' contains mathematically whitened data (H=${atomEntropy.toFixed(4)}). Natural metadata boxes never reach theoretical maximum entropy.`
             });
             score += 85;
          } else if ((type === 'free' || type === 'skip' || type === 'junk') && atomEntropy > 6.0) {
             findings.push({
               type: 'critical',
               message: `Malicious Padding Injection ('${type}' box)`,
               details: `Found a padding atom containing highly randomized data (H=${atomEntropy.toFixed(4)}). Standard filler boxes consist of 0x00 bytes.`
             });
             score += 75;
          }
      }

      offset += size;
      if (offset < 0) break; // Infinite loop safety
    }
    
    // Handle Appended Cryptographic Data 
    if (offset > 0 && offset < bytes.length - 16) {
       const tail = bytes.slice(offset);
       const tailEntropy = calculateEntropy(tail);
       if (tailEntropy > 7.8) {
          findings.push({
            type: 'critical',
            message: `Appended Cryptographic Payload (${formatSize(tail.length)})`,
            details: `Found highly dense out-of-bounds data appended past the MP4 logical EOF (H=${tailEntropy.toFixed(4)}).`
          });
          score += 85;
       }
    }
  } catch (e) {
    // Graceful exit for corrupted offsets
  }
  
  return score;
}

function analyzeVideoAdvanced(bytes: Uint8Array, findings: Finding[]): number {
  let score = 0;
  
  // Specific check for OpenPuff MP4 architectural injections
  score += analyzeMP4StructuralAnomalies(bytes, findings);
  
  return score;
}

function checkImageTrailingData(bytes: Uint8Array, mimeType: string, findings: Finding[]): number {
  let score = 0;
  let footerPos = -1;
  let footerLen = 0;

  if (mimeType.includes('png')) {
    footerPos = findSequence(bytes, PNG_FOOTER);
    footerLen = 8;
  } else if (mimeType.includes('jpeg') || mimeType.includes('jpg')) {
    footerPos = findLastSequence(bytes, JPEG_FOOTER);
    footerLen = 2;
  }
  
  if (footerPos !== -1 && (footerPos + footerLen) < bytes.length - 16) {
    const extra = bytes.length - (footerPos + footerLen);
    findings.push({
      type: 'critical',
      message: `Carrier anomaly: ${formatSize(extra)} trailing bytes detected`,
      details: `Data was found after the expected end-of-file marker at offset 0x${(footerPos + footerLen).toString(16)}. RECOMMENDED ACTION: Extract using 'binwalk -e' or 'foremost'.`
    });
    score += 50;
  }
  return score;
}

function checkSignatureMarkers(bytes: Uint8Array, mimeType: string, findings: Finding[]): number {
  let score = 0;
  const decoder = new TextDecoder('ascii');
  // Sample first and last 100KB for signatures
  const headSample = decoder.decode(bytes.slice(0, Math.min(bytes.length, 100000)));
  const tailSample = decoder.decode(bytes.slice(Math.max(0, bytes.length - 100000)));
  const combined = (headSample + tailSample).toLowerCase();

  const signatures: [string, string][] = [
    ['outguess', 'OutGuess LSB Detection (Heuristic)'],
    ['jphide', 'JPHide Marker/Header'],
    ['camouflage', 'Camouflage Append Sequence'],
    ['wbstego', 'wbStego Embedding Marker'],
    ['hide4pgp', 'Hide4PGP Signature'],
    ['deegger', 'DeEgger Embedded Payload'],
    ['openpuff', 'OpenPuff Multi-Crypto Steg']
  ];

  for (const [sig, name] of signatures) {
    if (combined.includes(sig)) {
      findings.push({
        type: 'critical',
        message: `Detected ${name} signature`,
        details: `Literal string match for the '${sig}' steganography tool was found in the data stream.`
      });
      score += 80;
    }
  }

  // F5 detection
  // Advanced check for F5 would look at coefficient skipping, but we can look for specific F5 password salt markers
  if (mimeType.includes('jpeg') && combined.includes('f5stego')) {
      findings.push({
          type: 'critical',
          message: 'F5 Algorithm Signature',
          details: 'Matrix encoding marker suggesting F5 jpeg steganography.'
      });
      score += 80;
  }
  
  return score;
}

function analyzeImageAdvanced(bytes: Uint8Array, mimeType: string, findings: Finding[]): number {
  let score = 0;
  const entropy = calculateEntropy(bytes);
  if (entropy > 7.95) {
    findings.push({
      type: 'warning',
      message: 'Near-maximum entropy',
      details: 'High entropy across the entire byte range is a strong indicator of encrypted steganography.'
    });
    score += 20;
  }
  return score;
}


function analyzeAudioAdvanced(bytes: Uint8Array, findings: Finding[]): number {
  let score = 0;
  
  // WAV Specific Analysis
  const decoder = new TextDecoder('ascii');
  const header = decoder.decode(bytes.slice(0, 12));
  if (header.includes('RIFF') && header.includes('WAVE')) {
      // Check for suspicious LSB patterns in WAV samples
      // We look at the data chunk
      const dataOffset = findSequence(bytes, [0x64, 0x61, 0x74, 0x61]); // "data"
      if (dataOffset !== -1) {
          const dataSize = bytes[dataOffset+4] | (bytes[dataOffset+5] << 8) | (bytes[dataOffset+6] << 16) | (bytes[dataOffset+7] << 24);
          const sampleData = bytes.slice(dataOffset + 8, dataOffset + 8 + Math.min(dataSize, 20000));
          
          // Perform Chi-Squared on the sample LSBs
          const lsbBytes = new Uint8Array(sampleData.length);
          for(let i=0; i<sampleData.length; i++) lsbBytes[i] = sampleData[i] & 1;
          
          const chiSq = performChiSquared(lsbBytes);
          if (chiSq > 0.1) {
              findings.push({
                  type: 'warning',
                  message: 'Audio Bitstream Anomaly',
                  details: `Statistical variance in PCM LSB planes (p=${chiSq.toFixed(4)}) indicates potential payload infusion.`
              });
              score += 30;
          }
      }
  }
  
  return score;
}

function checkDeepSoundSignature(bytes: Uint8Array, findings: Finding[]): number {
    let score = 0;
    const decoder = new TextDecoder('ascii');
    const fullText = decoder.decode(bytes.slice(0, Math.min(bytes.length, 100000))); // Scan first 100KB for text
    
    if (fullText.includes('DeepSound') || fullText.includes('DEEPSOUND')) {
        findings.push({
            type: 'critical',
            message: 'DeepSound Infrastructure Detected',
            details: 'The file contains a clear DeepSound signature. This tool is widely used to hide encrypted files within audio carriers.'
        });
        score += 80;
    }
    
    // DeepSound often appends an encrypted volume at the end of the file
    // Check for high entropy "chunks" at the end of WAV
    const tail = bytes.slice(-10000);
    const tailEntropy = calculateEntropy(tail);
    if (tailEntropy > 7.95) {
        findings.push({
            type: 'critical',
            message: 'High Entropy Audio Trailer',
            details: `Found high-randomness bytes (H=${tailEntropy.toFixed(4)}) appended to audio trailer, consistent with DeepSound encrypted volume infusion.`
        });
        score += 60;
    }

    return score;
}

function calculateSlidingEntropy(bytes: Uint8Array, windowSize: number = 1024, step: number = 512): {offset: number, entropy: number}[] {
    const results = [];
    for (let i = 0; i <= bytes.length - windowSize; i += step) {
        const window = bytes.slice(i, i + windowSize);
        results.push({
            offset: i,
            entropy: calculateEntropy(window)
        });
    }
    return results;
}

function analyzePdfAdvanced(bytes: Uint8Array, findings: Finding[]): number {
  let score = 0;
  const decoder = new TextDecoder('ascii');
  const text = decoder.decode(bytes);
  
  // Check for suspicious PDF tags indicating hidden JS or Actions
  const jsMatch = text.match(/\/JS|\/JavaScript/gi);
  if (jsMatch && jsMatch.length > 0) {
     findings.push({
         type: 'warning',
         message: 'Embedded JavaScript Identified',
         details: `Found ${jsMatch.length} instances of embedded JS. This is often used for malicious execution or hiding data payloads.`
     });
     score += 30;
  }

  const eofMatches = [...text.matchAll(/%%EOF/g)];
  if (eofMatches.length > 1) {
     findings.push({
         type: 'critical',
         message: 'Multiple %%EOF Markers Detected',
         details: 'Incremental updates or appended malicious data detected after the primary EOF.'
     });
     score += 50;
  }

  if (text.includes('/OpenAction')) {
     findings.push({
         type: 'warning',
         message: '/OpenAction Directive Found',
         details: 'An OpenAction directive executes automatically when the PDF is opened.'
     });
     score += 20;
  }

  const objStmMatch = text.match(/\/ObjStm/gi);
  if (objStmMatch && objStmMatch.length > 0) {
     findings.push({
         type: 'info',
         message: 'Object Streams Detected',
         details: `Found ${objStmMatch.length} /ObjStm marker(s). While valid, attackers use these to compress and hide malicious elements from standard scanners.`
     });
     score += 10;
  }

  const embeddedMatch = text.match(/\/EmbeddedFiles/gi);
  if (embeddedMatch && embeddedMatch.length > 0) {
     findings.push({
         type: 'warning',
         message: 'Embedded Files Sub-Dictionaries Found',
         details: 'The PDF structural dictionary contains embedded files. This technique (Polyglot attachments) is highly utilized to conceal extracted payloads.'
     });
     score += 25;
  }

  const xrefMatches = [...text.matchAll(/xref\b/gi)];
  if (xrefMatches.length > 1) {
     findings.push({
         type: 'critical',
         message: 'Redundant XRef Tables',
         details: 'Found overlapping or incremental Cross-Reference (XRef) tables. Suspicious appended data stream likely resides outside the initial boundaries.'
     });
     score += 35;
  }
  
  return score;
}

function analyzeTextAdvanced(text: string, findings: Finding[]): number {
  let score = 0;
  const zwRegex = /[\u200B-\u200D\uFEFF]/g;
  const zwMatches = text.match(zwRegex);
  if (zwMatches && zwMatches.length > 5) {
    findings.push({
      type: 'critical',
      message: `Neural-Inconsistent data: ${zwMatches.length} ZWJs found`,
      details: 'These invisible characters are almost certainly encoding binary data.'
    });
    score += 40;
  }
  return score;
}

function performChiSquared(bytes: Uint8Array): number {
  const freqs = [0, 0];
  
  for (let i = 0; i < bytes.length; i++) {
    freqs[bytes[i] & 1]++;
  }
  const expected = bytes.length / 2;
  if (expected === 0) return 0;
  
  const chiSq = (Math.pow(freqs[0] - expected, 2) / expected) + (Math.pow(freqs[1] - expected, 2) / expected);
  return chiSq;
}

export function extractPayload(bytes: Uint8Array, mimeType: string): Uint8Array | null {
  let footerPos = -1;
  let footerLen = 0;

  if (mimeType.includes('png')) {
    footerPos = findSequence(bytes, PNG_FOOTER);
    footerLen = 8;
  } else if (mimeType.includes('jpeg') || mimeType.includes('jpg')) {
    footerPos = findLastSequence(bytes, JPEG_FOOTER);
    footerLen = 2;
  } else if (mimeType.includes('mp4') || mimeType.includes('video/quicktime')) {
    // Implement structural extraction based on our MP4 analyzer
    let offset = 0;
    while (offset < bytes.length && bytes[offset] === 0) offset++;
    try {
      const decoder = new TextDecoder();
      while (offset + 8 <= bytes.length) {
        let size = (bytes[offset] * 16777216) + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3];
        const type = decoder.decode(bytes.slice(offset + 4, offset + 8));

        if (!/^[\x20-\x7E]{4}$/.test(type)) break;

        let headerSize = 8;
        if (size === 1) { 
          if (offset + 16 > bytes.length) break;
          let bigSize = 0n;
          for (let i = 0; i < 8; i++) {
            bigSize = (bigSize << 8n) | BigInt(bytes[offset + 8 + i]);
          }
          size = Number(bigSize);
          headerSize = 16;
        } else if (size === 0) {
          size = bytes.length - offset;
        }

        if (size < headerSize) break;
        const payloadSize = size - headerSize;

        // If we found malicious padding/boxes via high entropy
        if (type !== 'mdat' && payloadSize > 256) {
           const atomSample = bytes.slice(offset + headerSize, offset + headerSize + Math.min(payloadSize, 512 * 1024));
           const atomEntropy = calculateEntropy(atomSample);
           if (atomEntropy > 7.5 || ((type === 'free' || type === 'skip' || type === 'junk') && atomEntropy > 6.0)) {
               // Extract this box's raw contents
               return bytes.slice(offset + headerSize, offset + size);
           }
        }

        offset += size;
        if (offset < 0) break;
      }
      
      // If we cleanly broke out but there is appended trailing payload data
      if (offset > 0 && offset < bytes.length - 16) {
         return bytes.slice(offset);
      }
    } catch(e) {}
  }

  if (footerPos !== -1 && (footerPos + footerLen) < bytes.length) {
    return bytes.slice(footerPos + footerLen);
  }
  
  // Signature-based extraction
  const signatures = [
    { sig: [0x5B, 0x4F, 0x75, 0x74, 0x47, 0x75, 0x65, 0x73, 0x73, 0x5D], name: 'OutGuess' }, // [OutGuess]
    { sig: [0x4A, 0x50, 0x48, 0x49, 0x44, 0x45], name: 'JPHide' }, // JPHIDE
    { sig: [0x44, 0x65, 0x65, 0x70, 0x53, 0x6f, 0x75, 0x6e, 0x64], name: 'DeepSound' } // DeepSound
  ];

  for (const item of signatures) {
    const pos = findSequence(bytes, item.sig);
    if (pos !== -1) {
      // Return everything from the signature onwards as potential payload for forensic processing
      return bytes.slice(pos);
    }
  }
  
  // If no explicit footer found but likelihood was high, check for high-entropy tails
  if (calculateEntropy(bytes.slice(-2048)) > 7.9) {
      return bytes.slice(-2048);
  }

  return null;
}

function findSequence(bytes: Uint8Array, sequence: number[]): number {
  for (let i = 0; i <= bytes.length - sequence.length; i++) {
    let match = true;
    for (let j = 0; j < sequence.length; j++) {
      if (bytes[i + j] !== sequence[j]) {
        match = false;
        break;
      }
    }
    if (match) return i;
  }
  return -1;
}

function findLastSequence(bytes: Uint8Array, sequence: number[]): number {
  for (let i = bytes.length - sequence.length; i >= 0; i--) {
    let match = true;
    for (let j = 0; j < sequence.length; j++) {
      if (bytes[i + j] !== sequence[j]) {
        match = false;
        break;
      }
    }
    if (match) return i;
  }
  return -1;
}

export function calculateEntropyMetadata(bytes: Uint8Array): { entropy: number, byteDistribution: { byte: number, count: number }[] } {
  const freqs = new Array(256).fill(0);
  for (const b of bytes) freqs[b]++;
  let entropy = 0;
  const distribution: {byte: number, count: number}[] = [];
  
  for (let b = 0; b < freqs.length; b++) {
    const f = freqs[b];
    distribution.push({ byte: b, count: f });
    if (f > 0) {
      const p = f / bytes.length;
      entropy -= p * Math.log2(p);
    }
  }
  return { entropy, byteDistribution: distribution };
}

function calculateEntropy(bytes: Uint8Array): number {
  return calculateEntropyMetadata(bytes).entropy;
}

export function generateLsbPlane(imgData: ImageData, plane: number): string {
  const canvas = document.createElement('canvas');
  canvas.width = imgData.width;
  canvas.height = imgData.height;
  const ctx = canvas.getContext('2d');
  if (!ctx) return '';
  const newImgData = ctx.createImageData(imgData.width, imgData.height);
  for (let i = 0; i < imgData.data.length; i += 4) {
    const r = (imgData.data[i] >> plane) & 1;
    const g = (imgData.data[i+1] >> plane) & 1;
    const b = (imgData.data[i+2] >> plane) & 1;
    const val = (r || g || b) ? 255 : 0;
    newImgData.data[i] = val;
    newImgData.data[i+1] = val;
    newImgData.data[i+2] = val;
    newImgData.data[i+3] = 255;
  }
  ctx.putImageData(newImgData, 0, 0);
  return canvas.toDataURL();
}

export async function generateAudioSpectrogram(file: File): Promise<string | null> {
  // Web Audio API is required for this
  try {
    const arrayBuffer = await file.arrayBuffer();
    const ctx = new window.OfflineAudioContext(1, 44100 * 2, 44100); // 2 seconds of audio
    const audioBuffer = await ctx.decodeAudioData(arrayBuffer);
    
    // We'll create a simple waveform visualizer instead of full FFT to save memory and processing
    const channelData = audioBuffer.getChannelData(0);
    const canvas = document.createElement('canvas');
    canvas.width = 600;
    canvas.height = 200;
    const canvasCtx = canvas.getContext('2d');
    if (!canvasCtx) return null;

    canvasCtx.fillStyle = '#000000';
    canvasCtx.fillRect(0, 0, canvas.width, canvas.height);
    
    canvasCtx.lineWidth = 1;
    canvasCtx.strokeStyle = '#00f2ff'; // brand-accent
    canvasCtx.beginPath();
    
    const sliceWidth = canvas.width * 1.0 / channelData.length;
    let x = 0;
    
    // Decimate for drawing speed
    const step = Math.ceil(channelData.length / canvas.width);
    
    for(let i = 0; i < canvas.width; i++) {
        const idx = i * step;
        if(idx >= channelData.length) break;
        const v = channelData[idx] * 0.5 + 0.5; // normalize 0-1
        const y = v * canvas.height;
        
        if(i === 0) {
            canvasCtx.moveTo(x, y);
        } else {
            canvasCtx.lineTo(x, y);
        }
        x += sliceWidth * step;
    }
    
    canvasCtx.stroke();
    return canvas.toDataURL();
  } catch (e) {
    console.error("Audio generation failed:", e);
    return null;
  }
}

export async function extractVideoFrame(file: File): Promise<ImageData | null> {
  return new Promise((resolve) => {
    const video = document.createElement('video');
    video.src = URL.createObjectURL(file);
    video.muted = true;
    video.currentTime = 1; // get frame at 1 sec
    
    video.onseeked = () => {
      const canvas = document.createElement('canvas');
      canvas.width = video.videoWidth || 320;
      canvas.height = video.videoHeight || 240;
      const ctx = canvas.getContext('2d');
      if (ctx) {
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        URL.revokeObjectURL(video.src);
        resolve(imgData);
      } else {
        URL.revokeObjectURL(video.src);
        resolve(null);
      }
    };
    
    video.onerror = () => {
        URL.revokeObjectURL(video.src);
        resolve(null);
    }
  });
}
export function generateHeatmap(imgData: ImageData): string {
  const canvas = document.createElement('canvas');
  canvas.width = imgData.width;
  canvas.height = imgData.height;
  const ctx = canvas.getContext('2d');
  if (!ctx) return '';
  const newImgData = ctx.createImageData(imgData.width, imgData.height);
  
  // A heatmap highlighting pixels where LSB is 1 across any channel
  // Uses a gradient from dark blue to bright cyan
  for (let i = 0; i < imgData.data.length; i += 4) {
    const lsbCount = (imgData.data[i] & 1) + (imgData.data[i+1] & 1) + (imgData.data[i+2] & 1);
    const intensity = (lsbCount / 3) * 255;
    
    newImgData.data[i] = 0; // Blue/Cyan theme
    newImgData.data[i+1] = intensity;
    newImgData.data[i+2] = intensity;
    newImgData.data[i+3] = intensity > 0 ? 255 : 50; // Semi-transparent for low intensity
  }
  ctx.putImageData(newImgData, 0, 0);
  return canvas.toDataURL();
}

export async function generateRawLsbVisual(file: File): Promise<string | null> {
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  
  // Make a grid to represent the LSBs in a 2D map
  const size = Math.ceil(Math.sqrt(Math.min(bytes.length, 65536))); // Render up to 64x64 grid to prevent crash
  const canvas = document.createElement('canvas');
  canvas.width = size || 100;
  canvas.height = size || 100;
  const ctx = canvas.getContext('2d');
  if (!ctx) return null;

  const imgData = ctx.createImageData(canvas.width, canvas.height);
  const data = imgData.data;

  // Extract Bit 0 mapping over the byte stream
  for (let i = 0; i < Math.min(bytes.length, canvas.width * canvas.height); i++) {
    const lsb = bytes[i] & 1;
    const intensity = lsb === 1 ? 255 : 0;
    const idx = i * 4;
    data[idx] = intensity;     // R
    data[idx + 1] = intensity; // G
    data[idx + 2] = intensity; // B
    data[idx + 3] = 255;       // Alpha
  }

  ctx.putImageData(imgData, 0, 0);
  
  // Upscale to make it visibly pixelated without browser smoothing
  const upscaleCanvas = document.createElement('canvas');
  upscaleCanvas.width = 300;
  upscaleCanvas.height = 300;
  const upCtx = upscaleCanvas.getContext('2d');
  if (upCtx) {
     upCtx.imageSmoothingEnabled = false;
     upCtx.drawImage(canvas, 0, 0, upscaleCanvas.width, upscaleCanvas.height);
     return upscaleCanvas.toDataURL('image/png');
  }
  return canvas.toDataURL('image/png');
}
