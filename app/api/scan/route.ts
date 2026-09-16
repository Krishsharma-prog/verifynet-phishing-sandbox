import { NextResponse } from 'next/server';
import { GoogleGenerativeAI } from '@google/generative-ai';
import puppeteer from 'puppeteer';
import AdmZip from 'adm-zip';
import dns from 'dns/promises';
import tls from 'tls';
import pLimit from 'p-limit';

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || '');
const FALLBACK_MODELS = ['gemini-3.5-flash', 'gemini-3.5-flash-lite', 'gemini-3.8-flash'];

// Restrict concurrent browser instances to safeguard server memory and CPU
const browserLimiter = pLimit(2);

// ==========================================
// 1. SSRF SHIELD & URL SANITIZATION
// ==========================================
function isPrivateOrReservedIP(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => isNaN(n) || n < 0 || n > 255)) return true;
  
  const [a, b] = parts;
  return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || 
         (a === 192 && b === 168) || (a === 169 && b === 254) || a === 0;
}

async function getHardenedTarget(rawUrl: string) {
  const parsed = new URL(rawUrl);
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Unsupported protocol: Only HTTP/HTTPS allowed.');
  }
  
  // Resolve host via OS network stack to respect local firewalls and proxies
  const lookups = await dns.lookup(parsed.hostname, { all: true, family: 4 }).catch(() => []);
  const ips = lookups.map((item) => item.address);
  
  if (!ips.length) {
    throw new Error('Host resolution failed: The domain is inactive, unregistered, or unreachable.');
  }
  
  for (const ip of ips) {
    if (isPrivateOrReservedIP(ip)) {
      throw new Error(`Access denied: Target resolves to internal or restricted IP range (${ip})`);
    }
  }
  
  return { parsed, ipAddresses: ips };
}

// ==========================================
// 2. SAFE ARCHIVE INSPECTOR (In-Memory & Zip-Bomb Protected)
// ==========================================
async function safeGetZipManifest(targetUrl: string): Promise<string[]> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 6000);
  try {
    const res = await fetch(targetUrl, { 
      signal: controller.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
    });
    
    const size = parseInt(res.headers.get('content-length') || '0', 10);
    if (size > 15 * 1024 * 1024) return ['[BLOCKED]: Archive exceeds 15MB analysis limit'];
    if (!res.body) return ['Empty response body'];

    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let received = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.length;
      if (received > 15 * 1024 * 1024) {
        controller.abort();
        return ['[BLOCKED]: Archive stream exceeded 15MB limit mid-transfer'];
      }
      chunks.push(value);
    }

    const zip = new AdmZip(Buffer.concat(chunks));
    const entries = zip.getEntries();
    
    if (entries.length > 100) return ['[ALERT]: Suspicious archive structure (>100 files)'];
    
    let uncompressed = 0;
    for (const e of entries) {
      uncompressed += e.header.size;
      if (uncompressed > 50 * 1024 * 1024) return ['[ALERT]: Zip Bomb pattern detected (>50MB uncompressed)'];
    }
    return entries.map(e => e.entryName);
  } catch {
    return ['Archive contents unreadable or download aborted'];
  } finally {
    clearTimeout(timeout);
  }
}

// ==========================================
// 3. PASSIVE INFRASTRUCTURE TELEMETRY
// ==========================================
async function getInfrastructureData(hostname: string, ipAddresses: string[]) {
  const mxRecords = await dns.resolveMx(hostname).catch(() => []);
  const sslData: any = await new Promise((resolve) => {
    const socket = tls.connect({ host: hostname, port: 443, servername: hostname, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate(false);
      socket.end();
      if (cert?.valid_from) {
        resolve({
          issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown',
          daysOld: Math.floor((Date.now() - new Date(cert.valid_from).getTime()) / (1000 * 60 * 60 * 24))
        });
      } else {
        resolve(null);
      }
    });
    socket.on('error', () => resolve(null));
    socket.setTimeout(3000, () => { socket.destroy(); resolve(null); });
  });

  return { hostname, ipAddresses, hasMailServers: mxRecords.length > 0, ssl: sslData };
}

// ==========================================
// 4. MAIN PIPELINE EXECUTION
// ==========================================
export async function POST(request: Request) {
  try {
    const { url } = await request.json();
    if (!url) return NextResponse.json({ error: 'URL required' }, { status: 400 });

    // Step A: SSRF Defense & Target Sanitization
    const { parsed, ipAddresses } = await getHardenedTarget(url);
    const cleanPath = parsed.pathname.toLowerCase();
    const isZipUrl = cleanPath.endsWith('.zip');

    // Step B: Telemetry & Archive Inspection
    const [infraData, zipManifest] = await Promise.all([
      getInfrastructureData(parsed.hostname, ipAddresses),
      isZipUrl ? safeGetZipManifest(url) : Promise.resolve([])
    ]);

    // Step C: Fast Lexical Pre-Filter (Tier 1)
    const fastCheckPrompt = `Analyze URL: "${url}". Infra: ${JSON.stringify(infraData)}. Manifest: ${JSON.stringify(zipManifest)}.
    Respond strictly in JSON: {"isObviousScam": boolean, "confidence": "98%", "verdictSummary": "string", "redFlags": ["flag"]}`;
    
    let tier1Result = null;
    for (const model of FALLBACK_MODELS) {
      try {
        const m = genAI.getGenerativeModel({ model, generationConfig: { responseMimeType: 'application/json' } });
        const res = await m.generateContent(fastCheckPrompt);
        tier1Result = JSON.parse(res.response.text());
        break;
      } catch {}
    }

    if (tier1Result?.isObviousScam) {
      return NextResponse.json({
        status: 'SCAM',
        confidence: tier1Result.confidence,
        brandImpersonated: 'Fast Filter Detection',
        verdictSummary: tier1Result.verdictSummary,
        redFlags: tier1Result.redFlags,
        scannedBy: 'Fast Threat Filter',
        screenshot: '',
        zipManifest,
        infrastructure: infraData,
        redirectChain: [],
        domAnalysis: null
      });
    }

    // Step D: Sandboxed Browser Execution (Tier 2 & 3)
    let pageTitle = 'Unknown';
    let screenshotBase64 = '';
    let downloadAttempted = isZipUrl;
    let redirectChain: string[] = [];
    let domAnalysis = null;

    if (!isZipUrl) {
      await browserLimiter(async () => {
        const browser = await puppeteer.launch({
          headless: true,
          args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-blink-features=AutomationControlled',
            '--window-size=1280,800'
          ]
        });
        const page = await browser.newPage();
        await page.setViewport({ width: 1280, height: 800 });
        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36');
        await page.setRequestInterception(true);

        // Network Interceptor with clean URL pathname matching
        page.on('request', (req) => {
          try {
            const reqUrl = new URL(req.url());
            const reqPath = reqUrl.pathname.toLowerCase();
            if (reqPath.endsWith('.exe') || reqPath.endsWith('.apk') || reqPath.endsWith('.zip')) {
              downloadAttempted = true;
              req.abort();
            } else {
              req.continue();
            }
          } catch {
            req.continue();
          }
        });

        try {
          const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10000 });
          
          // Capture full redirect sequence
          if (response) {
            const chain = response.request().redirectChain();
            redirectChain = chain.map(req => req.url());
            if (redirectChain.length > 0) redirectChain.push(response.url());
          }

          pageTitle = await page.title();
          await new Promise(r => setTimeout(r, 4500)); 

          // Extract DOM anomalies
          domAnalysis = await page.evaluate(() => {
            const scripts = Array.from(document.querySelectorAll('script')).map(s => s.src).filter(Boolean);
            const hiddenElements = document.querySelectorAll('[style*="display: none"], [style*="visibility: hidden"], [style*="opacity: 0"]').length;
            const iframes = Array.from(document.querySelectorAll('iframe')).length;
            return { externalScripts: scripts.length, hiddenElements, iframes };
          });

          const buf = await page.screenshot({ encoding: 'base64', fullPage: false });
          screenshotBase64 = buf as string;
        } catch {
          try {
            const buf = await page.screenshot({ encoding: 'base64', fullPage: false });
            screenshotBase64 = buf as string;
          } catch {} 
        } finally {
          await browser.close();
        }
      });
    }

    // Step E: Multimodal AI Forensics (Tier 4)
    const prompt = `
      URL: ${url}
      Title: ${pageTitle}
      Downloads Attempted: ${downloadAttempted}
      Zip Manifest Found: ${JSON.stringify(zipManifest)}
      Infrastructure Telemetry: ${JSON.stringify(infraData, null, 2)}
      Redirect Chain: ${JSON.stringify(redirectChain)}
      DOM Structure: ${JSON.stringify(domAnalysis)}

      Analyze the visual screenshot alongside the server telemetry, DOM data, and redirect sequences.
      Cross-reference visual identity against actual technical infrastructure (e.g. brand claims vs SSL age/issuer).
      Respond strictly in JSON:
      {
        "status": "SAFE" or "SCAM",
        "confidence": "percentage (01% to 100%)",
        "brandImpersonated": "Name or None",
        "verdictSummary": "1 concise sentence",
        "redFlags": ["flag 1", "flag 2"]
      }
    `;

    const contents: any[] = [prompt];
    if (screenshotBase64) {
      contents.push({ inlineData: { data: screenshotBase64, mimeType: 'image/png' } });
    }

    let parsedData = null;
    let successfulModel = '';

    for (const model of FALLBACK_MODELS) {
      try {
        const m = genAI.getGenerativeModel({ model, generationConfig: { responseMimeType: 'application/json' } });
        const res = await m.generateContent(contents);
        parsedData = JSON.parse(res.response.text());
        successfulModel = model;
        break;
      } catch {}
    }

    if (!parsedData) return NextResponse.json({ error: 'AI analysis engines unavailable.' }, { status: 503 });

    return NextResponse.json({
      ...parsedData,
      scannedBy: successfulModel,
      screenshot: screenshotBase64 ? `data:image/png;base64,${screenshotBase64}` : '',
      zipManifest,
      infrastructure: infraData,
      redirectChain,
      domAnalysis
    });

  } catch (err: any) {
    return NextResponse.json({ error: err.message || 'Execution error' }, { status: 500 });
  }
}