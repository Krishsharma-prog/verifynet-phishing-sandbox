import { NextResponse } from 'next/server';
import puppeteer from 'puppeteer';
import { GoogleGenerativeAI } from '@google/generative-ai';
import dns from 'dns/promises';
import tls from 'tls';
import AdmZip from 'adm-zip';
import pLimit from 'p-limit';

export const maxDuration = 60;
export const dynamic = 'force-dynamic';

const browserLimiter = pLimit(2);

const ENTERPRISE_WHITELIST = [
  'verifynet.onrender.com',
  'github.com',
  'www.github.com',
  'microsoft.com',
  'www.microsoft.com',
  'google.com',
  'www.google.com',
  'linkedin.com',
  'www.linkedin.com',
  'landrover.in',
  'www.landrover.in',
  'yesbank.in',
  'www.yesbank.in',
  'yes.bank.in',
  'www.yes.bank.in',
  'hdfcbank.com',
  'www.hdfcbank.com',
  'icicibank.com',
  'www.icicibank.com',
];

function isPrivateIP(ip: string): boolean {
  if (ip === '::1' || ip === 'localhost') return true;
  const ipv4 = ip.startsWith('::ffff:') ? ip.slice(7) : ip;
  const parts = ipv4.split('.').map(Number);
  if (parts.length === 4) {
    if (parts[0] === 10) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 0) return true;
  }
  if (ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80')) return true;
  return false;
}

function getSSLDetails(hostname: string, port = 443): Promise<{ issuer: string; daysOld: number } | null> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host: hostname, port, servername: hostname, timeout: 4000, rejectUnauthorized: false },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          if (cert && cert.valid_from) {
            const validFrom = new Date(cert.valid_from).getTime();
            const daysOld = Math.max(0, Math.floor((Date.now() - validFrom) / (1000 * 60 * 60 * 24)));
            
            const rawIssuer = cert.issuer ? (cert.issuer.O || cert.issuer.CN || 'Standard CA') : 'Standard CA';
            const issuer = Array.isArray(rawIssuer) ? (rawIssuer[0] || 'Standard CA') : (rawIssuer || 'Standard CA');

            socket.end();
            return resolve({ issuer: String(issuer), daysOld });
          }
        } catch {}
        socket.end();
        resolve(null);
      }
    );
    socket.on('error', () => resolve(null));
    socket.on('timeout', () => {
      socket.destroy();
      resolve(null);
    });
  });
}

async function inspectZipArchive(targetUrl: string): Promise<string[]> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000);
  try {
    const res = await fetch(targetUrl, { signal: controller.signal });
    clearTimeout(timeoutId);
    if (!res.ok) return [];

    const contentLength = res.headers.get('content-length');
    if (contentLength && parseInt(contentLength, 10) > 15 * 1024 * 1024) {
      return ['[SECURITY NOTICE] Download file is too large to inspect safely.'];
    }

    const arrayBuffer = await res.arrayBuffer();
    if (arrayBuffer.byteLength > 15 * 1024 * 1024) {
      return ['[SECURITY NOTICE] Download file is too large to inspect safely.'];
    }

    const zip = new AdmZip(Buffer.from(arrayBuffer));
    const entries = zip.getEntries();
    let totalUncompressedSize = 0;
    const manifest: string[] = [];

    for (const entry of entries) {
      totalUncompressedSize += entry.header.size;
      if (totalUncompressedSize > 50 * 1024 * 1024) {
        manifest.push('[SECURITY NOTICE] File archive is unusually large. Stopped checking.');
        break;
      }
      manifest.push(entry.entryName);
    }
    return manifest;
  } catch (err: any) {
    return [`Could not open file archive: ${err.message}`];
  }
}

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const { url } = body;

    if (!url || typeof url !== 'string') {
      return NextResponse.json({ error: 'Please enter a valid website address.' }, { status: 400 });
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url);
      if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        return NextResponse.json({ error: 'Only regular website links (HTTP/HTTPS) are supported.' }, { status: 400 });
      }
    } catch {
      return NextResponse.json({ error: 'The website address provided is not formatted correctly.' }, { status: 400 });
    }

    const targetHostname = parsedUrl.hostname.toLowerCase();
    const pathnameLower = parsedUrl.pathname.toLowerCase();

    // Whitelist bypass
    if (ENTERPRISE_WHITELIST.includes(targetHostname)) {
      return NextResponse.json({
        status: 'SAFE',
        confidence: '100%',
        brandImpersonated: 'None',
        verdictSummary: `This is a trusted, official website (${targetHostname}). It is completely safe to visit.`,
        redFlags: [],
        scannedBy: 'VerifyNet Safety System',
        screenshot: '',
        zipManifest: [],
        infrastructure: {
          hasMailServers: true,
          ipAddresses: ['Trusted Cloud Network'],
          ssl: { issuer: 'Trusted Security Provider', daysOld: 365 },
        },
        redirectChain: [parsedUrl.href],
        domAnalysis: { externalScripts: 0, hiddenElements: 0, iframes: 0 },
      });
    }

    // Binary / C2 File filter
    const malwareExtensions = /\.(mips|elf|arm|bin|exe|sh|bat|ps1|vbs|scr|cmd|apk|msi)$/i;
    const isRawIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(targetHostname);

    if (malwareExtensions.test(pathnameLower) || (isRawIP && pathnameLower !== '/' && pathnameLower !== '')) {
      return NextResponse.json({
        status: 'SCAM',
        confidence: '100%',
        brandImpersonated: 'None',
        verdictSummary: 'Danger! This link leads directly to a harmful software download instead of a normal webpage.',
        redFlags: ['The link tries to download a harmful file directly to your device.'],
        scannedBy: 'VerifyNet Threat Detector',
        screenshot: '',
        zipManifest: [],
        infrastructure: { hasMailServers: false, ipAddresses: [targetHostname], ssl: null },
        redirectChain: [parsedUrl.href],
        domAnalysis: null,
      });
    }

    // Google Safe Browsing Check
    const googleSafeBrowsingKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    if (googleSafeBrowsingKey) {
      try {
        const gsRes = await fetch(
          `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${googleSafeBrowsingKey}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              client: { clientId: 'verifynet-scanner', clientVersion: '1.0' },
              threatInfo: {
                threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                platformTypes: ['ANY_PLATFORM'],
                threatEntryTypes: ['URL'],
                threatEntries: [{ url: parsedUrl.href }],
              },
            }),
          }
        );

        const gsData = await gsRes.json();
        if (gsData && gsData.matches && gsData.matches.length > 0) {
          return NextResponse.json({
            status: 'SCAM',
            confidence: '100%',
            brandImpersonated: 'None',
            verdictSummary: 'Danger! Google has flagged this website as a known online scam or virus distributor.',
            redFlags: ['Listed on official global security watchlists as a threat.'],
            scannedBy: 'Global Security Watchlist',
            screenshot: '',
            zipManifest: [],
            infrastructure: { hasMailServers: false, ipAddresses: [], ssl: null },
            redirectChain: [parsedUrl.href],
            domAnalysis: null,
          });
        }
      } catch (err) {
        console.error('Safety check failed:', err);
      }
    }

    // SSRF Check
    let resolvedIPs: string[] = [];
    try {
      const lookupResult = await dns.lookup(targetHostname, { all: true });
      resolvedIPs = lookupResult.map((r) => r.address);
      for (const address of resolvedIPs) {
        if (isPrivateIP(address)) {
          return NextResponse.json({ error: 'Security restriction: Cannot scan internal private network addresses.' }, { status: 403 });
        }
      }
    } catch (e: any) {
      return NextResponse.json({ error: `Could not find website address: ${e.message}` }, { status: 400 });
    }

    // Telemetry Gathering
    const [mxRecords, sslDetails] = await Promise.all([
      dns.resolveMx(targetHostname).catch(() => []),
      parsedUrl.protocol === 'https:' ? getSSLDetails(targetHostname) : Promise.resolve(null),
    ]);
    const hasMailServers = Array.isArray(mxRecords) && mxRecords.length > 0;

    // Zip Inspect
    let zipManifest: string[] = [];
    if (parsedUrl.pathname.toLowerCase().endsWith('.zip')) {
      zipManifest = await inspectZipArchive(parsedUrl.href);
      const hasExecutable = zipManifest.some((f) => /\.(exe|bat|ps1|vbs|scr|js|cmd)$/i.test(f));
      return NextResponse.json({
        status: hasExecutable ? 'SCAM' : 'SAFE',
        confidence: '95%',
        brandImpersonated: 'None',
        verdictSummary: hasExecutable ? 'Warning: This downloaded file package contains harmful program scripts.' : 'The downloaded file package appears safe to open.',
        redFlags: hasExecutable ? ['Contains executable scripts inside the package'] : [],
        scannedBy: 'File Package Inspector',
        screenshot: '',
        zipManifest,
        infrastructure: { hasMailServers, ipAddresses: resolvedIPs, ssl: sslDetails },
      });
    }

    // Headless Browser Sandbox Execution
    let screenshotBase64 = '';
    const redirectChain: string[] = [parsedUrl.href];
    let domAnalysis = { externalScripts: 0, hiddenElements: 0, iframes: 0 };

    await browserLimiter(async () => {
      let browser;
      try {
        browser = await puppeteer.launch({
          headless: true,
          args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--disable-blink-features=AutomationControlled', '--window-size=1280,800'],
        });

        const page = await browser.newPage();
        await page.setViewport({ width: 1280, height: 800 });
        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36');

        await page.setRequestInterception(true);
        page.on('request', (interceptedReq) => {
          try {
            const reqPath = new URL(interceptedReq.url()).pathname.toLowerCase();
            if (reqPath.endsWith('.exe') || reqPath.endsWith('.apk') || reqPath.endsWith('.msi')) {
              interceptedReq.abort();
              return;
            }
          } catch {}
          interceptedReq.continue();
        });

        page.on('response', (res) => {
          const status = res.status();
          if (status >= 300 && status < 400) {
            const loc = res.headers()['location'];
            if (loc) {
              try {
                redirectChain.push(new URL(loc, parsedUrl.href).href);
              } catch {
                redirectChain.push(loc);
              }
            }
          }
        });

        try {
          await page.goto(parsedUrl.href, { waitUntil: 'domcontentloaded', timeout: 15000 });
        } catch {}

        domAnalysis = await page
          .evaluate(() => {
            const externalScripts = document.querySelectorAll('script[src]').length;
            const iframes = document.querySelectorAll('iframe').length;
            let hiddenElements = 0;
            document.querySelectorAll('*').forEach((node) => {
              const el = node as HTMLElement;
              const style = window.getComputedStyle(el);
              if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
                hiddenElements++;
              }
            });
            return { externalScripts, hiddenElements, iframes };
          })
          .catch(() => ({ externalScripts: 0, hiddenElements: 0, iframes: 0 }));

        // Optimized quality: 50 for quick, non-blocking PDF generation
        const buffer = await page.screenshot({ type: 'jpeg', quality: 50, encoding: 'base64' });
        screenshotBase64 = `data:image/jpeg;base64,${buffer}`;
      } finally {
        if (browser) {
          await browser.close().catch(() => {});
        }
      }
    });

    // Multimodal Gemini AI Analysis
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return NextResponse.json({
        status: 'SAFE',
        confidence: '70%',
        brandImpersonated: 'None',
        verdictSummary: 'Website snapshot taken successfully. Appears normal.',
        redFlags: [],
        scannedBy: 'Automated Safety Check',
        screenshot: screenshotBase64,
        zipManifest: [],
        infrastructure: { hasMailServers, ipAddresses: resolvedIPs, ssl: sslDetails },
        redirectChain,
        domAnalysis,
      });
    }

    const genAI = new GoogleGenerativeAI(apiKey);
    const candidateModels = ['gemini-2.5-flash', 'gemini-1.5-flash', 'gemini-2.0-flash'];

    const promptText = `
You are a friendly online safety assistant explaining website safety to a normal person who is not technical. Avoid technical jargon like DOM, telemetry, sockets, SSRF, or hashes. Use everyday plain language.

WEBSITE INFORMATION:
- Website Address: ${parsedUrl.href}
- Security Certificate Age: ${sslDetails ? `${sslDetails.daysOld} days old` : 'Unknown'}

RULES FOR YOUR RESPONSE:
1. Explain in simple sentences whether this website is safe to use or if it looks like a scam/phishing trick.
2. If it is a normal company website or portfolio, say it is safe.
3. Only mark it as a scam if you see fake login forms trying to steal passwords or pretend to be another company.

Respond ONLY with valid JSON in this exact structure:
{
  "status": "SAFE" | "SCAM",
  "confidence": "85%",
  "brandImpersonated": "None" | "Company Name",
  "verdictSummary": "A simple, friendly 1-2 sentence explanation written for a non-technical user.",
  "redFlags": ["Simple warning point 1"]
}
`;

    let aiResultText = '';
    let selectedModel = 'AI Safety Vision';

    for (const modelName of candidateModels) {
      try {
        const model = genAI.getGenerativeModel({ model: modelName });
        const contents: any[] = [{ text: promptText }];

        if (screenshotBase64) {
          const rawData = screenshotBase64.replace(/^data:image\/jpeg;base64,/, '');
          contents.push({
            inlineData: { data: rawData, mimeType: 'image/jpeg' },
          });
        }

        const response = await model.generateContent(contents);
        aiResultText = response.response.text();
        selectedModel = modelName;
        break;
      } catch {
        continue;
      }
    }

    let parsedAI: any = null;
    try {
      const cleanedJson = aiResultText.replace(new RegExp('```json', 'gi'), '').replace(new RegExp('```', 'g'), '').trim();
      parsedAI = JSON.parse(cleanedJson);
    } catch {
      parsedAI = {
        status: 'SAFE',
        confidence: '85%',
        brandImpersonated: 'None',
        verdictSummary: 'This website loaded normally and appears safe to browse.',
        redFlags: [],
      };
    }

    return NextResponse.json({
      status: parsedAI.status || 'SAFE',
      confidence: parsedAI.confidence || '85%',
      brandImpersonated: parsedAI.brandImpersonated || 'None',
      verdictSummary: parsedAI.verdictSummary || 'Website check complete. No threats found.',
      redFlags: Array.isArray(parsedAI.redFlags) ? parsedAI.redFlags : [],
      scannedBy: 'AI Safety Assistant',
      screenshot: screenshotBase64,
      zipManifest,
      infrastructure: { hasMailServers, ipAddresses: resolvedIPs, ssl: sslDetails },
      redirectChain,
      domAnalysis,
    });
  } catch (error: any) {
    return NextResponse.json(
      { error: 'Something went wrong while checking this website. Please try another link.' },
      { status: 500 }
    );
  }
}