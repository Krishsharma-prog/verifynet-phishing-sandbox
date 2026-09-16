'use client';
import { useState } from 'react';
import { 
  Search, AlertTriangle, Shield, ArrowRight, CheckCircle2, XCircle, 
  Cpu, Info, X, Eye, Image as ImageIcon, FileArchive, Server, 
  Mail, Lock, Download, Route, Code 
} from 'lucide-react';

interface ScanReport {
  status: 'SAFE' | 'SCAM';
  confidence: string;
  brandImpersonated: string;
  verdictSummary: string;
  redFlags: string[];
  scannedBy: string;
  screenshot: string;
  zipManifest: string[];
  infrastructure?: {
    hasMailServers: boolean;
    ipAddresses: string[];
    ssl?: {
      issuer: string;
      daysOld: number;
    } | null;
  } | null;
  redirectChain?: string[];
  domAnalysis?: {
    externalScripts: number;
    hiddenElements: number;
    iframes: number;
  } | null;
}

export default function Home() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState('');
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState('');
  
  const [showScoreInfo, setShowScoreInfo] = useState(false);
  const [showScreenshotModal, setShowScreenshotModal] = useState(false);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setReport(null);
    setError('');
    setShowScoreInfo(false);
    setShowScreenshotModal(false);

    try {
      setLoadingStep('Resolving host IP & gathering passive SSL telemetry...');
      const step2 = setTimeout(() => setLoadingStep('Booting isolated sandbox & monitoring redirects...'), 2500);
      const step3 = setTimeout(() => setLoadingStep('Extracting DOM codebase & compiling multimodal evidence...'), 7000);

      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      clearTimeout(step2);
      clearTimeout(step3);

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Scan failed to complete.');
      setReport(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
      setLoadingStep('');
    }
  };

  const downloadPDF = async () => {
    const element = document.getElementById('forensic-report-container');
    if (element) {
      const html2pdf = (await import('html2pdf.js')).default;
      const opt = {
        margin: 0.4,
        filename: `Forensic_Threat_Report_${Date.now()}.pdf`,
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { scale: 2, useCORS: true, backgroundColor: '#020617' },
        jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' }
      };
      html2pdf().set(opt).from(element).save();
    }
  };

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center p-4 md:p-8">
      
      {/* Top Header */}
      <header className="absolute top-6 left-6 flex items-center gap-2">
        <Shield className="w-7 h-7 text-cyan-400" />
        <span className="text-xl font-bold tracking-wider text-white">
          VERIFY<span className="text-cyan-400">NET</span>
        </span>
      </header>

      <div className="max-w-3xl w-full flex flex-col items-center mt-12 md:mt-0">
        
        <h1 className="text-3xl md:text-5xl font-black text-center mb-4 tracking-tight">
          AI Phishing & Threat Scanner
        </h1>
        <p className="text-slate-400 text-center mb-8 text-sm md:text-base max-w-md">
          Inspect URLs with real-time generative AI forensics, server telemetry, and DOM analysis before visiting them.
        </p>

        {/* Search Input Bar */}
        <form onSubmit={handleScan} className="w-full flex flex-col sm:flex-row gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
            <input
              type="url"
              required
              placeholder="https://suspicious-link.com/login"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="w-full pl-12 pr-4 py-4 bg-slate-900 border border-slate-800 rounded-xl focus:outline-none focus:border-cyan-500 text-white placeholder-slate-600 text-base shadow-inner transition-all"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="px-8 py-4 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-xl transition-all disabled:opacity-50 flex items-center justify-center gap-2 text-base min-w-[160px]"
          >
            {loading ? (
              <span className="animate-pulse">Scanning...</span>
            ) : (
              <>Analyze <ArrowRight className="w-4 h-4" /></>
            )}
          </button>
        </form>

        {loading && (
          <p className="mt-4 text-cyan-400 text-sm font-medium animate-pulse">
            {loadingStep}
          </p>
        )}

        {error && (
          <div className="mt-6 w-full p-4 bg-red-950/40 border border-red-800/50 rounded-xl text-red-400 text-sm text-center">
            {error}
          </div>
        )}

        {/* Master Forensic Report Card */}
        {report && (
          <div 
            id="forensic-report-container" 
            className="mt-8 w-full bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl animate-in fade-in slide-in-from-bottom-4 duration-500"
          >
            
            {/* 1. VERDICT HEADER */}
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between border-b border-slate-800 pb-4 mb-4 gap-4">
              <div className="flex items-start gap-3">
                {report.status === 'SAFE' ? (
                  <CheckCircle2 className="w-8 h-8 text-emerald-400 mt-1 shrink-0" />
                ) : (
                  <XCircle className="w-8 h-8 text-rose-500 mt-1 shrink-0" />
                )}
                <div>
                  <h2 className={`text-xl font-bold ${report.status === 'SAFE' ? 'text-emerald-400' : 'text-rose-500'}`}>
                    {report.status === 'SAFE' ? 'Legitimate Domain' : 'Phishing Risk Detected'}
                  </h2>
                  
                  {/* Interactive Confidence Score with 01%-100% Popover */}
                  <div className="relative flex items-center gap-2 mt-1">
                    <p className="text-xs text-slate-400">Confidence Score: {report.confidence}</p>
                    <button 
                      type="button"
                      onClick={() => setShowScoreInfo(!showScoreInfo)}
                      className="text-slate-500 hover:text-cyan-400 transition-colors focus:outline-none"
                      aria-label="Toggle scoring details"
                    >
                      <Info className="w-4 h-4" />
                    </button>

                    {showScoreInfo && (
                      <div className="absolute top-full left-0 mt-2 w-72 sm:w-80 bg-slate-800 border border-slate-700 rounded-xl p-4 shadow-2xl z-50 animate-in fade-in zoom-in-95 duration-200">
                        <div className="flex items-center justify-between mb-3 border-b border-slate-700/60 pb-2">
                          <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">Score Scale (01% - 100%)</h3>
                          <button onClick={() => setShowScoreInfo(false)} className="text-slate-400 hover:text-white">
                            <X className="w-3.5 h-3.5" />
                          </button>
                        </div>
                        <div className="space-y-2.5 text-xs">
                          <div className="flex items-start text-slate-300">
                            <span className="text-emerald-400 font-bold w-16 shrink-0">85% - 100%</span>
                            <span className="flex-1"><strong>High Certainty:</strong> Definitive visual, structural, or cryptographic evidence confirming verdict.</span>
                          </div>
                          <div className="flex items-start text-slate-300">
                            <span className="text-amber-400 font-bold w-16 shrink-0">60% - 84%</span>
                            <span className="flex-1"><strong>Moderate Risk:</strong> Anomalies present across redirects, headers, or DOM layout.</span>
                          </div>
                          <div className="flex items-start text-slate-300">
                            <span className="text-rose-400 font-bold w-16 shrink-0">30% - 59%</span>
                            <span className="flex-1"><strong>Low Certainty:</strong> Ambiguous signatures; careful scrutiny recommended.</span>
                          </div>
                          <div className="flex items-start text-slate-300">
                            <span className="text-slate-400 font-bold w-16 shrink-0">01% - 29%</span>
                            <span className="flex-1"><strong>Inconclusive:</strong> Insufficient telemetry or blocked crawler response.</span>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              <div className="flex flex-col items-end gap-2">
                {report.brandImpersonated !== 'None' && (
                  <span className="px-3 py-1 bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs rounded-full font-medium">
                    Spoofing: {report.brandImpersonated}
                  </span>
                )}
                <span className="flex items-center gap-1 text-[10px] text-slate-500 bg-slate-950 px-2 py-1 rounded-md border border-slate-800">
                  <Cpu className="w-3 h-3" /> {report.scannedBy}
                </span>
              </div>
            </div>

            <p className="text-slate-300 text-sm mb-6 leading-relaxed">
              {report.verdictSummary}
            </p>

            {/* 2. INFRASTRUCTURE TELEMETRY PANEL */}
            {report.infrastructure && (
              <div className="mb-4 grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 flex items-center gap-3">
                  <Server className="w-5 h-5 text-cyan-500 shrink-0" />
                  <div>
                    <p className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">Host IP Resolves</p>
                    <p className="text-xs text-slate-300 truncate w-32">
                      {report.infrastructure.ipAddresses?.length ? report.infrastructure.ipAddresses[0] : 'Hidden / Proxy'}
                    </p>
                  </div>
                </div>

                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 flex items-center gap-3">
                  <Lock className={`w-5 h-5 shrink-0 ${report.infrastructure.ssl ? 'text-emerald-500' : 'text-rose-500'}`} />
                  <div>
                    <p className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">SSL Certificate</p>
                    <p className="text-xs text-slate-300 truncate w-32">
                      {report.infrastructure.ssl ? `${report.infrastructure.ssl.daysOld} Days Old` : 'Invalid / Missing'}
                    </p>
                  </div>
                </div>

                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 flex items-center gap-3">
                  <Mail className={`w-5 h-5 shrink-0 ${report.infrastructure.hasMailServers ? 'text-emerald-500' : 'text-amber-500'}`} />
                  <div>
                    <p className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">Email (MX) Routing</p>
                    <p className="text-xs text-slate-300">
                      {report.infrastructure.hasMailServers ? 'Configured' : 'Missing'}
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* 3. DOM & REDIRECT PANELS */}
            {(report.domAnalysis || (report.redirectChain && report.redirectChain.length > 0)) && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
                {report.domAnalysis && (
                  <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800 flex items-start gap-3">
                    <Code className="w-5 h-5 text-cyan-400 mt-1 shrink-0" />
                    <div>
                      <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">DOM Analysis</p>
                      <p className="text-xs text-slate-300">
                        Hidden Elements: <span className="font-mono text-amber-400">{report.domAnalysis.hiddenElements}</span> <br/>
                        iFrames / External Scripts: <span className="font-mono text-cyan-400">{report.domAnalysis.iframes} / {report.domAnalysis.externalScripts}</span>
                      </p>
                    </div>
                  </div>
                )}

                {report.redirectChain && report.redirectChain.length > 0 && (
                  <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800 flex items-start gap-3">
                    <Route className="w-5 h-5 text-cyan-400 mt-1 shrink-0" />
                    <div className="w-full">
                      <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Network Redirect Chain</p>
                      <ul className="text-xs text-slate-300 font-mono space-y-1 truncate max-w-full">
                        {report.redirectChain.map((u, i) => (
                          <li key={i} className="truncate text-[10px] text-slate-400">
                            - {new URL(u).hostname}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* 4. ZIP FILE MANIFEST DISPLAY */}
            {report.zipManifest && report.zipManifest.length > 0 && (
              <div className="mb-4 bg-slate-950/60 p-4 rounded-xl border border-cyan-500/20">
                <div className="flex items-center gap-2 mb-2">
                  <FileArchive className="w-4 h-4 text-cyan-400" />
                  <span className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">
                    Archive Contents Manifest (Inside Zip)
                  </span>
                </div>
                <ul className="space-y-1 bg-slate-900 p-3 rounded-lg border border-slate-800 max-h-40 overflow-y-auto">
                  {report.zipManifest.map((fileName, idx) => (
                    <li key={idx} className="text-xs font-mono text-slate-300 flex items-center gap-2">
                      <span className="text-slate-500">[{idx + 1}]</span> {fileName}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* 5. FORENSIC FINDINGS / RED FLAGS */}
            {report.redFlags && report.redFlags.length > 0 && (
              <div className="bg-slate-950/50 p-4 rounded-xl border border-slate-800/50 mb-4">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-2">
                  Forensic Findings
                </span>
                <ul className="space-y-2">
                  {report.redFlags.map((flag, idx) => (
                    <li key={idx} className="text-xs text-slate-300 flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                      <span>{flag}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* 6. ACTION BAR (Excluded from PDF export via data attribute) */}
            <div className="flex flex-wrap gap-2 pt-2" data-html2canvas-ignore>
              {report.screenshot && (
                <button 
                  onClick={() => setShowScreenshotModal(true)} 
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-semibold rounded-lg border border-slate-700 transition-all flex items-center gap-2 cursor-pointer"
                >
                  <Eye className="w-4 h-4" /> View Visual Capture
                </button>
              )}
              <button 
                onClick={downloadPDF} 
                className="px-4 py-2 bg-slate-800 hover:bg-cyan-500/20 text-emerald-400 text-xs font-semibold rounded-lg border border-slate-700 hover:border-cyan-500/50 transition-all flex items-center gap-2 cursor-pointer"
              >
                <Download className="w-4 h-4" /> Export Forensic PDF
              </button>
            </div>

          </div>
        )}
      </div>

      {/* 7. SCREENSHOT MODAL VIEWER */}
      {showScreenshotModal && report && report.screenshot && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 animate-in fade-in duration-200">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-4xl w-full p-6 shadow-2xl flex flex-col max-h-[90vh]">
            <div className="flex justify-between items-center pb-4 border-b border-slate-800">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <ImageIcon className="w-5 h-5 text-cyan-400" /> Isolated Sandbox Visual Capture
              </h3>
              <button 
                onClick={() => setShowScreenshotModal(false)} 
                className="p-2 text-slate-400 hover:text-white rounded-lg bg-slate-800 hover:bg-slate-700 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="my-4 overflow-auto flex-1 rounded-xl bg-slate-950 p-2 flex items-center justify-center border border-slate-800">
              <img 
                src={report.screenshot} 
                alt="Sandbox target rendering" 
                className="max-w-full h-auto rounded shadow-lg object-contain" 
              />
            </div>
            <p className="text-xs text-slate-400 text-center">
              Visual evidence captured safely inside the isolated browser prior to AI inspection.
            </p>
          </div>
        </div>
      )}
    </main>
  );
}