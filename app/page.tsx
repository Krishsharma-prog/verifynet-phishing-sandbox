'use client';
import { useState } from 'react';
import { 
  Search, AlertTriangle, Shield, ArrowRight, CheckCircle2, XCircle, 
  Cpu, Info, X, Eye, Image as ImageIcon, Download 
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
  const [downloadingPdf, setDownloadingPdf] = useState(false);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setReport(null);
    setError('');
    setShowScoreInfo(false);
    setShowScreenshotModal(false);

    try {
      setLoadingStep('Checking safety databases & verifying website setup...');
      const step2 = setTimeout(() => setLoadingStep('Scanning website content and running safety checks...'), 2500);
      const step3 = setTimeout(() => setLoadingStep('Analyzing results and preparing a simple summary...'), 7000);

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

  const downloadPDF = () => {
    if (downloadingPdf) return;
    
    const element = document.getElementById('forensic-report-container');
    if (!element) return;

    setDownloadingPdf(true);

    // Using a 150ms timeout to unblock the main browser thread. 
    // This allows React to render the "Generating PDF..." state BEFORE html2canvas locks the CPU.
    setTimeout(async () => {
      try {
        const html2pdf = (await import('html2pdf.js')).default;
        const opt: any = {
          margin: 0.4,
          filename: `VerifyNet_Safety_Report_${Date.now()}.pdf`,
          image: { type: 'jpeg', quality: 0.85 },
          html2canvas: { 
            scale: 2, 
            useCORS: true, 
            backgroundColor: '#020617',
            windowWidth: element.scrollWidth,
            windowHeight: element.scrollHeight,
            logging: false
          },
          jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' }
        };
        await html2pdf().set(opt).from(element).save();
      } catch (err) {
        console.error('PDF generation failed:', err);
        alert('Failed to generate PDF. Please try again.');
      } finally {
        setDownloadingPdf(false);
      }
    }, 150); 
  };

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center p-4 md:p-8">
      
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
          Check any website link safely before visiting it to ensure you avoid scams and viruses.
        </p>

        <form onSubmit={handleScan} className="w-full flex flex-col sm:flex-row gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
            <input
              type="url"
              required
              placeholder="https://example.com"
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
            {loading ? <span className="animate-pulse">Checking...</span> : <>Check Link <ArrowRight className="w-4 h-4" /></>}
          </button>
        </form>

        {loading && <p className="mt-4 text-cyan-400 text-sm font-medium animate-pulse">{loadingStep}</p>}

        {error && (
          <div className="mt-6 w-full p-4 bg-red-950/40 border border-red-800/50 rounded-xl text-red-400 text-sm text-center">
            {error}
          </div>
        )}

        {report && (
          <div 
            id="forensic-report-container" 
            className="mt-8 w-full bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl animate-in fade-in slide-in-from-bottom-4 duration-500"
          >
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between border-b border-slate-800 pb-4 mb-4 gap-4">
              <div className="flex items-start gap-3">
                {report.status === 'SAFE' ? (
                  <CheckCircle2 className="w-8 h-8 text-emerald-400 mt-1 shrink-0" />
                ) : (
                  <XCircle className="w-8 h-8 text-rose-500 mt-1 shrink-0" />
                )}
                <div>
                  <h2 className={`text-xl font-bold ${report.status === 'SAFE' ? 'text-emerald-400' : 'text-rose-500'}`}>
                    {report.status === 'SAFE' ? 'Safe Website' : 'Scam / Threat Detected'}
                  </h2>
                  <div className="relative flex items-center gap-2 mt-1">
                    <p className="text-xs text-slate-400">Confidence Score: {report.confidence}</p>
                    <button 
                      type="button"
                      onClick={() => setShowScoreInfo(!showScoreInfo)}
                      className="text-slate-500 hover:text-cyan-400 transition-colors focus:outline-none"
                    >
                      <Info className="w-4 h-4" />
                    </button>

                    {showScoreInfo && (
                      <div className="absolute top-full left-0 mt-2 w-72 sm:w-80 bg-slate-800 border border-slate-700 rounded-xl p-4 shadow-2xl z-50 animate-in fade-in zoom-in-95 duration-200">
                        <div className="flex items-center justify-between mb-3 border-b border-slate-700/60 pb-2">
                          <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">Confidence Guide</h3>
                          <button onClick={() => setShowScoreInfo(false)} className="text-slate-400 hover:text-white">
                            <X className="w-3.5 h-3.5" />
                          </button>
                        </div>
                        <div className="space-y-2.5 text-xs">
                          <div className="flex items-start text-slate-300">
                            <span className="text-emerald-400 font-bold w-16 shrink-0">85% - 100%</span>
                            <span className="flex-1"><strong>Very Certain:</strong> Clear, undeniable proof confirms the verdict.</span>
                          </div>
                          <div className="flex items-start text-slate-300">
                            <span className="text-amber-400 font-bold w-16 shrink-0">60% - 84%</span>
                            <span className="flex-1"><strong>Medium Risk:</strong> Suspicious warning signs found in the setup.</span>
                          </div>
                          <div className="flex items-start text-slate-300">
                            <span className="text-rose-400 font-bold w-16 shrink-0">30% - 59%</span>
                            <span className="flex-1"><strong>Caution:</strong> Mixed signals found; double-check before proceeding.</span>
                          </div>
                          <div className="flex items-start text-slate-300">
                            <span className="text-slate-400 font-bold w-16 shrink-0">01% - 29%</span>
                            <span className="flex-1"><strong>Unknown:</strong> Not enough data or the website blocked our scanner.</span>
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
                    Impersonating: {report.brandImpersonated}
                  </span>
                )}
                <span className="flex items-center gap-1 text-[10px] text-slate-500 bg-slate-950 px-2 py-1 rounded-md border border-slate-800">
                  <Cpu className="w-3 h-3" /> {report.scannedBy}
                </span>
              </div>
            </div>

            <p className="text-slate-300 text-sm mb-6 leading-relaxed">{report.verdictSummary}</p>

            {report.redFlags && report.redFlags.length > 0 && (
              <div className="bg-slate-950/50 p-4 rounded-xl border border-slate-800/50 mb-4">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-2">Key Warnings</span>
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

            <div className="flex flex-wrap gap-2 pt-2" data-html2canvas-ignore>
              {report.screenshot && (
                <button 
                  onClick={() => setShowScreenshotModal(true)} 
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-semibold rounded-lg border border-slate-700 transition-all flex items-center gap-2 cursor-pointer"
                >
                  <Eye className="w-4 h-4" /> View Website Snapshot
                </button>
              )}
              <button 
                onClick={downloadPDF} 
                disabled={downloadingPdf}
                className="px-4 py-2 bg-slate-800 hover:bg-cyan-500/25 text-emerald-400 text-xs font-semibold rounded-lg border border-slate-700 transition-all flex items-center gap-2 cursor-pointer disabled:opacity-50"
              >
                <Download className="w-4 h-4" /> {downloadingPdf ? 'Generating PDF...' : 'Download Report PDF'}
              </button>
            </div>
          </div>
        )}
      </div>

      {showScreenshotModal && report && report.screenshot && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-4xl w-full p-6 shadow-2xl flex flex-col max-h-[90vh]">
            <div className="flex justify-between items-center pb-4 border-b border-slate-800">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <ImageIcon className="w-5 h-5 text-cyan-400" /> Safe Website Snapshot Preview
              </h3>
              <button onClick={() => setShowScreenshotModal(false)} className="p-2 text-slate-400 hover:text-white rounded-lg bg-slate-800">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="my-4 overflow-auto flex-1 rounded-xl bg-slate-950 p-2 flex items-center justify-center border border-slate-800">
              <img src={report.screenshot} alt="Website snapshot preview" className="max-w-full h-auto rounded shadow-lg object-contain" />
            </div>
          </div>
        </div>
      )}
    </main>
  );
}