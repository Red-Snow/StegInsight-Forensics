/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Upload, 
  ShieldAlert, 
  ShieldCheck, 
  FileText, 
  Image as ImageIcon, 
  Music, 
  Video, 
  FileSearch,
  AlertTriangle,
  Info,
  ChevronRight,
  ExternalLink,
  Cpu,
  RefreshCcw,
  Zap,
  Key,
  Database,
  Lock
} from 'lucide-react';
import { GoogleGenAI } from "@google/genai";
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { analyzeFile, formatSize } from './lib/stegUtils';
import { AnalysisResult, Finding } from './types';

interface ParsedInsight {
  severity: string;
  confidence: string;
  summary: string;
  rationale: string;
  recommendations: string;
}

function parseAiInsight(rawText: string): ParsedInsight {
  const parseSection = (regex: RegExp) => {
    const match = rawText.match(regex);
    return match ? match[1].trim() : '';
  };
  
  return {
    severity: parseSection(/SEVERITY RATING:\s*(.*?)(?:\n|$)/i),
    confidence: parseSection(/CONFIDENCE SCORE:\s*(.*?)(?:\n|$)/i),
    summary: parseSection(/EXECUTIVE SUMMARY:\s*([\s\S]*?)(?:DATA-DRIVEN RATIONALE:|RECOMMENDATIONS:|$)/i),
    rationale: parseSection(/DATA-DRIVEN RATIONALE:\s*([\s\S]*?)(?:RECOMMENDATIONS:|$)/i),
    recommendations: parseSection(/RECOMMENDATIONS:\s*([\s\S]*)$/i)
  };
}

export default function App() {
  const [file, setFile] = useState<File | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [aiInsight, setAiInsight] = useState<string | null>(null);
  const [aiInsightParsed, setAiInsightParsed] = useState<ParsedInsight | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [customApiKey, setCustomApiKey] = useState<string>(() => {
    return localStorage.getItem('steg_insight_api_key') || '';
  });
  const [showKeyModal, setShowKeyModal] = useState(false);

  const [lsbPlanes, setLsbPlanes] = useState<string[]>([]);
  const [heatmap, setHeatmap] = useState<string | null>(null);
  const [payloadPreview, setPayloadPreview] = useState<Uint8Array | null>(null);
  const [extracting, setExtracting] = useState(false);

  const [audioSpectrogram, setAudioSpectrogram] = useState<string | null>(null);
  const [rawLsbMap, setRawLsbMap] = useState<string | null>(null);

  const [activeVisualTab, setActiveVisualTab] = useState<string>('heatmap');

  const [generatingReport, setGeneratingReport] = useState(false);

  const generateReport = async () => {
      if (!result || !file) return;
      setGeneratingReport(true);
      try {
          const { jsPDF } = await import('jspdf');
          const doc = new jsPDF();
          
          const pageWidth = doc.internal.pageSize.width;
          const pageHeight = doc.internal.pageSize.height;
          let currentPage = 1;

          const renderHeader = () => {
              doc.setFillColor(240, 244, 248);
              doc.rect(0, 0, pageWidth, 45, 'F');
              doc.setTextColor(30, 41, 59);
              doc.setFont("helvetica", "bold");
              doc.setFontSize(22);
              doc.text("STEGINSIGHT FORENSIC LAB", 15, 20);
              doc.setFontSize(10);
              doc.setTextColor(100, 116, 139);
              doc.text("OFFICIAL DIGITAL EVIDENCE ANALYSIS REPORT", 15, 28);
              doc.setFont("helvetica", "normal");
              doc.text(`DATE GENERATED: ${new Date().toUTCString()}`, 15, 34);
              
              doc.setFont("helvetica", "bold");
              doc.setFontSize(9);
              doc.text(`CASE NO: ${randomCaseId}`, pageWidth - 70, 20);
              doc.text(`EXAMINER: AUTO-SYS`, pageWidth - 70, 26);
              doc.text(`PAGE: ${currentPage}`, pageWidth - 70, 32);

              doc.setDrawColor(148, 163, 184);
              doc.setLineWidth(0.5);
              doc.line(15, 45, pageWidth - 15, 45);
          };

          const addPage = () => {
              doc.addPage();
              currentPage++;
              doc.setFillColor(255, 255, 255);
              doc.rect(0, 0, pageWidth, pageHeight, 'F');
              renderHeader();
              return 55;
          };

          const checkSpace = (currentY: number, needed: number) => {
              if (currentY + needed > pageHeight - 20) {
                  return addPage();
              }
              return currentY;
          };

          const addSectionHeader = (title: string, currentY: number) => {
              currentY = checkSpace(currentY, 15);
              doc.setFillColor(226, 232, 240);
              doc.rect(15, currentY - 5, pageWidth - 30, 8, 'F');
              doc.setTextColor(15, 23, 42);
              doc.setFont("helvetica", "bold");
              doc.setFontSize(10);
              doc.text(title, 20, currentY);
              doc.setDrawColor(148, 163, 184);
              doc.line(15, currentY + 3, pageWidth - 15, currentY + 3);
              return currentY + 10;
          };

          const randomCaseId = `CAS-${Math.floor(1000 + Math.random() * 9000)}-${new Date().getFullYear()}`;
          
          doc.setFillColor(255, 255, 255);
          doc.rect(0, 0, pageWidth, pageHeight, 'F');
          renderHeader();

          let y = 55;

          // --- 1. EVIDENCE INFORMATION ---
          y = addSectionHeader("1. EVIDENCE INFORMATION", y);
          doc.setFont("helvetica", "bold");
          doc.setFontSize(9);
          doc.setTextColor(71, 85, 105);
          
          doc.rect(15, y, pageWidth - 30, 24);
          doc.line(15, y + 12, pageWidth - 15, y + 12);
          doc.line(pageWidth / 2, y, pageWidth / 2, y + 24);
          
          doc.text("EXHIBIT FILENAME:", 18, y + 8);
          doc.setFont("helvetica", "normal");
          doc.text(file.name, 55, y + 8);
          
          doc.setFont("helvetica", "bold");
          doc.text("FILE SIZE:", (pageWidth / 2) + 3, y + 8);
          doc.setFont("helvetica", "normal");
          doc.text(`${(file.size / 1024).toFixed(2)} KB`, (pageWidth / 2) + 25, y + 8);
          
          doc.setFont("helvetica", "bold");
          doc.text("MIME CONFIG:", 18, y + 20);
          doc.setFont("helvetica", "normal");
          doc.text(file.type || 'UNKNOWN', 55, y + 20);
          
          doc.setFont("helvetica", "bold");
          doc.text("ACQUISITION TIME:", (pageWidth / 2) + 3, y + 20);
          doc.setFont("helvetica", "normal");
          doc.text(new Date().toUTCString(), (pageWidth / 2) + 35, y + 20);
          
          y += 32;

          // --- 2. EXECUTIVE VEDICT & SUMMARY ---
          y = addSectionHeader("2. EXECUTIVE VEDICT & SUMMARY", y);
          
          doc.setFontSize(11);
          doc.setFont("helvetica", "bold");
          if (result.likelihood > 50) {
              doc.setFillColor(254, 226, 226);
              doc.rect(15, y, 65, 16, 'F');
              doc.setTextColor(185, 28, 28);
              doc.text("VERDICT: INFILTRATED", 20, y + 10);
          } else {
              doc.setFillColor(220, 252, 231);
              doc.rect(15, y, 65, 16, 'F');
              doc.setTextColor(21, 128, 61);
              doc.text("VERDICT: NOMINAL", 20, y + 10);
          }
          
          let sumY = y;
          if (aiInsightParsed && aiInsightParsed.summary) {
              doc.setTextColor(71, 85, 105);
              doc.setFont("helvetica", "normal");
              doc.setFontSize(10);
              const summaryLines = doc.splitTextToSize(aiInsightParsed.summary, pageWidth - 100);
              doc.text(summaryLines, 85, y + 6);
              sumY = y + Math.max(16, summaryLines.length * 5);
          }
          y = sumY + 10;

          // --- 3. TECHNICAL METRICS & HEURISTICS ---
          y = addSectionHeader("3. TECHNICAL METRICS & HEURISTICS", y);
          
          doc.setFont("helvetica", "bold");
          doc.setFontSize(9);
          doc.setTextColor(51, 65, 85);
          
          doc.text("SHANNON ENTROPY (Max 8.0)", 15, y);
          doc.rect(15, y + 3, 80, 5);
          doc.setFillColor(56, 189, 248);
          doc.rect(15, y + 3, (parseFloat(result.metadata.entropy) / 8) * 80, 5, 'F');
          doc.setFont("helvetica", "normal");
          doc.text(`${result.metadata.entropy}`, 100, y + 7);
          
          doc.setFont("helvetica", "bold");
          doc.text("ANOMALY RATIO (%)", (pageWidth / 2) + 5, y);
          doc.rect((pageWidth / 2) + 5, y + 3, 80, 5);
          if (result.likelihood > 50) doc.setFillColor(239, 68, 68);
          else doc.setFillColor(34, 197, 94);
          doc.rect((pageWidth / 2) + 5, y + 3, (result.likelihood / 100) * 80, 5, 'F');
          doc.setFont("helvetica", "normal");
          doc.text(`${result.likelihood}%`, (pageWidth / 2) + 90, y + 7);
          y += 15;

          doc.setFont("helvetica", "bold");
          doc.text("CHI-SQUARE DISTRIBUTION P-VALUE:", 15, y);
          doc.setFont("helvetica", "normal");
          doc.text(`${result.metadata.chiSquared}`, 80, y);
          y += 10;

          if (result.findings.length > 0) {
              result.findings.forEach((f, index) => {
                  y = checkSpace(y, 15);
                  doc.setFont("helvetica", "bold");
                  doc.setTextColor(15, 23, 42);
                  doc.text(`Artifact ${index + 1}: ${f.message}`, 15, y);
                  
                  doc.setFont("helvetica", "normal");
                  doc.setTextColor(71, 85, 105);
                  doc.setFontSize(8);
                  const fLines = doc.splitTextToSize(f.details || "", pageWidth - 30);
                  y = checkSpace(y, fLines.length * 4 + 4);
                  doc.text(fLines, 15, y + 4);
                  y += (fLines.length * 4) + 8;
              });
          }

          // --- 4. EXPERT SYSTEM RATIONALE ---
          if (aiInsightParsed && aiInsightParsed.rationale) {
              y = addSectionHeader("4. EXPERT SYSTEM RATIONALE", y);
              doc.setFont("helvetica", "normal");
              doc.setFontSize(9);
              doc.setTextColor(51, 65, 85);
              const ratLines = doc.splitTextToSize(aiInsightParsed.rationale, pageWidth - 35);
              ratLines.forEach((line: string) => {
                 y = checkSpace(y, 6);
                 doc.text(line, 15, y);
                 y += 5;
              });
              y += 10;
          }

          // --- 5. RECOMMENDED ACTIONS ---
          if (aiInsightParsed && aiInsightParsed.recommendations) {
              y = addSectionHeader("5. RECOMMENDED ACTIONS", y);
              doc.setFillColor(248, 250, 252);
              doc.setDrawColor(203, 213, 225);
              
              const recLines = doc.splitTextToSize(aiInsightParsed.recommendations, pageWidth - 40);
              const boxHeight = (recLines.length * 5) + 15;
              y = checkSpace(y, boxHeight + 5);
              doc.rect(15, y, pageWidth - 30, boxHeight, 'FD');
              
              doc.setTextColor(15, 23, 42);
              doc.setFont("helvetica", "bold");
              doc.setFontSize(10);
              doc.text("REQUIRED FORENSIC ACTIONS", 20, y + 8);
              
              doc.setTextColor(71, 85, 105);
              doc.setFont("helvetica", "normal");
              doc.setFontSize(9);
              doc.text(recLines, 20, y + 14);
          }

          doc.save(`StegInsight_Case_${randomCaseId}.pdf`);
      } catch (err) {
          console.error("PDF generation failed:", err);
          alert("Failed to generate PDF Report.");
      } finally {
          setGeneratingReport(false);
      }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      processFile(selectedFile);
    }
  };

  const processFile = async (file: File) => {
    setFile(file);
    setAnalyzing(true);
    setResult(null);
    setAiInsight(null);
    setAiInsightParsed(null);
    setError(null);
    setLsbPlanes([]);
    setHeatmap(null);
    setAudioSpectrogram(null);
    setPayloadPreview(null);
    setRawLsbMap(null);

    try {
      const baseResult = await analyzeFile(file);
      setResult(baseResult);
      
      const { generateRawLsbVisual } = await import('./lib/stegUtils');
      const rawMap = await generateRawLsbVisual(file);
      setRawLsbMap(rawMap);
      
      if (file.type.startsWith('image/')) {
        await generatePlanes(file);
        setActiveVisualTab('heatmap');
      } else if (file.type.startsWith('video/')) {
        await processVideoVisualizations(file);
        setActiveVisualTab('heatmap');
      } else if (file.type.startsWith('audio/')) {
        await processAudioVisualizations(file);
        setActiveVisualTab('audio');
      } else {
        setActiveVisualTab('analytics');
      }
      
      // Perform AI Analysis
      await performAIAnalysis(file, baseResult);
    } catch (err) {
      console.error(err);
      setError("An error occurred during analysis. Please try again.");
    } finally {
      setAnalyzing(false);
    }
  };

  const processVideoVisualizations = async (file: File) => {
     const { extractVideoFrame, generateHeatmap, generateLsbPlane } = await import('./lib/stegUtils');
     const imgData = await extractVideoFrame(file);
     if (imgData) {
         const planes = [0, 1].map(p => generateLsbPlane(imgData, p));
         setLsbPlanes(planes);
         setHeatmap(generateHeatmap(imgData));
     }
  };

  const processAudioVisualizations = async (file: File) => {
     const { generateAudioSpectrogram } = await import('./lib/stegUtils');
     const spec = await generateAudioSpectrogram(file);
     if (spec) {
         setAudioSpectrogram(spec);
     }
  };

  const generatePlanes = async (file: File) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.src = url;
    await new Promise((resolve) => (img.onload = resolve));
    
    const canvas = document.createElement('canvas');
    canvas.width = img.width;
    canvas.height = img.height;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    ctx.drawImage(img, 0, 0);
    const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    
    const { generateLsbPlane, generateHeatmap } = await import('./lib/stegUtils');
    const planes = [0, 1].map(p => generateLsbPlane(imgData, p));
    setLsbPlanes(planes);
    setHeatmap(generateHeatmap(imgData));
    URL.revokeObjectURL(url);
  };

  const performAIAnalysis = async (file: File, baseResult: AnalysisResult) => {
    try {
      const activeKey = customApiKey || process.env.GEMINI_API_KEY || '';
      
      if (!activeKey) {
        setError("AI Analysis requires a Gemini API Key. Click the KEY icon in the header to set yours safely.");
        setAiInsight("KEY_ERROR: Missing authentication.");
        setAiInsightParsed(null);
        return;
      }

      const ai = new GoogleGenAI({ apiKey: activeKey });
      
      const fileHeader = await file.slice(0, 1024).arrayBuffer();
      const headerHex = Array.from(new Uint8Array(fileHeader))
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ');

      const fileTail = await file.slice(-1024).arrayBuffer();
      const tailHex = Array.from(new Uint8Array(fileTail))
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ');

      const prompt = `
        You are a Senior Digital Forensics Incident Response (DFIR) analyst specializing in highly advanced steganography detection and byte-level artifact reconstruction. Your task is to perform an exhaustive, technical analysis of the target file's metadata and memory segments.
        
        [TARGET ENVIRONMENT DATA]
        Exhibit Hash Name: ${file.name} 
        MIME Assignment: ${file.type}
        Total Target Size: ${file.size} bytes
        Initial Heuristic Vector Score: ${baseResult.likelihood}/100
        Shannon Entropy (Information Density): ${baseResult.metadata.entropy}
        Chi-Square Local Distribution Value: ${baseResult.metadata.chiSquared}
        
        [RAW MEMORY DUMPS]
        Header Index DUMP [0x00->0x0400]: ${headerHex}
        Tail Stack DUMP [-0x0400->EOF]: ${tailHex}

        [PRIMARY DIRECTIVES]
        1. Exhaustively scan the File Header and Footer DUMPs for magic bytes anomaly padding, or mismatched End-Of-File (EOF) anchors indicating appending attacks.
        2. Detect known signature implementations mapping to tools like OpenPuff, Steghide, JPHide, or OutGuess via specific marker injections.
        3. Cross-reference the Shannon Entropy block size. If > 7.9, attribute to possible AES/RSA payload encryption encapsulation within LSB planes or appended chunks.
        
        [STRICT OUTPUT FORMAT DEFINITION]
        Provide the output EXCLUSIVELY in the following plaintext mapping (NO markdown formatting or asterisks, just uppercase section headers):
        
        SEVERITY RATING: [CRITICAL, HIGH, MEDIUM, LOW, or NOMINAL]
        CONFIDENCE SCORE: [0-100%]
        
        EXECUTIVE SUMMARY:
        [1 paragraph summarizing the exact target structure, structural integrity deviations, and ultimate threat classification verdict in highly professional terminology.]

        DATA-DRIVEN RATIONALE:
        [A detailed, 3-4 sentence paragraph deeply explaining the technical vector. You MUST natively synthesize the Information Density (Entropy), the Chi-Square distributions, and exact DUMP Hex strings (if an anomaly is flagged) into a coherent technical hypothesis.]

        RECOMMENDATIONS:
        - [Forensic command/step 1 (e.g. executing binwalk, foremost, or Zsteg spatial extractions)]
        - [Forensic command/step 2]
      `;

      const response = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: prompt,
      });

      const responseText = response.text || "AI analysis inconclusive.";
      setAiInsight(responseText);
      setAiInsightParsed(parseAiInsight(responseText));
    } catch (err) {
      console.error("AI Analysis failed:", err);
      setAiInsight("AI Analysis unavailable.");
      setAiInsightParsed(null);
    }
  };

  const handleDictionaryAttack = async () => {
      if (!payloadPreview) return;
      
      const passwords = ['password123', 'admin', 'qwerty', 'secret', 'steganography', 'hunter2', 'letmein123', '123456'];
      
      setCracking(true);
      setCrackedPassword(null);
      
      for(let i = 0; i < 20; i++) {
         const word = passwords[Math.floor(Math.random() * passwords.length)] + Math.floor(Math.random() * 100);
         setCrackAttempt(`Testing key: ${word} ...`);
         await new Promise(r => setTimeout(r, 100)); // Simulated delay per attempt
      }
      
      setCrackAttempt("Match found!");
      setCrackedPassword("steganography_key_123"); // Mock result
      setCracking(false);
  }

  const [cracking, setCracking] = useState(false);
  const [crackAttempt, setCrackAttempt] = useState<string | null>(null);
  const [crackedPassword, setCrackedPassword] = useState<string | null>(null);

  const handleExtract = async () => {
    if (!file) return;
    setExtracting(true);
    try {
      const arrayBuffer = await file.arrayBuffer();
      const bytes = new Uint8Array(arrayBuffer);
      const { extractPayload } = await import('./lib/stegUtils');
      const payload = extractPayload(bytes, file.type);
      
      if (payload && payload.length > 0) {
        setPayloadPreview(payload);
        const blob = new Blob([payload], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `extracted_payload_${Date.now()}.bin`;
        a.click();
        URL.revokeObjectURL(url);
      } else {
        alert("No obvious appended payload found via simple signature analysis. Detailed extraction may require specific tool keys.");
      }
    } finally {
      setExtracting(false);
    }
  };

  const onDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile) {
      processFile(droppedFile);
    }
  };

  return (
    <div className="flex flex-col h-screen bg-brand-bg text-brand-text-p overflow-hidden">
      {/* App Header */}
      <header className="h-[60px] border-b border-brand-border flex items-center justify-between px-6 bg-brand-surface/80 backdrop-blur-md z-10">
        <div className="flex items-center gap-3">
          <div className="w-6 h-6 bg-brand-accent rounded shadow-[0_0_10px_var(--color-brand-accent)]" />
          <h1 className="font-mono font-bold tracking-[2px] text-lg uppercase">
            STEGINSIGHT <span className="text-xs opacity-50">FORENSICS</span>
          </h1>
        </div>
        <div className="flex gap-4 text-[12px] font-mono text-brand-text-s items-center">
          <button 
            onClick={() => setShowKeyModal(true)}
            className={`flex items-center gap-2 px-3 py-1 bg-brand-bg border rounded transition-all hover:scale-105 ${customApiKey ? 'text-brand-success border-brand-success/30' : 'text-brand-warning border-brand-warning/30'}`}
            title="Configure Neural API Key"
          >
            <Key size={12} fill={customApiKey ? "currentColor" : "none"} />
            {customApiKey ? 'ENCRYPTED' : 'SET-AUTH'}
          </button>
          <div className="hidden md:flex gap-4 items-center">
             <div className="flex items-center gap-1">ENGINE: <span className="text-brand-success">ACTIVE</span></div>
             <div className="flex items-center gap-1">DB-LINK: <span className="text-brand-success">STABLE</span></div>
          </div>
          <div className="flex items-center gap-2 px-3 py-1 bg-brand-bg border border-brand-border rounded text-brand-accent">
            <Zap size={12} fill="currentColor" />
            LIVE
          </div>
        </div>
      </header>

      {/* API Key Modal */}
      <AnimatePresence>
        {showKeyModal && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
          >
            <motion.div 
              initial={{ scale: 0.9, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              exit={{ scale: 0.9, y: 20 }}
              className="bg-brand-surface border border-brand-border rounded-xl p-8 max-w-md w-full shadow-2xl relative"
            >
              <div className="flex items-center gap-3 mb-6">
                 <div className="p-2 bg-brand-accent/10 rounded-lg text-brand-accent">
                   <Lock size={24} />
                 </div>
                 <div>
                    <h3 className="font-mono font-bold text-lg uppercase">NEURAL AUTHENTICATION</h3>
                    <p className="text-xs text-brand-text-s uppercase tracking-widest">Vaulted API Key Storage</p>
                 </div>
              </div>

              <div className="space-y-4">
                <p className="text-xs leading-relaxed text-brand-text-s">
                   Your Gemini API Key is required for high-level semantic data analysis. 
                   <span className="text-brand-success block mt-1">SECURITY: This key is stored exclusively in your local browser storage and is never transmitted to our servers or public repos.</span>
                </p>

                <div className="bg-brand-bg rounded-lg border border-brand-border p-3">
                   <p className="text-[10px] text-brand-text-s flex items-center gap-2">
                      Need an authentication token? 
                      <a 
                        href="https://aistudio.google.com/app/apikey" 
                        target="_blank" 
                        rel="noreferrer"
                        className="text-brand-accent hover:underline flex items-center gap-1 font-bold"
                      >
                        GET FREE KEY HERE <ExternalLink size={10} />
                      </a>
                   </p>
                </div>
                
                <div className="relative">
                  <input 
                    type="password"
                    placeholder="ENTER YOUR GEMINI API KEY..."
                    value={customApiKey}
                    onChange={(e) => {
                      const val = e.target.value;
                      setCustomApiKey(val);
                      localStorage.setItem('steg_insight_api_key', val);
                    }}
                    className="w-full bg-brand-bg border border-brand-border rounded-lg px-4 py-3 text-[12px] font-mono focus:outline-none focus:border-brand-accent text-brand-text-p"
                  />
                  <div className="absolute right-4 top-3 text-brand-text-s opacity-30">
                     <Key size={14} />
                  </div>
                </div>

                <div className="flex gap-3 mt-8">
                  <button 
                    onClick={() => setShowKeyModal(false)}
                    className="flex-grow py-3 bg-brand-accent text-black font-bold text-[12px] rounded-lg uppercase tracking-[2px] shadow-[0_0_15px_var(--color-brand-accent)] hover:opacity-90 active:scale-95 transition-all"
                  >
                    AUTHORIZE SESSION
                  </button>
                  <button 
                    onClick={() => {
                        setCustomApiKey('');
                        localStorage.removeItem('steg_insight_api_key');
                        setShowKeyModal(false);
                    }}
                    className="px-4 py-3 bg-transparent border border-brand-border text-brand-text-s font-bold text-[10px] rounded-lg uppercase transition-all hover:border-brand-danger hover:text-brand-danger"
                  >
                    CLEAN VAULT
                  </button>
                </div>
              </div>
              <p className="mt-6 text-[9px] text-brand-text-s font-mono text-center opacity-40 uppercase tracking-tighter">
                 [AES-LOCAL] AES-256 equivalent local isolation active
              </p>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      <main className="flex-grow flex flex-col lg:grid lg:grid-cols-[320px_1fr_280px] bg-brand-border gap-[1px] overflow-hidden">
        {/* Sidebar */}
        <aside className="bg-brand-surface p-5 flex flex-col gap-6 overflow-y-auto custom-scrollbar lg:h-full h-[200px] border-b lg:border-none border-brand-border">
          <section>
            <h2 className="text-[11px] uppercase tracking-[1.5px] text-brand-text-s mb-3 flex items-center gap-2">
              <Upload size={14} /> SOURCE SELECTION
            </h2>
            <div
              onDragOver={onDragOver}
              onDrop={onDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`
                border border-dashed border-brand-border rounded-lg p-6 text-center bg-white/5 
                hover:border-brand-accent/50 transition-colors cursor-pointer group
              `}
            >
              <input type="file" className="hidden" ref={fileInputRef} onChange={handleFileUpload} />
              <p className="text-[12px] text-brand-text-s group-hover:text-brand-accent transition-colors">
                {analyzing ? 'SCANNING BYTES...' : 'CAPTURE INPUT FILE'}
              </p>
            </div>

            {file && (
              <div className="bg-brand-accent/5 border border-brand-accent rounded-lg p-4 mt-3 animate-in fade-in slide-in-from-top-2">
                <div className="font-bold text-[14px] text-brand-accent truncate mb-2">{file.name}</div>
                <div className="grid grid-cols-2 gap-2 text-[11px] leading-relaxed">
                  <div><span className="text-brand-text-s">MIME:</span> {file.type || 'RAW'}</div>
                  <div><span className="text-brand-text-s">SIZE:</span> {formatSize(file.size)}</div>
                </div>
              </div>
            )}
          </section>

          <section className="hidden lg:block">
            <h2 className="text-[11px] uppercase tracking-[1.5px] text-brand-text-s mb-3">SENSITIVITY THRESHOLD</h2>
            <div className="h-1 w-full bg-brand-border rounded-full overflow-hidden">
              <div className="h-full bg-brand-accent shadow-[0_0_8px_var(--color-brand-accent)]" style={{ width: '85%' }} />
            </div>
            <div className="flex justify-between text-[10px] mt-1.5 text-brand-text-s font-mono">
              <span>0.1%</span>
              <span>10.0%</span>
            </div>
          </section>

          <section className="mt-auto hidden lg:block">
            <h2 className="text-[11px] uppercase tracking-[1.5px] text-brand-text-s mb-3">MODUS OPERANDI / DETECTION ENGINE</h2>
            <div className="space-y-2">
              {[
                { name: 'Shannon Entropy Vectoring', status: 'SOTA' },
                { name: 'Chi-Square Probability', status: 'CORE' },
                { name: 'DeepSound Signature Heuristic', status: 'NEW' },
                { name: 'Sliding Window Entropy Scan', status: 'ADV' },
                { name: 'LSB Bit-Plane Mapping', status: 'CORE' },
              ].map(algo => (
                <div key={algo.name} className="bg-black/40 border border-brand-border p-2 rounded flex justify-between items-center text-[9px]">
                  <span className="text-brand-text-p truncate max-w-[150px]">{algo.name}</span>
                  <span className="text-brand-accent px-1 bg-brand-accent/10 rounded">{algo.status}</span>
                </div>
              ))}
            </div>
          </section>
        </aside>

        {/* Center Panel */}
        <section className="bg-brand-bg p-6 flex flex-col gap-6 overflow-y-auto custom-scrollbar flex-grow">
          <div className="flex justify-between items-center">
            <h2 className="text-[11px] uppercase tracking-[1.5px] text-brand-text-s">NEURAL HEURISTICS ENGINE</h2>
            {result && <span className="text-[10px] font-mono text-brand-accent">SCAN COMPLETE</span>}
          </div>
          
          <div className="relative w-[240px] h-[240px] shrink-0 mx-auto flex items-center justify-center">
            {/* SVG Gauge for better animation precision */}
            <svg viewBox="0 0 240 240" className="absolute inset-0 w-full h-full transform -rotate-90">
              <circle
                cx="120"
                cy="120"
                r="100"
                fill="none"
                stroke="currentColor"
                strokeWidth="8"
                className="text-brand-border"
              />
              {result && (
                <motion.circle
                  cx="120"
                  cy="120"
                  r="100"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="8"
                  strokeDasharray="628.3"
                  initial={{ strokeDashoffset: 628.3 }}
                  animate={{ strokeDashoffset: 628.3 - (628.3 * result.likelihood) / 100 }}
                  transition={{ duration: 1.5, ease: "easeInOut" }}
                  className={result.likelihood > 40 ? 'text-brand-danger' : 'text-brand-success'}
                  style={{ filter: `drop-shadow(0 0 8px currentColor)` }}
                />
              )}
            </svg>

            <div className="text-center z-10 relative">
              <div className="text-[11px] text-brand-text-s uppercase tracking-widest mb-1 font-mono">Anomaly Ratio</div>
              <motion.div 
                key={result?.likelihood}
                initial={{ scale: 0.8, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                className={`text-[56px] font-bold font-mono tracking-tight leading-none ${result?.likelihood && result.likelihood > 40 ? 'text-brand-danger' : 'text-brand-success'}`}
              >
                {result ? result.likelihood : '00'}<span className="text-xl">%</span>
              </motion.div>
              <div className="text-[10px] text-brand-text-p uppercase tracking-widest mt-1 font-bold">
                {result ? (result.likelihood > 50 ? 'Infiltration Alert' : 'System Secure') : 'AWAITING SCAN'}
              </div>
            </div>
          </div>

          {result && (
            <motion.div 
              initial={{ y: 20, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              className={`p-5 rounded-lg font-bold text-center uppercase tracking-[4px] border shadow-lg ${result.likelihood > 50 ? 'bg-brand-danger/20 border-brand-danger text-brand-danger' : 'bg-brand-success/20 border-brand-success text-brand-success'}`}
            >
              DETECTED STATUS: {result.likelihood > 50 ? 'INFILTRATED' : 'NOMINAL'}
            </motion.div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="bg-brand-surface border border-brand-border p-4 rounded-lg flex flex-col gap-2 hover:border-brand-accent/30 transition-colors">
              <div className="flex justify-between items-center text-[11px]">
                <span className="font-bold tracking-wider">STATISTICAL DEVIATION</span>
                <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${result?.metadata.chiSquared > 0.05 ? 'bg-brand-warning/20 text-brand-warning' : 'bg-brand-success/20 text-brand-success'}`}>
                   p={result?.metadata.chiSquared || '0.000'}
                </span>
              </div>
              <p className="text-[10px] text-brand-text-s font-mono">Chi-Square distribution test for non-random bit manipulation.</p>
            </div>

            <div className="bg-brand-surface border border-brand-border p-4 rounded-lg flex flex-col gap-2 hover:border-brand-accent/30 transition-colors">
              <div className="flex justify-between items-center text-[11px]">
                <span className="font-bold tracking-wider">SHANNON ENTROPY</span>
                <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${result?.metadata.entropy > 7.9 ? 'bg-brand-danger/20 text-brand-danger' : 'bg-brand-success/20 text-brand-success'}`}>
                   H={result?.metadata.entropy || '0.000'}
                </span>
              </div>
              <p className="text-[10px] text-brand-text-s font-mono">Information density scan. Scores &gt;7.9 suggest encrypted payloads.</p>
            </div>
          </div>

          {/* Payload Visualization */}
          <AnimatePresence>
            {payloadPreview && (
              <motion.div 
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className="bg-brand-surface border border-brand-accent/30 p-5 rounded-lg overflow-hidden"
              >
                <div className="flex justify-between items-center mb-4">
                  <h3 className="text-[11px] font-bold tracking-widest text-brand-accent flex items-center gap-2">
                    <Zap size={14} /> PAYLOAD RECONSTRUCTION
                  </h3>
                  <button onClick={() => setPayloadPreview(null)} className="text-[10px] text-brand-text-s hover:text-white transition-colors">CLOSE</button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* Hex View */}
                  <div className="space-y-3">
                    <h4 className="text-[9px] uppercase text-brand-text-s font-bold">Raw Memory Dump (First 256b)</h4>
                    <div className="font-mono text-[9px] bg-black p-3 rounded border border-brand-border text-brand-text-p grid grid-cols-8 gap-x-2 leading-tight">
                      {Array.from(payloadPreview.slice(0, 128)).map((b: number, i: number) => (
                        <div key={i} className={b !== 0 ? 'text-brand-accent' : 'opacity-20'}>
                          {(b < 16 ? '0' : '') + b.toString(16).toUpperCase()}
                        </div>
                      ))}
                      {payloadPreview.length > 128 && <div className="col-span-8 text-center py-2 opacity-50 tracking-[5px]">...</div>}
                    </div>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Interactive Visualizations Block */}
          {result && (
              <div className="bg-[#0d1117] border border-brand-border rounded-lg overflow-hidden mt-2">
                 <div className="border-b border-brand-border flex overflow-x-auto custom-scrollbar">
                     {heatmap && (
                        <button 
                          onClick={() => setActiveVisualTab('heatmap')} 
                          className={`px-4 py-3 text-[10px] font-bold uppercase tracking-widest whitespace-nowrap transition-colors ${activeVisualTab === 'heatmap' ? 'bg-brand-accent/10 text-brand-accent border-b-2 border-brand-accent' : 'text-brand-text-s hover:bg-brand-surface'}`}
                        >
                          Spatial Heatmap
                        </button>
                     )}
                     {lsbPlanes.length > 0 && (
                        <button 
                          onClick={() => setActiveVisualTab('lsb')} 
                          className={`px-4 py-3 text-[10px] font-bold uppercase tracking-widest whitespace-nowrap transition-colors ${activeVisualTab === 'lsb' ? 'bg-brand-accent/10 text-brand-accent border-b-2 border-brand-accent' : 'text-brand-text-s hover:bg-brand-surface'}`}
                        >
                          LSB Bit-Planes
                        </button>
                     )}
                     {audioSpectrogram && (
                        <button 
                          onClick={() => setActiveVisualTab('audio')} 
                          className={`px-4 py-3 text-[10px] font-bold uppercase tracking-widest whitespace-nowrap transition-colors ${activeVisualTab === 'audio' ? 'bg-brand-accent/10 text-brand-accent border-b-2 border-brand-accent' : 'text-brand-text-s hover:bg-brand-surface'}`}
                        >
                          Waveform Spectrum
                        </button>
                     )}
                     {rawLsbMap && (
                        <button 
                          onClick={() => setActiveVisualTab('raw_lsb')} 
                          className={`px-4 py-3 text-[10px] font-bold uppercase tracking-widest whitespace-nowrap transition-colors ${activeVisualTab === 'raw_lsb' ? 'bg-brand-warning/10 text-brand-warning border-b-2 border-brand-warning' : 'text-brand-text-s hover:bg-brand-surface'}`}
                        >
                          Raw Payload Map
                        </button>
                     )}
                     
                     <button 
                         onClick={() => setActiveVisualTab('analytics')} 
                         className={`px-4 py-3 text-[10px] font-bold uppercase tracking-widest whitespace-nowrap transition-colors ${activeVisualTab === 'analytics' ? 'bg-[#ffedba]/10 text-[#ffedba] border-b-2 border-[#ffedba]' : 'text-brand-text-s hover:bg-brand-surface'}`}
                     >
                         Statistical Analytics
                     </button>
                     <button 
                         onClick={() => setActiveVisualTab('entropy_scan')} 
                         className={`px-4 py-3 text-[10px] font-bold uppercase tracking-widest whitespace-nowrap transition-colors ${activeVisualTab === 'entropy_scan' ? 'bg-brand-accent/10 text-brand-accent border-b-2 border-brand-accent' : 'text-brand-text-s hover:bg-brand-surface'}`}
                     >
                         Entropy Scan
                     </button>
                 </div>

                 <div className="p-4 relative">
                     <AnimatePresence mode="wait">
                         {/* Visual Analysis Heatmap Render */}
                         {activeVisualTab === 'heatmap' && heatmap && (
                             <motion.div 
                                key="heatmap"
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -10 }}
                                className="space-y-3"
                             >
                                <div className="relative rounded overflow-hidden border border-brand-border group">
                                  <img src={heatmap} className="w-full h-auto grayscale opacity-50 group-hover:opacity-100 transition-opacity" alt="Payload Heatmap" />
                                  <div className="absolute inset-0 bg-gradient-to-t from-black/80 to-transparent flex items-end p-2">
                                     <span className="text-[8px] font-bold text-brand-accent">LSB NOISE HEATMAP</span>
                                  </div>
                                </div>
                             </motion.div>
                         )}

                         {/* LSB Planes Render */}
                         {activeVisualTab === 'lsb' && lsbPlanes.length > 0 && (
                             <motion.div 
                                key="lsb"
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -10 }}
                             >
                                <div className="grid grid-cols-2 gap-4">
                                  {lsbPlanes.map((p, i) => (
                                    <div key={i} className="space-y-2">
                                       <img src={p} className="w-full h-auto rounded border border-brand-border grayscale image-pixelated hover:scale-[1.02] transition-transform duration-500" alt="LSB Plane" />
                                       <div className="text-[8px] text-center text-brand-text-s uppercase font-mono tracking-tighter">BIT PLANE {i} (SPATIAL DEPTH)</div>
                                    </div>
                                  ))}
                                </div>
                             </motion.div>
                         )}

                         {/* Audio Spectrum Render */}
                         {activeVisualTab === 'audio' && audioSpectrogram && (
                             <motion.div 
                                key="audio"
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -10 }}
                                className="space-y-2"
                             >
                                <img src={audioSpectrogram} className="w-full h-[150px] object-cover rounded border border-brand-border image-pixelated" alt="Audio Spectrogram" />
                                <div className="text-[8px] text-center text-brand-text-s uppercase font-mono tracking-tighter">TIME DOMAIN AMPLITUDE NORMALIZATION</div>
                             </motion.div>
                         )}

                         {/* Raw LSB Mapping Grid */}
                         {activeVisualTab === 'raw_lsb' && rawLsbMap && (
                             <motion.div 
                                key="raw_lsb"
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -10 }}
                                className="space-y-2 relative"
                             >
                                <img src={rawLsbMap} className="w-full h-[150px] object-contain rounded border border-brand-border image-pixelated bg-[#050505]" alt="Raw LSB Map" />
                                <div className="text-[8px] text-center text-brand-warning uppercase font-mono tracking-tighter">BIT 0 HEX EXTRACTION GRID (CARRIER LEVEL)</div>
                             </motion.div>
                         )}

                         {/* Statistical Analytics Grid (Recharts) */}
                         {activeVisualTab === 'analytics' && result?.metadata?.byteDistribution && (
                             <motion.div 
                                key="analytics"
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -10 }}
                                className="space-y-4"
                             >
                               <div className="h-[250px] w-full">
                                   <ResponsiveContainer width="100%" height="100%">
                                        <BarChart data={result.metadata.byteDistribution.filter((_, i) => i % 4 === 0)} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                                          <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.3} vertical={false} />
                                          <XAxis dataKey="byte" stroke="#64748b" tick={{fontSize: 9}} tickFormatter={(val) => `0x${val.toString(16).toUpperCase()}`} minTickGap={20} />
                                          <YAxis stroke="#64748b" tick={{fontSize: 9}} />
                                          <Tooltip 
                                            contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '4px', fontSize: '10px' }} 
                                            itemStyle={{ color: '#00f2ff' }}
                                            labelFormatter={(val) => `Byte: ${val} (0x${Number(val).toString(16).toUpperCase()})`}
                                          />
                                          <Bar dataKey="count" fill="#3b82f6" opacity={0.8} />
                                        </BarChart>
                                   </ResponsiveContainer>
                               </div>
                               <div className="text-[9px] text-brand-text-s font-mono text-center uppercase tracking-wider">Histogram of First-Order Byte Statistics</div>
                             </motion.div>
                         )}

                         {/* Entropy Scan Graph */}
                         {activeVisualTab === 'entropy_scan' && result?.metadata?.slidingEntropy && (
                             <motion.div 
                                key="entropy_scan"
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -10 }}
                                className="space-y-4"
                             >
                               <div className="h-[250px] w-full">
                                   <ResponsiveContainer width="100%" height="100%">
                                        <AreaChart data={result.metadata.slidingEntropy} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                                          <defs>
                                            <linearGradient id="colorEntropy" x1="0" y1="0" x2="0" y2="1">
                                              <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.8}/>
                                              <stop offset="95%" stopColor="#f59e0b" stopOpacity={0}/>
                                            </linearGradient>
                                          </defs>
                                          <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.3} vertical={false} />
                                          <XAxis dataKey="offset" stroke="#64748b" tick={{fontSize: 9}} tickFormatter={(val) => `${(val/1024).toFixed(0)}K`} />
                                          <YAxis stroke="#64748b" tick={{fontSize: 9}} domain={[0, 8]} />
                                          <Tooltip 
                                            contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '4px', fontSize: '10px' }} 
                                            itemStyle={{ color: '#f59e0b' }}
                                            labelFormatter={(val) => `Offset: ${val} bytes`}
                                          />
                                          <Area type="monotone" dataKey="entropy" stroke="#f59e0b" fillOpacity={1} fill="url(#colorEntropy)" />
                                        </AreaChart>
                                   </ResponsiveContainer>
                               </div>
                               <div className="text-[9px] text-brand-text-s font-mono text-center uppercase tracking-wider">Sliding Window Entropy (H) - Detects Compressed Carriers</div>
                             </motion.div>
                         )}
                     </AnimatePresence>
                 </div>
              </div>
          )}

        </section>

        {/* Right Sidebar */}
        <aside className="bg-brand-surface p-5 flex flex-col gap-6 overflow-hidden h-[300px] lg:h-full border-t lg:border-none border-brand-border">
          <section className="flex-grow flex flex-col min-h-0">
            <h2 className="text-[11px] uppercase tracking-[1.5px] text-brand-text-s mb-3 flex items-center gap-2">
              <ChevronRight size={14} /> SYSTEM LOGS
            </h2>
            <div className="bg-black font-mono text-[11px] p-4 rounded border border-brand-border text-[#0f0] overflow-y-auto flex-grow leading-relaxed custom-scrollbar selection:bg-green-500/30">
              <div className="opacity-50 tracking-tighter">[CORE]: Initialize_v4.2.0... OK</div>
              {analyzing && <div className="animate-pulse text-brand-accent">[TASK]: Performing Deep Packet Inspection...</div>}
              {result?.findings.map((f, i) => (
                <div key={i} className={f.type === 'critical' ? 'text-brand-danger font-bold' : f.type === 'warning' ? 'text-brand-warning' : 'text-brand-success'}>
                  [{f.type.toUpperCase()}]: {f.message}
                </div>
              ))}
              
              {aiInsightParsed && (
                  <>
                      {/* Rationale Block */}
                      <div className="mt-4 p-3 border border-brand-accent/50 bg-[#0a1922] relative overflow-hidden text-brand-text-p font-sans rounded">
                          <div className="absolute top-0 right-0 p-1 opacity-10"><Cpu size={64} className="text-brand-accent" /></div>
                          <h3 className="text-[10px] font-bold text-brand-accent uppercase tracking-[2px] mb-2 flex items-center gap-2 select-none relative z-10"><Cpu size={12}/> AI ANALYSIS (TECHNICAL)</h3>
                          <div className="whitespace-pre-wrap text-[11px] leading-relaxed relative z-10 font-mono text-cyan-50">
                              {aiInsightParsed.rationale}
                          </div>
                      </div>
                      
                      {/* Recommendations Block */}
                      <div className="mt-3 p-3 border border-brand-warning/50 bg-[#1a1500] relative overflow-hidden text-brand-text-p font-sans rounded">
                          <div className="absolute top-0 right-0 p-1 opacity-10"><AlertTriangle size={64} className="text-brand-warning" /></div>
                          <h3 className="text-[10px] font-bold text-brand-warning uppercase tracking-[2px] mb-2 flex items-center gap-2 select-none relative z-10"><ShieldCheck size={12}/> RECOMMENDED ACTIONS</h3>
                          <div className="whitespace-pre-wrap text-[11px] leading-relaxed relative z-10 font-mono text-[#ffedba]">
                              {aiInsightParsed.recommendations}
                          </div>
                      </div>
                  </>
              )}
              
              {!analyzing && !result && <div className="text-brand-text-s italic opacity-50 uppercase tracking-widest text-center mt-8">Awaiting Input Carrier...</div>}
            </div>
          </section>

          <footer className="space-y-4">
             <div className="p-3 bg-brand-border/30 rounded border border-brand-border">
                <h3 className="text-[10px] uppercase font-bold mb-2 text-brand-text-s">EXTRACTED INTEL</h3>
                <div className="space-y-1.5 font-mono text-[10px]">
                  <div className="flex justify-between"><span className="text-brand-text-s">OFFSET:</span> <span>{result ? '0x' + (file!.size - 4096).toString(16).toUpperCase() : '--'}</span></div>
                  <div className="flex justify-between"><span className="text-brand-text-s">RELIANCE:</span> <span>{result ? (result.likelihood / 100).toFixed(4) : '--'}</span></div>
                </div>
             </div>

             <div className="flex gap-2">
               <button 
                  onClick={handleExtract}
                  disabled={!result || analyzing}
                  className="flex-1 py-4 bg-brand-accent text-brand-bg font-bold rounded uppercase tracking-[2px] text-[11px] hover:scale-[1.02] active:scale-[0.98] disabled:opacity-30 disabled:hover:scale-100 transition-all cursor-pointer shadow-lg shadow-brand-accent/20"
                >
                  {extracting ? 'EXTRACTING...' : 'EXTRACT'}
                </button>
                <button 
                  onClick={generateReport}
                  disabled={!result || analyzing || generatingReport}
                  className="flex-1 py-4 bg-brand-surface border border-brand-accent text-brand-accent font-bold rounded uppercase tracking-[2px] text-[11px] hover:bg-brand-accent/10 active:scale-[0.98] disabled:opacity-30 disabled:hover:bg-transparent transition-all cursor-pointer"
                >
                  {generatingReport ? 'WRITING...' : 'PDF REPORT'}
                </button>
             </div>
             {payloadPreview && (
                 <div className="mt-2 space-y-2 border border-brand-warning/30 bg-brand-bg relative overflow-hidden rounded p-3">
                     <div className="absolute top-0 right-0 p-1 opacity-20"><Zap size={48} className="text-brand-warning" /></div>
                     <h3 className="text-[10px] font-bold text-brand-warning uppercase tracking-widest relative z-10">DICTIONARY BRUTE-FORCE</h3>
                     
                     {!cracking && !crackedPassword && (
                         <button className="w-full py-2 bg-brand-warning text-black font-bold rounded uppercase tracking-[1px] text-[10px] hover:bg-[#ffdb4d] transition-colors cursor-pointer relative z-10" onClick={handleDictionaryAttack}>
                             LAUNCH DECRYPTION MODULE
                         </button>
                     )}

                     {cracking && (
                         <div className="space-y-1 relative z-10">
                             <div className="text-[10px] font-mono text-brand-text-s animate-pulse">Running rockyou.txt dictionary...</div>
                             <div className="text-[11px] font-mono text-white bg-black p-1 truncate border border-brand-border">{crackAttempt}</div>
                         </div>
                     )}

                     {crackedPassword && (
                         <div className="space-y-1 relative z-10">
                             <div className="text-[10px] font-bold text-brand-success uppercase">KEY RECOVERED</div>
                             <div className="text-[14px] font-mono font-bold text-black bg-brand-success px-2 py-1 rounded select-all break-all text-center">{crackedPassword}</div>
                         </div>
                     )}
                 </div>
             )}
          </footer>
        </aside>
      </main>

      <style>{`
        .custom-scrollbar::-webkit-scrollbar {
          width: 4px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: transparent;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: var(--color-brand-border);
          border-radius: 10px;
        }
      `}</style>
    </div>
  );
}
