import React, { useState, useRef } from 'react';
import type { QRAnalysisResponse, UnifiedRiskClassification } from '../types/api';
import QR_PRESETS from '../assets/qr_presets.json';
import {
  QrCode,
  Upload,
  AlertTriangle,
  HelpCircle,
  CheckCircle2,
  AlertOctagon,
  Copy,
  Check,
  CreditCard,
  Globe,
  Wifi,
  Layers,
  Sparkles,
  RefreshCw,
  Info,
  ArrowLeft,
  BookOpen,
} from 'lucide-react';
import { UnifiedEvidenceViewer } from './UnifiedEvidenceViewer';
import { RecommendationCard } from './RecommendationCard';
import { API_BASE_URL, extractApiErrorMessage } from '../api';
import bgQr from '../assets/backgrounds/qr-safety-background.jpg';

interface QRScannerProps {
  onBackToOverview?: () => void;
}

export const QRScanner: React.FC<QRScannerProps> = ({ onBackToOverview }) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<QRAnalysisResponse | null>(null);
  const [copied, setCopied] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (file: File) => {
    if (!file.type.startsWith('image/') && !file.name.match(/\.(png|jpe?g|webp|bmp|gif)$/i)) {
      setError('Unsupported file type. Please upload a PNG, JPEG, WEBP, or BMP image.');
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      setError('File size exceeds the 5MB limit.');
      return;
    }

    setError(null);
    setSelectedFile(file);
    const reader = new FileReader();
    reader.onload = () => {
      setImagePreview(reader.result as string);
    };
    reader.readAsDataURL(file);
  };

  const handlePresetSelect = async (name: string, dataUrl: string) => {
    setError(null);
    setImagePreview(dataUrl);
    // Convert base64 dataUrl to File object
    const res = await fetch(dataUrl);
    const blob = await res.blob();
    const file = new File([blob], `${name.toLowerCase().replace(/[^a-z0-9]/g, '_')}.png`, { type: 'image/png' });
    setSelectedFile(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileChange(e.dataTransfer.files[0]);
    }
  };

  const handleScan = async () => {
    if (!selectedFile) {
      setError('Please select or upload a QR image first.');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);

      const response = await fetch(`${API_BASE_URL}/analyze-qr`, {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(extractApiErrorMessage(errorData, `Server returned ${response.status} error.`));
      }

      const data: QRAnalysisResponse = await response.json();
      setResult(data);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to scan QR code image.';
      setError(message);
      setResult(null);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopyPayload = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getRiskConfig = (classification: UnifiedRiskClassification) => {
    switch (classification) {
      case 'HIGH RISK':
        return {
          banner: 'bg-rose-50 border-rose-200 text-rose-900',
          badge: 'bg-rose-100 border-rose-300 text-rose-800',
          icon: <AlertOctagon className="w-5 h-5 text-rose-600" />,
        };
      case 'MEDIUM RISK':
        return {
          banner: 'bg-amber-50 border-amber-200 text-amber-900',
          badge: 'bg-amber-100 border-amber-300 text-amber-800',
          icon: <AlertTriangle className="w-5 h-5 text-amber-600" />,
        };
      case 'LOW RISK':
        return {
          banner: 'bg-emerald-50 border-emerald-200 text-emerald-900',
          badge: 'bg-emerald-100 border-emerald-300 text-emerald-800',
          icon: <CheckCircle2 className="w-5 h-5 text-emerald-600" />,
        };
      case 'UNABLE TO VERIFY':
      default:
        return {
          banner: 'bg-stone-50 border-stone-200 text-stone-900',
          badge: 'bg-stone-100 border-stone-300 text-stone-700',
          icon: <HelpCircle className="w-5 h-5 text-stone-500" />,
        };
    }
  };

  return (
    <div className="relative min-h-screen w-full py-8 px-4 sm:px-6 lg:px-8 overflow-hidden">
      {/* Dedicated Background Image 7 */}
      <img
        src={bgQr}
        alt="QR Safety Scanner Background"
        className="fixed inset-0 w-full h-full object-cover object-center scale-105 pointer-events-none -z-10"
      />
      {/* Subtle Atmospheric Dark Vignette Overlay for Depth & High Contrast */}
      <div className="fixed inset-0 bg-gradient-to-b from-black/75 via-black/55 to-black/80 pointer-events-none -z-10 backdrop-blur-[1px]" />

      <div className="relative z-10 max-w-7xl mx-auto space-y-8">
        {/* Back to Overview Bar */}
        {onBackToOverview && (
          <button
            type="button"
            onClick={onBackToOverview}
            className="inline-flex items-center space-x-2 text-xs font-semibold text-charcoal bg-white/75 backdrop-blur-xl px-4 py-2 rounded-full border border-white/35 shadow-md hover:border-forest/40 transition-colors group"
          >
            <ArrowLeft className="w-4 h-4 transition-transform group-hover:-translate-x-0.5 text-forest" />
            <span>Back to Overview</span>
          </button>
        )}

        {/* Main Scanner Container */}
        <div className="bg-white/75 backdrop-blur-xl rounded-3xl sm:rounded-4xl border border-white/35 p-6 md:p-10 space-y-8 shadow-2xl">
        {/* Module Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-6">
          <div className="flex items-center space-x-3.5">
            <div className="p-3 rounded-2xl bg-card-mint border border-sage-300 text-forest shadow-xs">
              <QrCode className="w-7 h-7" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xs font-bold uppercase text-forest tracking-wider font-mono">
                  Optical Safety Inspection
                </span>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] bg-emerald-100 border border-emerald-300 text-emerald-800 font-bold">
                  Isolated Optical Decoder
                </span>
              </div>
              <h1 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-charcoal tracking-tight">
                QR Code Safety Scanner &amp; UPI Inspector
              </h1>
            </div>
          </div>
          <p className="text-xs sm:text-sm text-charcoal-muted max-w-md leading-relaxed">
            Decodes optical payloads safely offline via OpenCV and pyzbar, parses UPI payment URIs, and routes web destinations into the phishing engine without executing remote scripts.
          </p>
        </div>

        {/* Preset Test Benchmarks */}
        <div className="space-y-2.5">
          <label className="text-xs font-semibold text-charcoal flex items-center space-x-1.5">
            <Sparkles className="w-3.5 h-3.5 text-forest" />
            <span>Interactive Benchmark Presets (One-Click Test Images):</span>
          </label>
          <div className="flex flex-wrap gap-2">
            {Object.entries(QR_PRESETS).map(([name, dataUrl]) => (
              <button
                key={name}
                type="button"
                onClick={() => handlePresetSelect(name, dataUrl)}
                className="text-xs px-3.5 py-1.5 rounded-full bg-white/60 backdrop-blur-md border border-white/40 hover:border-sage-400 hover:bg-white/80 text-charcoal transition-colors text-left flex items-center space-x-1.5 shadow-2xs"
              >
                <QrCode className="w-3.5 h-3.5 text-forest" />
                <span>{name}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Upload & Drag-and-Drop Area */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="md:col-span-2 space-y-4">
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setIsDragOver(true);
              }}
              onDragLeave={() => setIsDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-3xl p-8 flex flex-col items-center justify-center text-center cursor-pointer transition-all ${
                isDragOver
                  ? 'border-forest bg-card-mint/40 backdrop-blur-sm'
                  : 'border-white/45 hover:border-forest/40 bg-white/60 backdrop-blur-sm'
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept="image/png,image/jpeg,image/webp,image/bmp,image/gif"
                className="hidden"
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    handleFileChange(e.target.files[0]);
                  }
                }}
              />

              <div className="p-3.5 rounded-full bg-white/80 border border-white/40 text-forest mb-3 shadow-2xs">
                <Upload className="w-6 h-6" />
              </div>

              <p className="text-sm font-semibold text-charcoal">
                {selectedFile ? (
                  <span className="text-forest font-mono font-bold">{selectedFile.name}</span>
                ) : (
                  'Drop QR code image here or click to browse'
                )}
              </p>
              <p className="text-xs text-charcoal-muted mt-1">
                Supports PNG, JPEG, WEBP, BMP (Max 5MB, up to 4096×4096 px)
              </p>
            </div>

            <button
              type="button"
              onClick={handleScan}
              disabled={!selectedFile || isLoading}
              className={`w-full py-3.5 px-6 rounded-full font-bold text-xs flex items-center justify-center space-x-2 transition shadow-xs ${
                !selectedFile || isLoading
                  ? 'bg-surface-subtle text-charcoal-faint cursor-not-allowed border border-border'
                  : 'bg-forest hover:bg-forest-hover text-white'
              }`}
            >
              {isLoading ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Decoding &amp; Inspecting Optical Payloads...</span>
                </>
              ) : (
                <>
                  <QrCode className="w-4 h-4" />
                  <span>Scan &amp; Inspect QR Code</span>
                </>
              )}
            </button>
          </div>

          {/* Image Preview Box */}
          <div className="border border-white/40 rounded-2xl bg-white/60 backdrop-blur-sm p-4 flex flex-col items-center justify-center min-h-[220px]">
            {imagePreview ? (
              <div className="space-y-3 w-full flex flex-col items-center">
                <div className="relative max-h-48 rounded-xl overflow-hidden border border-white/40 bg-white/80 p-2.5 shadow-xs">
                  <img
                    src={imagePreview}
                    alt="QR Code Preview"
                    className="max-h-40 max-w-full object-contain"
                  />
                </div>
                <div className="text-[11px] font-mono text-charcoal-muted text-center font-medium">
                  {selectedFile?.name || 'Selected QR Image'}
                </div>
              </div>
            ) : (
              <div className="text-center text-charcoal-muted space-y-2">
                <QrCode className="w-10 h-10 mx-auto text-charcoal-faint" />
                <p className="text-xs font-medium text-charcoal">No image loaded</p>
                <p className="text-[11px] text-charcoal-faint">Choose a preset or upload an image to preview</p>
              </div>
            )}
          </div>
        </div>

        {/* Error Message Alert */}
        {error && (
          <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 text-xs flex items-center space-x-3">
            <AlertOctagon className="w-5 h-5 flex-shrink-0 text-rose-600" />
            <div>
              <span className="font-bold">Scan Error: </span>
              <span>{error}</span>
            </div>
          </div>
        )}

        {/* Results Section */}
        {result && (
          <div className="space-y-6 pt-6 border-t border-border">
            {/* Risk Verdict Banner */}
            {(() => {
              const riskConfig = getRiskConfig(result.classification);
              return (
                <div
                  className={`p-5 rounded-2xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 ${riskConfig.banner}`}
                >
                  <div className="flex items-center space-x-3">
                    <div className="p-2.5 rounded-xl bg-white border border-border shadow-xs">
                      {riskConfig.icon}
                    </div>
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-bold uppercase tracking-wider text-charcoal-muted">
                          Primary Verdict
                        </span>
                        <span className="text-[10px] px-2 py-0.5 rounded-full bg-white text-charcoal border border-border font-mono font-bold">
                          {result.qr_count_detected} Code{result.qr_count_detected === 1 ? '' : 's'} Detected
                        </span>
                      </div>
                      <div className="text-2xl font-black text-charcoal tracking-tight flex items-center space-x-2">
                        <span>{result.classification}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs px-3 py-1.5 rounded-lg font-mono bg-white border border-border text-charcoal">
                      Payload: <strong className="text-sage-800">{result.payload_type}</strong>
                    </span>
                    <span className="text-xs px-3 py-1.5 rounded-lg font-mono bg-white border border-border text-charcoal">
                      Decoder: <strong className="text-emerald-700">{result.status}</strong>
                    </span>
                  </div>
                </div>
              );
            })()}

            {/* Safe Destination Preview Card */}
            {result.destination_preview && (
              <div className="p-5 rounded-xl bg-white/70 backdrop-blur-md border border-white/45 space-y-3 shadow-sm">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-charcoal uppercase tracking-wider flex items-center space-x-1.5">
                    <Globe className="w-4 h-4 text-sage-600" />
                    <span>Hidden Destination Preview (Safe Non-Executing Sandbox)</span>
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-white/80 border border-white/40 text-charcoal uppercase font-bold">
                    Scheme: {result.destination_preview.scheme}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-white/80 border border-white/40 text-xs font-mono text-charcoal break-all select-all flex items-center justify-between gap-3 shadow-inner">
                  <span>{result.destination_preview.destination}</span>
                  <button
                    type="button"
                    onClick={() => handleCopyPayload(result.destination_preview!.destination)}
                    className="p-1.5 rounded-md bg-white/60 hover:bg-white text-charcoal-muted hover:text-charcoal border border-white/40 transition-all flex-shrink-0"
                    title="Copy payload"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>

                <div className="flex items-center space-x-2 text-[11px] text-charcoal-muted">
                  <Info className="w-3.5 h-3.5 text-sage-600 flex-shrink-0" />
                  <span>{result.destination_preview.note}</span>
                </div>
              </div>
            )}

            {/* UPI Payment Inspection Card */}
            {result.upi_inspection && result.payload_type.includes('UPI') && (
              <div className="p-5 rounded-xl bg-white/70 backdrop-blur-md border border-white/45 space-y-4 shadow-sm">
                <div className="flex items-center justify-between border-b border-border pb-3">
                  <div className="flex items-center space-x-2 text-charcoal font-bold text-sm">
                    <CreditCard className="w-4 h-4 text-amber-600" />
                    <span>UPI Payment Forensic Breakdown</span>
                  </div>
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-50 text-amber-800 border border-amber-200 font-mono font-bold">
                    Syntactic Parser Active
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                  <div className="p-3 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40">
                    <span className="text-[10px] text-charcoal-muted font-mono block">Payee VPA (UPI ID)</span>
                    <span className="font-mono font-bold text-charcoal break-all">
                      {result.upi_inspection.payee_vpa || 'Not Specified'}
                    </span>
                  </div>
                  <div className="p-3 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40">
                    <span className="text-[10px] text-charcoal-muted font-mono block">Payee Display Name</span>
                    <span className="font-semibold text-charcoal">
                      {result.upi_inspection.payee_name || 'Not Specified'}
                    </span>
                  </div>
                  <div className="p-3 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40">
                    <span className="text-[10px] text-charcoal-muted font-mono block">Pre-set Debit Amount</span>
                    <span className="font-mono font-bold text-amber-800 text-sm">
                      {result.upi_inspection.amount
                        ? `${result.upi_inspection.amount} ${result.upi_inspection.currency || 'INR'}`
                        : 'None (User Enters Amount)'}
                    </span>
                  </div>
                  <div className="p-3 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40">
                    <span className="text-[10px] text-charcoal-muted font-mono block">Transaction Note</span>
                    <span className="text-charcoal italic">
                      {result.upi_inspection.transaction_note || 'None'}
                    </span>
                  </div>
                </div>

                {/* Validation Structural Warnings */}
                {result.upi_inspection.validation_notes && result.upi_inspection.validation_notes.length > 0 && (
                  <div className="p-3.5 rounded-xl bg-amber-50/80 backdrop-blur-sm border border-amber-200 space-y-1.5">
                    <span className="text-xs font-bold text-amber-900 flex items-center space-x-1">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
                      <span>Structural Review Indicators:</span>
                    </span>
                    <ul className="list-disc list-inside text-xs text-amber-900/90 space-y-1">
                      {result.upi_inspection.validation_notes.map((note, idx) => (
                        <li key={idx}>{note}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Mandatory UPI Safety Disclaimer */}
                <div className="p-3.5 rounded-xl bg-white/60 backdrop-blur-sm border border-white/40 text-[11px] text-charcoal-muted flex items-start space-x-2">
                  <AlertOctagon className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
                  <span>
                    <strong className="text-charcoal">Mandatory Caution: </strong>
                    {result.upi_inspection.safety_warning} FraudLens does not initiate, authorize, or endorse UPI payments.
                  </span>
                </div>
              </div>
            )}

            {/* URL Phishing Analysis Preview */}
            {result.url_analysis && (
              <div className="p-5 rounded-xl bg-white/70 backdrop-blur-md border border-white/45 space-y-4 shadow-sm">
                <div className="flex items-center justify-between border-b border-border pb-3">
                  <div className="flex items-center space-x-2 text-charcoal font-bold text-sm">
                    <Globe className="w-4 h-4 text-sage-600" />
                    <span>Integrated Phishing URL Model Evaluation</span>
                  </div>
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-300 font-mono font-bold">
                    Random Forest Active
                  </span>
                </div>

                {/* Forensics quick breakdown */}
                {result.url_analysis.forensics && (
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                    <div className="p-3 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40">
                      <span className="text-[10px] text-charcoal-muted block">Hostname</span>
                      <span className="text-charcoal font-bold break-all">
                        {result.url_analysis.forensics.hostname}
                      </span>
                    </div>
                    <div className="p-3 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40">
                      <span className="text-[10px] text-charcoal-muted block">Domain / TLD</span>
                      <span className="text-charcoal">
                        {result.url_analysis.forensics.domain}.{result.url_analysis.forensics.tld}
                      </span>
                    </div>
                    <div className="p-3 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40">
                      <span className="text-[10px] text-charcoal-muted block">ML Phishing Flag</span>
                      <span
                        className={`font-bold ${
                          result.url_analysis.model_prediction?.is_phishing
                            ? 'text-rose-700'
                            : 'text-emerald-700'
                        }`}
                      >
                        {result.url_analysis.model_prediction?.is_phishing ? 'Flagged Phishing' : 'Legitimate Pattern'}
                      </span>
                    </div>
                    <div className="p-3 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40">
                      <span className="text-[10px] text-charcoal-muted block">Model Confidence</span>
                      <span className="text-sage-900 font-bold">
                        {result.url_analysis.model_prediction?.confidence
                          ? `${(result.url_analysis.model_prediction.confidence * 100).toFixed(1)}%`
                          : 'N/A'}
                      </span>
                    </div>
                  </div>
                )}

                {/* Typosquatting alert if detected */}
                {result.url_analysis.typosquatting?.is_impersonation && (
                  <div className="p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-800 flex items-center space-x-2">
                    <AlertOctagon className="w-4 h-4 text-rose-600 flex-shrink-0" />
                    <span>
                      <strong>Brand Spoofing Alert: </strong>
                      {result.url_analysis.typosquatting.details}
                    </span>
                  </div>
                )}
              </div>
            )}

            {/* Wi-Fi Details Card if payload is Wi-Fi */}
            {result.wifi_details && (
              <div className="p-5 rounded-xl bg-white/70 backdrop-blur-md border border-white/45 space-y-3 shadow-sm">
                <div className="flex items-center space-x-2 text-charcoal font-bold text-sm">
                  <Wifi className="w-4 h-4 text-sage-600" />
                  <span>Wi-Fi Network Configuration</span>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
                  <div className="p-3 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40">
                    <span className="text-[10px] text-charcoal-muted block">Network SSID</span>
                    <span className="font-bold text-charcoal">{result.wifi_details.ssid}</span>
                  </div>
                  <div className="p-3 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40">
                    <span className="text-[10px] text-charcoal-muted block">Encryption Type</span>
                    <span className="font-mono text-charcoal">{result.wifi_details.auth_type}</span>
                  </div>
                  <div className="p-3 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40">
                    <span className="text-[10px] text-charcoal-muted block">Hidden Network</span>
                    <span className="text-charcoal">{result.wifi_details.is_hidden ? 'Yes' : 'No'}</span>
                  </div>
                </div>
                {result.wifi_details.security_warning && (
                  <div className="p-3.5 rounded-xl bg-amber-50/80 backdrop-blur-sm border border-amber-200 text-xs text-amber-800">
                    {result.wifi_details.security_warning}
                  </div>
                )}
              </div>
            )}

            {/* Multi-QR Symbol Breakdown */}
            {result.decoded_items && result.decoded_items.length > 1 && (
              <div className="p-5 rounded-xl bg-white/70 backdrop-blur-md border border-white/45 space-y-3 shadow-sm">
                <div className="flex items-center space-x-2 text-charcoal font-bold text-sm">
                  <Layers className="w-4 h-4 text-sage-600" />
                  <span>All Decoded Symbols in Image ({result.decoded_items.length} codes)</span>
                </div>
                <div className="space-y-2">
                  {result.decoded_items.map((item, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-white/60 backdrop-blur-sm border border-white/40 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                    >
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-[10px] px-2 py-0.5 rounded-full bg-white/80 text-charcoal border border-white/40">
                          #{item.qr_index}
                        </span>
                        <span className="font-mono text-sage-900 font-bold">{item.payload_type}</span>
                        <span className="text-charcoal-muted truncate max-w-xs">{item.raw_payload}</span>
                      </div>
                      <span
                        className={`px-2 py-0.5 rounded-full font-mono text-[10px] font-bold ${
                          item.classification === 'HIGH RISK'
                            ? 'bg-rose-100 text-rose-800 border border-rose-300'
                            : item.classification === 'MEDIUM RISK'
                            ? 'bg-amber-100 text-amber-800 border border-amber-300'
                            : 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                        }`}
                      >
                        {item.classification}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Forensic Evidence and Guidance */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <UnifiedEvidenceViewer
                evidence={result.evidence}
                unifiedEvidence={result.unified_evidence}
                title="Unified QR Evidence Hierarchy"
              />

              <RecommendationCard
                structuredRecommendation={result.structured_recommendation}
                recommendations={result.recommendations}
                title="Actionable Safety Guidance"
              />
            </div>
          </div>
        )}
      </div>

      {/* How It Works Section */}
      <div className="rounded-3xl bg-white/75 backdrop-blur-xl border border-white/35 p-6 md:p-8 space-y-4 shadow-2xl">
        <div className="flex items-center space-x-2.5 text-sage-900 font-bold text-base">
          <BookOpen className="w-5 h-5 text-sage-600" />
          <span>How QR Code Safety Scanning Works</span>
        </div>
        <p className="text-xs text-charcoal-muted leading-relaxed">
          FraudLens bridges physical QR codes with digital fraud defense by decoding matrix symbols in a sandboxed offline environment before any destination URL or payment trigger can execute.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-2">
          <div className="p-4 rounded-xl bg-white/65 backdrop-blur-md border border-white/40 space-y-2 shadow-xs">
            <div className="w-6 h-6 rounded-full bg-sage-100 text-sage-800 font-bold text-xs flex items-center justify-center">
              1
            </div>
            <h4 className="font-bold text-charcoal text-xs">Isolated Computer Vision</h4>
            <p className="text-[11px] text-charcoal-muted leading-relaxed">
              Decodes 2D barcode symbols locally via OpenCV and pyzbar without browser rendering or executing remote JavaScript.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-white/65 backdrop-blur-md border border-white/40 space-y-2 shadow-xs">
            <div className="w-6 h-6 rounded-full bg-sage-100 text-sage-800 font-bold text-xs flex items-center justify-center">
              2
            </div>
            <h4 className="font-bold text-charcoal text-xs">Protocol Dissection</h4>
            <p className="text-[11px] text-charcoal-muted leading-relaxed">
              Classifies optical payload into UPI payment URIs, HTTP/HTTPS web links, Wi-Fi configuration credentials, or raw text.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-white/65 backdrop-blur-md border border-white/40 space-y-2 shadow-xs">
            <div className="w-6 h-6 rounded-full bg-sage-100 text-sage-800 font-bold text-xs flex items-center justify-center">
              3
            </div>
            <h4 className="font-bold text-charcoal text-xs">UPI Forensics &amp; Guardrails</h4>
            <p className="text-[11px] text-charcoal-muted leading-relaxed">
              Parses payee VPA, payee name, and pre-set debit amounts. Warns against deceptive pay requests disguised as money receipts.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-white/65 backdrop-blur-md border border-white/40 space-y-2 shadow-xs">
            <div className="w-6 h-6 rounded-full bg-sage-100 text-sage-800 font-bold text-xs flex items-center justify-center">
              4
            </div>
            <h4 className="font-bold text-charcoal text-xs">Cross-Engine Routing</h4>
            <p className="text-[11px] text-charcoal-muted leading-relaxed">
              Dispatches extracted URLs directly into the 34-feature Random Forest phishing detector, evaluating destination safety before you click.
            </p>
          </div>
        </div>
      </div>
      </div>
    </div>
  );
};
