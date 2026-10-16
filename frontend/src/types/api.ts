export type UnifiedRiskClassification =
  | 'HIGH RISK'
  | 'MEDIUM RISK'
  | 'LOW RISK'
  | 'UNABLE TO VERIFY';

export interface HealthResponse {
  status: string;
  app_name: string;
  stage: number;
  environment: string;
  version: string;
  timestamp: string;
  subsystems: {
    message_detector: string;
    url_detector: string;
    qr_scanner: string;
    threat_intel: string;
  };
}

export interface EntitySpan {
  entity_type: string;
  value: string;
  raw_text: string;
  start: number;
  end: number;
}

export interface ExtractedEntities {
  urls: string[];
  phone_numbers: string[];
  upi_ids: string[];
  indicators: string[];
  spans?: EntitySpan[];
}

export interface HeuristicFinding {
  category: string;
  explanation: string;
  matched_text: string;
  severity: 'HIGH' | 'MEDIUM';
}

export interface SocialEngineeringIndicators {
  urgency: boolean;
  threats: boolean;
  impersonation: boolean;
  otp_requests: boolean;
  prize_bait: boolean;
  payment_demands: boolean;
  link_click_pressure?: boolean;
  is_advisory_or_educational?: boolean;
  is_benign_notification?: boolean;
  signals: string[];
  findings?: HeuristicFinding[];
}

export interface HighlightedPhrase {
  phrase: string;
  reason: string;
  start_idx: number;
  end_idx: number;
  start?: number;
  end?: number;
  text?: string;
  category?: string;
  explanation?: string;
}

export interface ScamTypeInfo {
  category: string;
  label?: string;
  confidence?: number;
  matched_patterns: string[];
  candidate_categories?: string[];
  explanation?: string;
}

export interface MessageAnalysisRequest {
  message_text: string;
}

export interface DomainForensics {
  hostname: string;
  subdomain: string;
  domain: string;
  tld: string;
  path: string;
  query_params: Record<string, string>;
  has_ip_address: boolean;
  url_length: number;
}

export interface TyposquattingDetails {
  target_brand?: string;
  similarity_score?: number;
  is_impersonation: boolean;
  details: string;
}

export type EvidenceCategory =
  | 'MODEL_PREDICTION'
  | 'HEURISTIC'
  | 'CONFIRMED_THREAT_INTEL'
  | 'INFORMATIONAL';

export type EvidenceStatus =
  | 'CONFIRMED'
  | 'INCONCLUSIVE'
  | 'STALE'
  | 'UNAVAILABLE';

export type EvidenceSeverity =
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'INFORMATIONAL';

export interface UnifiedEvidenceItem {
  category: EvidenceCategory;
  description: string;
  source: string;
  severity: EvidenceSeverity;
  status: EvidenceStatus;
  timestamp: string;
  provider_lookup_timestamp?: string;
  indicator_id?: string;
  is_cached?: boolean;
}

export interface RiskIndicator {
  indicator: string;
  contribution_type: 'MODEL_FEATURE' | 'CONFIRMED_EVIDENCE' | 'HEURISTIC';
  description: string;
}

export interface ThreatIntelResult {
  source: string;
  is_flagged: boolean;
  lookup_timestamp: string;
  lookup_status: 'MATCH_FOUND' | 'CLEAN' | 'SERVICE_UNAVAILABLE' | 'RATE_LIMITED' | 'UNCONFIGURED';
  details?: string;
  is_cached?: boolean;
  cached_timestamp?: string;
  provider_name?: string;
  malicious_count?: number;
  suspicious_count?: number;
  harmless_count?: number;
}

export interface DomainIntelligenceResult {
  domain: string;
  hostname: string;
  domain_age_days?: number;
  domain_created_at?: string;
  domain_expires_at?: string;
  registrar?: string;
  registration_status?: string[];
  nameservers?: string[];
  rdap_available: boolean;
  whois_available: boolean;
  lookup_status: 'SUCCESS' | 'PARTIAL' | 'UNAVAILABLE' | 'TIMED_OUT' | 'NOT_APPLICABLE' | 'UNCONFIGURED' | string;
  domain_intelligence_score?: number;
  domain_intelligence_findings: string[];
  checked_at: string;
  tls_certificate_valid?: boolean;
  tls_issuer?: string;
  tls_expires_at?: string;
  is_cached: boolean;
}

export interface StructuredSecurityRecommendation {
  title: string;
  detected_threat: string;
  suspicious_reasons: string[];
  organization_name?: string;
  official_url?: string;
  official_domain?: string;
  official_url_source?: string;
  official_url_verified: boolean;
  recommended_action: string;
  action_steps: string[];
  is_impersonation_detected: boolean;
  scam_category?: string;
}

export interface URLAnalysisRequest {
  url: string;
}

export interface URLAnalysisResponse {
  target_url: string;
  classification: UnifiedRiskClassification;
  status: string;
  model_prediction?: {
    is_phishing: boolean;
    confidence?: number;
    model_name: string;
  };
  typosquatting?: TyposquattingDetails;
  forensics?: DomainForensics;
  explainable_risk_indicators?: RiskIndicator[];
  threat_intelligence?: ThreatIntelResult;
  domain_intelligence?: DomainIntelligenceResult;
  evidence: string[];
  unified_evidence?: UnifiedEvidenceItem[];
  recommendations: string[];
  structured_recommendation?: StructuredSecurityRecommendation;
  timestamp: string;
}

export interface MessageAnalysisResponse {
  classification: UnifiedRiskClassification;
  status: string;
  model_prediction?: {
    is_scam: boolean;
    confidence?: number;
    model_name: string;
  };
  social_engineering?: SocialEngineeringIndicators;
  highlighted_phrases?: HighlightedPhrase[];
  extracted_entities?: ExtractedEntities;
  scam_type?: ScamTypeInfo;
  embedded_url_analyses?: URLAnalysisResponse[];
  evidence: string[];
  unified_evidence?: UnifiedEvidenceItem[];
  recommendations: string[];
  structured_recommendation?: StructuredSecurityRecommendation;
  timestamp: string;
}

export type QRPayloadType =
  | 'URL'
  | 'UPI'
  | 'UPI_PAYMENT'
  | 'PHONE_OR_CONTACT'
  | 'WIFI_CONFIGURATION'
  | 'EMAIL_OR_MESSAGE'
  | 'PLAIN_TEXT'
  | 'OTHER_SUPPORTED_SCHEME'
  | 'UNSUPPORTED'
  | 'UNSUPPORTED_OR_UNRECOGNIZED'
  | 'UNREADABLE';

export interface UPIPaymentDetails {
  payee_name?: string;
  payee_vpa?: string;
  amount?: string;
  currency?: string;
  transaction_note?: string;
  merchant_code?: string;
  transaction_ref?: string;
  safety_warning: string;
  is_verified_merchant: boolean;
  has_prepopulated_amount?: boolean;
  validation_notes?: string[];
}

export interface WiFiDetails {
  ssid?: string;
  auth_type?: string;
  is_hidden: boolean;
  has_password: boolean;
  security_warning?: string;
}

export interface ContactDetails {
  contact_type: string;
  target?: string;
  name?: string;
  body?: string;
}

export interface DestinationPreview {
  title?: string;
  destination: string;
  scheme: string;
  note: string;
}

export interface DecodedQRItem {
  qr_index: number;
  payload_type: QRPayloadType;
  raw_payload: string;
  classification: UnifiedRiskClassification;
  destination_preview?: DestinationPreview;
  url_analysis?: URLAnalysisResponse;
  upi_inspection?: UPIPaymentDetails;
  wifi_details?: WiFiDetails;
  contact_details?: ContactDetails;
  evidence: string[];
  unified_evidence?: UnifiedEvidenceItem[];
}

export interface QRAnalysisResponse {
  classification: UnifiedRiskClassification;
  status: string;
  qr_count_detected: number;
  payload_type: QRPayloadType;
  raw_payload?: string;
  destination_preview?: DestinationPreview;
  url_analysis?: URLAnalysisResponse;
  upi_inspection?: UPIPaymentDetails;
  wifi_details?: WiFiDetails;
  contact_details?: ContactDetails;
  decoded_items?: DecodedQRItem[];
  explainable_risk_indicators?: RiskIndicator[];
  evidence: string[];
  unified_evidence?: UnifiedEvidenceItem[];
  recommendations: string[];
  structured_recommendation?: StructuredSecurityRecommendation;
  timestamp: string;
}
