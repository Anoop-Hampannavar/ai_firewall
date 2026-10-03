/**
 * Type-Safe Contracts for AI Firewall Microservice Gateway
 */

export type ThreatSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface PromptScanPayload {
  promptText: string;
  sourceIp?: string;
  enforceStrictPolicy: boolean;
}

export interface SecurityScanResult {
  isBlocked: boolean;
  violationType?: 'PROMPT_INJECTION' | 'JAILBREAK' | 'SENSITIVE_DATA' | 'NONE';
  severity: ThreatSeverity;
  riskScore: number;
  message: string;
}

export interface FirewallTelemetryEvent {
  eventId: string;
  timestamp: string;
  status: 'ALLOWED' | 'QUARANTINED' | 'BLOCKED';
  payloadSummary: string;
}