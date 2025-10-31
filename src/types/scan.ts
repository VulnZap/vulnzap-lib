/**
 * Represents a single file included in a vulnerability scan.
 */
export interface ScannedFile {
  name: string;
  content: string;
}

/**
 * The payload sent to the Vulnzap API when initiating a scan.
 */
export interface ScanPayload {
  commit: string;
  repository?: string;
  branch?: string;
  files: ScannedFile[];
}

/**
 * The response returned after starting a scan.
 */
export interface ScanInitResponse {
  jobId: string;
  status: string;
}

/**
 * Event payload emitted during the scan lifecycle.
 */
export interface ScanUpdateEvent {
  jobId: string;
  status: "queued" | "scanning" | "analyzing" | "completed";
  progress?: number;
}

/**
 * Event payload emitted when a scan is completed successfully.
 */
export interface ScanCompletedEvent {
  jobId: string;
  status: "completed";
  findings: {
    file: string;
    line: number;
    severity: "low" | "medium" | "high" | "critical";
    message: string;
  }[];
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

/**
 * Event payload when an error occurs during scanning or SSE.
 */
export interface ScanErrorEvent {
  jobId?: string;
  message: string;
  error?: any;
}
