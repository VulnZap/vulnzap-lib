import { ScanMode } from "./common";

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
export interface CommitScanPayload {
  /**
   * The commit hash to scan.
   */
  commitHash: string;
  /**
   * The repository name to scan.
   */
  repository: string;
  /**
   * The branch name to scan.
   */
  branch?: string;
  /**
   * The files to scan.
   */
  files: ScannedFile[];
  /**
   * The identifier of the user who is initiating the scan (From the clientorganization).
   */
  userIdentifier: string;
}

export interface RepositoryScanPayload {
  /**
   * The identifier of the user who is initiating the scan (From the clientorganization).
   */
  userIdentifier: string;
  /**
   * The repository name to scan.
   */
  repository: string;
  /**
   * The branch name to scan.
   */
  branch?: string;
}

/**
 * The response returned after starting a scan.
 */
export interface ScanInitResponse {
  /**
   * The job ID of the scan.
   */
  success: boolean;
  /**
   * The data of the response.
   */
  data: {
    /**
     * The job ID of the scan.
     */
    jobId: string;
    /**
     * The status of the scan.
     */
    status: string;
  };
}

/**
 * Event payload emitted during the scan lifecycle.
 */
export interface ScanUpdateEvent {
  /**
   * The job ID of the scan.
   */
  jobId: string;
  /**
   * The status of the scan.
   */
  status: "queued" | "scanning" | "analyzing" | "completed";
  /**
   * The progress of the scan.
   */
  progress?: number;
}

/**
 * Event payload emitted when a scan is completed successfully.
 */
export interface ScanCompletedEvent {
  /**
   * The job ID of the scan.
   */
  jobId: string;
  /**
   * The status of the scan.
   */
  status: "completed";
  findings: {
    /**
     * The file name of the finding.
     */
    file: string;
    /**
     * The line number of the finding.
     */
    line: number;
    /**
     * The severity of the finding.
     */
    severity: "low" | "medium" | "high" | "critical";
    /**
     * The message of the finding.
     */
    message: string;
  }[];
  summary: {
    /**
     * The total number of findings.
     */
    totalFindings: number;
    /**
     * The number of critical findings.
     */
    critical: number;
    /**
     * The number of high findings.
     */
    high: number;
    /**
     * The number of medium findings.
     */
    medium: number;
    low: number;
  };
}

/**
 * Event payload when an error occurs during scanning or SSE.
 */
export interface ScanErrorEvent {
  /**
   * The job ID of the scan.
   */
  jobId?: string;
  /**
   * The message of the error.
   */
  message: string;
  /**
   * The error object.
   */
  error?: any;
}

/**
 * Cache entry format for stored scan results.
 */
export interface ScanCacheEntry {
  /**
   * The job ID of the scan.
   */
  jobId: string;
  /**
   * Timestamp when the cache entry was created.
   */
  timestamp: number;
  /**
   * The current status of the scan.
   */
  status: string;
  /**
   * Whether the scan has been resolved/completed.
   */
  resolved: boolean;
  /**
   * Timestamp when the scan was resolved/completed.
   */
  resolved_timestamp?: number;
  /**
   * The repository name.
   */
  repository: string;
  /**
   * The branch name.
   */
  branch?: string;
  /**
   * The scan results (findings, summary, etc.).
   */
  results: any;
}

/**
 * The response returned from the API when getting a scan.
 */
export interface ScanApiJobResponse {
  /**
   * The job ID of the scan.
   */
  jobId: string;
  /**
   * The commit hash of the scan.
   */
  commitHash: string;
  /**
   * The project ID of the scan.
   */
  projectId: string;
  /**
   * The progress of the scan.
   */
  progress: number;
  /**
   * The results of the scan.
   */
  results: any;
  /**
   * The metadata of the scan.
   */
  metadata: any;
  /**
   * The started at timestamp of the scan.
   */
  startedAt: number;
  /**
   * The completed at timestamp of the scan.
   */
  completedAt: number;
  /**
   * The status of the scan.
   */
  status: string;
}

export interface ListenerOptions {
  /**
   * The job ID of the scan.
   */
  jobId: string;
  /**
   * The commit hash of the scan.
   */
  commitHash?: string;
  /**
   * The repository of the scan.
   */
  repository: string;
  /**
   * The branch of the scan.
   */
  branch?: string;
  /**
   * The mode of the scan.
   */
  mode: ScanMode;
}