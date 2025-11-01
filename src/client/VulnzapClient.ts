import { VulnzapAPI } from "./api";
import type { VulnzapEvents } from "./eventTypes";
import type {
  ScanPayload,
  ScanCompletedEvent,
  ScanUpdateEvent,
  ScanInitResponse,
  ScanApiJobResponse,
} from "../types/scan";
import { EventEmitter } from "events";
import type { VulnzapClientOptions } from "../types/client";

/**
 * Main API client for interacting with the Vulnzap vulnerability scanning service.
 *
 * Provides methods to:
 * - Scan commits for vulnerabilities.
 * - Receive real-time updates via Server-Sent Events (SSE).
 * - Subscribe to scan lifecycle events such as `update`, `completed`, and `error`.
 *
 * @example
 * ```ts
 * const client = new VulnzapClient({ 
 *   apiKey: process.env.VULNZAP_API_KEY!,
 *   baseUrl: process.env.VULNZAP_BASE_URL!
 * });
 * client.on("completed", console.log);
 * ```
 */
export declare interface VulnzapClient {
  on<U extends keyof VulnzapEvents>(event: U, listener: VulnzapEvents[U]): this;
  emit<U extends keyof VulnzapEvents>(
    event: U,
    ...args: Parameters<VulnzapEvents[U]>
  ): boolean;
}

export class VulnzapClient extends EventEmitter {
  private api: VulnzapAPI;

  /**
   * Create a new VulnzapClient instance.
   * @param options - Configuration options for the client.
   * @param options.apiKey - Your Vulnzap API key.
   * @param options.baseUrl - Optional custom API base URL (defaults to Vulnzap cloud).
   */
  constructor(options: VulnzapClientOptions) {
    super();
    this.api = new VulnzapAPI(
      options.apiKey,
      options.baseUrl || "https://engine.vulnzap.com"
    );
    
    // Forward events from API to client
    this.api.on("completed", (data: ScanCompletedEvent) => {
      this.emit("completed", data);
    });
    
    this.api.on("update", (data: ScanUpdateEvent) => {
      this.emit("update", data);
    });
    
    this.api.on("error", (error: any) => {
      this.emit("error", error);
    });
  }

  /**
   * Initiate a vulnerability scan for a given commit.
   *
   * This method sends the commit data and file contents to the Vulnzap API
   * and automatically starts listening for the scan results using SSE.
   *
   * @param payload - The commit details and file contents to scan.
   * @returns A promise resolving to the scan initiation result with job ID and status.
   *
   * @example
   * ```ts
   * const result = await client.scanCommit({
   *   commit: "abc123",
   *   repository: "owner/repo",
   *   branch: "main",
   *   files: [{ name: "src/app.js", content: "console.log('hi');" }],
   * });
   * console.log(result.jobId);
   * ```
   */
  async scanCommit(
    payload: ScanPayload
  ): Promise<ScanInitResponse> {
    const job = await this.api.scanCommit(payload);
    this.api.listenForCompletion({ 
      jobId: job.data.jobId, 
      commitHash: payload.commitHash, 
      mode: "commit" 
    });
    return {
      success: true,
      data: {
        jobId: job.data.jobId,
        status: job.data.status,
      },
    } as ScanInitResponse;
  }

  /**
   * 
   * @param jobId - The job ID of the scan to get.
   * @returns The completed scan results.
   */
  async getCompletedCommitScan(jobId: string): Promise<ScanApiJobResponse> {
    return this.api.getScanFromApi(jobId);
  }
}
