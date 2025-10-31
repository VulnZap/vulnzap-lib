import { VulnzapAPI } from "./api";
import type { VulnzapEvents } from "./eventTypes";
import type {
  ScanPayload,
  ScanCompletedEvent,
  ScanUpdateEvent,
} from "../types/scan";
import { EventEmitter } from "events";

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
 * const client = new VulnzapClient({ apiKey: process.env.VULNZAP_API_KEY! });
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
  constructor(options: { apiKey: string; baseUrl?: string }) {
    super();
    this.api = new VulnzapAPI(
      options.apiKey,
      options.baseUrl || "https://api.vulnzap.com"
    );
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
  ): Promise<{ jobId: string; status: string }> {
    const job = await this.api.scanCommit(payload);
    this.listenForCompletion(job.jobId);
    return job;
  }

  /**
   * Listen for completion of a scan job using Server-Sent Events (SSE).
   * Emits "update", "completed", and "error" events.
   * @param jobId - The ID of the scan job to listen for.
   */
  private listenForCompletion(jobId: string): void {
    const sseUrl = `${this.api["baseUrl"]}/events/${jobId}`;
    const eventSource = new EventSource(sseUrl);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.status === "completed") {
          this.emit("completed", data as ScanCompletedEvent);
          eventSource.close();
        } else {
          this.emit("update", data as ScanUpdateEvent);
        }
      } catch (err) {
        this.emit("error", {
          jobId,
          message: "Failed to parse SSE data",
          error: err,
        });
      }
    };

    eventSource.onerror = (err) => {
      this.emit("error", {
        jobId,
        message: "SSE connection error",
        error: err,
      });
      eventSource.close();
    };
  }
}
