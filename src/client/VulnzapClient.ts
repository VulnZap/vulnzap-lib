import { VulnzapAPI } from "./api";
import type { VulnzapEvents } from "./eventTypes";
import type {
  CommitScanPayload,
  RepositoryScanPayload,
  ScanInitResponse,
  ScanApiJobResponse,
  ScanCacheEntry,
  IncrementalScanResponse,
  ScanEvent,
} from "../types/scan";
import * as fs from "fs";
import * as path from "path";
import { EventEmitter } from "events";
import type { SecurityAssistantOptions, VulnzapClientOptions } from "../types/client";
import { VulnzapCache } from "./system/cache";

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
  private cache: VulnzapCache;

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
    this.cache = new VulnzapCache();

    // Forward events from API to client
    this.api.on("completed", (data: ScanEvent) => {
      this.emit("completed", data);
    });

    this.api.on("update", (data: ScanEvent) => {
      this.emit("update", data);
    });

    this.api.on("error", (error: ScanEvent) => {
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
 *   commitHash: "abc123",
 *   repository: "owner/repo",
 *   branch: "main",
 *   files: [{ name: "src/app.js", content: "console.log('hi');" }],
 * });
 * console.log(result.jobId);
 * ```
   */
  async scanCommit(
    payload: CommitScanPayload
  ): Promise<ScanInitResponse> {
    const job = await this.api.scanCommit(payload);
    this.api.listenForCompletion({
      jobId: job.data.jobId,
      commitHash: payload.commitHash,
      repository: payload.repository!,
      branch: payload.branch || "",
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
   * Scan a repository for vulnerabilities.
   * @param payload - The repository details to scan.
   * @returns A promise resolving to the scan initiation result with job ID and status.
   */
  async scanRepository(
    payload: RepositoryScanPayload
  ): Promise<ScanInitResponse> {
    const job = await this.api.scanRepository(payload);
    this.api.listenForCompletion({
      jobId: job.data.jobId,
      commitHash: "",
      repository: payload.repository,
      branch: payload.branch || "",
      mode: "repo"
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

  /**
   * Gets the latest commit scan from the cache.
   * @returns The latest cached commit scan data or null if not found.
   */
  async getLatestCachedCommitScan(repository: string): Promise<ScanCacheEntry | null> {
    return this.cache.getLatestCommitScan(repository);
  }

  /**
   * Starts a security assistant session that watches a directory for changes and incrementally scans them.
   * @param dirPath - The directory to watch.
   * @param sessionId - The session ID.
   * @returns True if the watcher started successfully.
   */
  securityAssistant(options: SecurityAssistantOptions): boolean {
    if (!fs.existsSync(options.dirPath)) {
      return false;
    }

    // verify timeout is a number and withing 10000 to 600000
    if (typeof options.timeout !== "number" || options.timeout < 10000 || options.timeout > 600000) {
      return false;
    }

    let timeout: NodeJS.Timeout;
    const resetTimeout = () => {
      if (timeout) clearTimeout(timeout);
      timeout = setTimeout(() => {
        watcher.close();
        console.log(`Security agent session ${options.sessionId} closed due to inactivity.`);
      }, options.timeout);
    };

    const watcher = fs.watch(options.dirPath, { recursive: true }, async (eventType, filename) => {
      if (filename &&
        !filename.includes("node_modules") &&
        !filename.includes(".git") &&
        !filename.includes(".md") &&
        !filename.includes(".DS_Store") &&
        !filename.includes(".lock")
      ) {
        resetTimeout();
        const filePath = path.join(options.dirPath, filename);

        try {
          const stats = await fs.promises.stat(filePath);
          if (stats.isFile()) {
            const content = await fs.promises.readFile(filePath, "utf-8");

            // Get session to check if file was previously tracked
            const session = await this.cache.getSession(options.sessionId) || {
              sessionId: options.sessionId,
              path: options.dirPath,
              timestamp: Date.now(),
              files: []
            };

            // Determine if file is changed (exists in session) or new
            const isChanged = session.files.includes(filename) || !session.files.includes(filename);

            // Send to backend
            try {
              await this.api.scanIncremental({
                sessionId: options.sessionId,
                files: [{ path: filename, content, changed: isChanged }],
              });

              // Update session cache
              if (!isChanged) {
                session.files.push(filename);
                await this.cache.saveSession(options.sessionId, session);
              }
            } catch (error) {
              console.error(`Failed to scan incremental change for ${filename}:`, error);
            }
          }
        } catch (err) {
          // File might have been deleted or is inaccessible
        }
      }
    });

    resetTimeout();
    return true;
  }

  /**
   * Gets the incremental scan results for a session.
   * @param sessionId - The session ID.
   * @returns The incremental scan results.
   */
  async getIncrementalScanResults(sessionId: string): Promise<IncrementalScanResponse> {
    return this.api.getIncrementalScanResults(sessionId);
  }
}
