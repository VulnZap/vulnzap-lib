import axios from "axios";
import type {
    CommitScanPayload,
    ScanInitResponse,
    ScanCompletedEvent,
    ScanUpdateEvent,
    ScanCacheEntry,
    ScanApiJobResponse,
    ListenerOptions,
    RepositoryScanPayload,
} from "../types/scan";
import { EventEmitter } from "events";
import { VulnzapCache } from "./system/cache";

/**
 * Handles all direct API interactions with the Vulnzap backend.
 * Keeps VulnzapClient class free from API logic.
 */
export class VulnzapAPI extends EventEmitter {
    /**
     * Your Vulnzap API key from the Vulnzap dashboard.
     * @see https://vulnzap.com/dashboard/api-keys
     */
    private apiKey: string;
    /**
     * The base URL of the Vulnzap API.
     * @default https://engine.vulnzap.com
     */
    private baseUrl: string;

    /**
     * The cache system for the Vulnzap API.
     */
    private cache: VulnzapCache;

    /**
     * Create a new VulnzapAPI instance.
     * @param apiKey - Your Vulnzap API key.
     * @param baseUrl - The base URL of the Vulnzap API.
     */
    constructor(apiKey: string, baseUrl: string) {
        super();
        this.cache = new VulnzapCache();
        this.apiKey = apiKey;
        this.baseUrl = baseUrl;
    }

    /**
     * Send a new scan request to the Vulnzap API.
     * @param payload - Details of the commit and files to scan.
     * @returns A promise resolving to the scan initiation result with job ID and status.
     */
    async scanCommit(payload: CommitScanPayload): Promise<ScanInitResponse> {
        const response = await axios.post<ScanInitResponse>(
            `${this.baseUrl}/api/scan/commit`,
            payload,
            {
                headers: {
                    "x-api-key": this.apiKey,
                    "Content-Type": "application/json",
                },
            }
        );
        if (response.status !== 200) {
            throw new Error(`Failed to scan commit: ${response.statusText}`);
        }
        const { jobId, status } = response.data.data;
        if (!jobId) {
            throw new Error("Invalid response from API");
        }
        // save the scan to the cache
        await this.cache.save("commit", payload.commitHash, {
            jobId: jobId,
            timestamp: Date.now(),
            status: status,
            resolved: false,
            resolved_timestamp: 0,
            repository: payload.repository || "",
            branch: payload.branch || "",
            results: {},
        });
        return {
            success: true,
            data: {
                jobId: jobId,
                status: status,
            },
        } as ScanInitResponse;
    }

    async scanRepository(payload: RepositoryScanPayload): Promise<ScanInitResponse> {
        const response = await axios.post<ScanInitResponse>(
            `${this.baseUrl}/api/scan/github`,
            payload,
            {
                headers: {
                    "x-api-key": this.apiKey,
                    "Content-Type": "application/json",
                },
            }
        );
        if (response.status !== 200) {
            throw new Error(`Failed to scan repository: ${response.statusText}`);
        }
        const { jobId, status } = response.data.data;
        if (!jobId) {
            throw new Error("Invalid response from API");
        }
        // save the scan to the cache
        await this.cache.save("repo", payload.repository, {
            jobId: jobId,
            timestamp: Date.now(),
            status: status,
            resolved: false,
            resolved_timestamp: 0,
            repository: payload.repository,
            branch: "",
            results: null,
        });
        return {
            success: true,
            data: {
                jobId: jobId,
                status: status,
            },
        } as ScanInitResponse;
    }

    async getScanFromApi(jobId: string): Promise<ScanApiJobResponse> {
        const response = await axios.get<{
            success: boolean;
            data: ScanApiJobResponse;
        }>(`${this.baseUrl}/api/scan/jobs/${jobId}`, {
            headers: {
                "x-api-key": this.apiKey,
            },
        });
        if (response.status !== 200) {
            throw new Error(
                `Failed to get scan from API: ${response.statusText}`
            );
        }
        if (!response.data.data.jobId) {
            throw new Error("Invalid response from API");
        }
        return response.data.data;
    }

    /**
     * Listen for completion of a scan job using Server-Sent Events (SSE).
     * Emits "update", "completed", and "error" events.
     * @param options - The options for the listener.
     * @param options.jobId - The ID of the scan job to listen for.
     * @param options.commitHash - The commit hash of the scan to listen for.
     */
    async listenForCompletion(options: ListenerOptions): Promise<void> {
        let sseUrl = "";
        const { jobId, commitHash, mode } = options;

        if (mode === "repo") {
            if (!jobId) {
                throw new Error("Job ID is required for repo mode");
            }
            sseUrl = `${this.baseUrl}/api/scan/github/${jobId}/events`;
        } else if (mode === "commit") {
            if (!commitHash) {
                throw new Error("Commit hash is required for commit mode");
            }
            sseUrl = `${this.baseUrl}/api/scan/commit/${jobId}/events`;
        }

        if (!sseUrl) {
            throw new Error(
                "No job ID or commit hash provided, cannot listen for completion"
            );
        }

        try {
            const response = await fetch(sseUrl, {
                method: "GET",
                headers: {
                    "x-api-key": this.apiKey,
                    Accept: "text/event-stream",
                    "Cache-Control": "no-cache",
                },
            });

            if (!response.ok) {
                const responseText = await response.text();
                throw new Error(
                    `Failed to connect to event stream: ${response.status} - ${responseText}`
                );
            }

            const reader = response.body?.getReader();
            if (!reader) {
                throw new Error("Failed to get response reader");
            }

            const decoder = new TextDecoder();
            let buffer = "";

            try {
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) {
                        break;
                    }
                    const chunk = decoder.decode(value, { stream: true });
                    buffer += chunk;

                    const lines = buffer.split("\n");
                    buffer = lines.pop() || "";
                    for (const line of lines) {
                        if (line.startsWith("data: ")) {
                            try {
                                const eventData = JSON.parse(line.slice(6));

                                if (eventData.scanId && !eventData.jobId) {
                                    eventData.jobId = eventData.scanId;
                                    delete eventData.scanId;
                                }
                                if (eventData.type === "completed") {
                                    this.emit(
                                        "completed",
                                        eventData as ScanCompletedEvent
                                    );
                                    const scanJobId = jobId || eventData.jobId;
                                    if (scanJobId) {
                                        const scan = await this.getScanFromApi(
                                            scanJobId
                                        );
                                        const cacheKey =
                                            mode === "commit"
                                                ? commitHash!
                                                : scan.commitHash;
                                        const cacheEntry = await this.cache.get(
                                            mode,
                                            cacheKey
                                        );

                                        await this.cache.save(mode, cacheKey, {
                                            jobId: scan.jobId,
                                            timestamp: Date.now(),
                                            status: scan.status,
                                            resolved: true,
                                            resolved_timestamp: Date.now(),
                                            repository:
                                                cacheEntry?.repository || "",
                                            branch: cacheEntry?.branch || "",
                                            results: scan.results,
                                        });
                                    }
                                    reader.cancel();
                                    return;
                                } else if (eventData.type === "progress" || eventData.type === "connected") {
                                    this.emit(
                                        "update",
                                        eventData as ScanUpdateEvent
                                    );
                                } else if (eventData.type === "error") {
                                    this.emit("error", {
                                        jobId: jobId || "unknown",
                                        message: eventData.message,
                                        error: eventData.error,
                                    });
                                } else {
                                    this.emit("error", {
                                        jobId: jobId || "unknown",
                                        message: "Unknown event type",
                                        error: eventData,
                                    });
                                }
                            } catch (parseError) {
                                this.emit("error", {
                                    jobId: jobId || "unknown",
                                    message: "Failed to parse SSE data",
                                    error: parseError,
                                });
                            }
                        }
                    }
                }
            } finally {
                reader.releaseLock();
            }
        } catch (error) {
            this.emit("error", {
                jobId: jobId || "unknown",
                message: "SSE connection error",
                error: error,
            });
        }
    }
}
