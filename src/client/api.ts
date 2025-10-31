import axios from "axios";
import type { ScanPayload, ScanInitResponse } from "../types/scan";

/**
 * Handles all direct API interactions with the Vulnzap backend.
 * Keeps VulnzapClient class free from API logic.
 */
export class VulnzapAPI {
  private apiKey: string;
  private baseUrl: string;

  constructor(apiKey: string, baseUrl: string) {
    this.apiKey = apiKey;
    this.baseUrl = baseUrl;
  }

  /**
   * Send a new scan request to the Vulnzap API.
   * @param payload - Details of the commit and files to scan.
   */
  async scanCommit(payload: ScanPayload): Promise<ScanInitResponse> {
    const response = await axios.post<ScanInitResponse>(
      `${this.baseUrl}/scan`,
      payload,
      {
        headers: { Authorization: `Bearer ${this.apiKey}` },
      }
    );
    return response.data;
  }
}
