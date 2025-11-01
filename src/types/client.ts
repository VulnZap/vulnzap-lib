export interface VulnzapClientOptions {
   /**
    * Your Vulnzap API key from the Vulnzap dashboard.
    * @see https://vulnzap.com/dashboard/api-keys
    */
  apiKey: string;

  /**
   * Optional custom API base URL (defaults to Vulnzap cloud).
   * @default https://engine.vulnzap.com
   */
  baseUrl?: string;
}