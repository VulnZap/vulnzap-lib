import type {
  ScanCompletedEvent,
  ScanErrorEvent,
  ScanUpdateEvent,
} from "../types/scan";

/**
 * Type-safe event map for all VulnzapClient events.
 */
export interface VulnzapEvents {
  /**
   * Event emitted when the scan is updated (Has some progress, or is completed).
   */
  update: (data: ScanUpdateEvent) => void;
  /**
   * Event emitted when the scan is completed.
   * This event is emitted when the scan is completed successfully.
   * Hit the getScanResult API to get the scan results.
   */
  completed: (data: ScanCompletedEvent) => void;
  /**
   * Event emitted when an error occurs during the scan.
   * This can happen when the scan is not found, or when the scan is not completed.
   */
  error: (data: ScanErrorEvent) => void;
}
