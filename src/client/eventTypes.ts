import type {
  ScanCompletedEvent,
  ScanErrorEvent,
  ScanUpdateEvent,
} from "../types/scan";

/**
 * Type-safe event map for all VulnzapClient events.
 */
export interface VulnzapEvents {
  update: (data: ScanUpdateEvent) => void;
  completed: (data: ScanCompletedEvent) => void;
  error: (data: ScanErrorEvent) => void;
}
