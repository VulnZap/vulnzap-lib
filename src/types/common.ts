export interface ApiResponse<T> {
  data: T;
  status: number;
  message?: string;
}

/**
 * The mode of the scan.
 */
export type ScanMode = "repo" | "commit";