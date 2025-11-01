import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs/promises';
import type { ScanCacheEntry } from '../../types/scan';
import type { ScanMode as ScanType } from '../../types/common';

/**
 * Cache system for the Vulnzap client. Saves the ongoing scan jobs in the cache.
 * For commit scans: stores in ~/.vulnzap/client/scans/commits/{commitHash}.json
 * For repo scans: stores in ~/.vulnzap/client/scans/full/{commitHash}.json
 */
export class VulnzapCache {
  /**
   * The base directory where the cache files are saved. It defaults to HOME dir.
   */
  private cacheDirectory: string;

  constructor(cacheDirectory?: string) {
    this.cacheDirectory = cacheDirectory || path.join(os.homedir(), '.vulnzap', 'client');
  }

  /**
   * Gets the cache directory path for a specific scan type.
   * @param type - The type of scan (commit or repo)
   * @returns The path to the cache directory for that scan type
   */
  private getCacheDirectoryForType(type: ScanType): string {
    if (type === 'commit') {
      return path.join(this.cacheDirectory, 'scans', 'commits');
    } else {
      return path.join(this.cacheDirectory, 'scans', 'full');
    }
  }

  /**
   * Ensures the cache directory exists, creating it if necessary.
   * @param type - The type of scan (commit or repo)
   */
  private async ensureDirectory(type: ScanType): Promise<void> {
    const dir = this.getCacheDirectoryForType(type);
    try {
      await fs.access(dir);
    } catch {
      await fs.mkdir(dir, { recursive: true });
    }
  }

  /**
   * Gets the file path for a cache entry.
   * @param type - The type of scan (commit or repo)
   * @param commitHash - The commit hash
   * @returns The file path for the cache entry
   */
  private getFilePath(type: ScanType, commitHash: string): string {
    const dir = this.getCacheDirectoryForType(type);
    return path.join(dir, `${commitHash}.json`);
  }

  /**
   * Saves data to the cache with the given type and commitHash.
   * @param type - The type of scan (commit or repo)
   * @param commitHash - The commit hash to use as the file name
   * @param data - The data to cache (must match ScanCacheEntry format)
   */
  async save(type: ScanType, commitHash: string, data: ScanCacheEntry): Promise<void> {
    await this.ensureDirectory(type);
    const filePath = this.getFilePath(type, commitHash);
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf-8');
  }

  /**
   * Reads cached data for a specific type and commitHash.
   * @param type - The type of scan (commit or repo)
   * @param commitHash - The commit hash
   * @returns The cached data or null if not found
   */
  async get(type: ScanType, commitHash: string): Promise<ScanCacheEntry | null> {
    try {
      await this.ensureDirectory(type);
      const filePath = this.getFilePath(type, commitHash);
      const content = await fs.readFile(filePath, 'utf-8');
      return JSON.parse(content) as ScanCacheEntry;
    } catch {
      return null;
    }
  }

  /**
   * Reads cached data for a jobId (returns the most recent file for that job).
   * @deprecated Use get() instead for type-safe access
   * @param jobId - The unique identifier for the job
   * @returns The cached data or null if not found
   */
  async read(jobId: string): Promise<unknown | null> {
    // Try both commit and repo directories
    for (const type of ['commit', 'repo'] as ScanType[]) {
      try {
        await this.ensureDirectory(type);
        const dir = this.getCacheDirectoryForType(type);
        const files = await fs.readdir(dir);
        
        for (const file of files) {
          if (file.endsWith('.json')) {
            const filePath = path.join(dir, file);
            const content = await fs.readFile(filePath, 'utf-8');
            const entry = JSON.parse(content) as ScanCacheEntry;
            if (entry.jobId === jobId) {
              return entry;
            }
          }
        }
      } catch {
        // Continue to next type
      }
    }
    return null;
  }

  /**
   * Clears cached file for a specific type and commitHash.
   * @param type - The type of scan (commit or repo)
   * @param commitHash - The commit hash
   */
  async clear(type: ScanType, commitHash: string): Promise<void> {
    try {
      await this.ensureDirectory(type);
      const filePath = this.getFilePath(type, commitHash);
      await fs.unlink(filePath);
    } catch {
      // Ignore errors when clearing
    }
  }
}