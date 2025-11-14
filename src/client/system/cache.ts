import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs/promises';
import type { ScanCacheEntry } from '../../types/scan';
import type { ScanMode as ScanType } from '../../types/common';

/**
 * Cache system for the Vulnzap client. Saves the ongoing scan jobs in the cache.
 * For commit scans: stores in ~/.vulnzap/client/scans/{repository}/commits/{commitHash}.json
 * For repo scans: stores in ~/.vulnzap/client/scans/{repository}/full/{jobid}.json
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
  private getCacheDirectoryForType(
    type: ScanType,
    repository: string,
  ): string {
    const repoPath = repository.replace('/', '_');
    if (type === 'commit') {
      return path.join(this.cacheDirectory, 'scans', repoPath, 'commits');
    } else {
      return path.join(this.cacheDirectory, 'scans', repoPath, 'full');
    }
  }

  /**
   * Ensures the cache directory exists, creating it if necessary.
   * @param type - The type of scan (commit or repo)
   */
  private async ensureDirectory(
    type: ScanType,
    repository: string,
  ): Promise<void> {
    const dir = this.getCacheDirectoryForType(type, repository);
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
  private getFilePath(
    type: ScanType,
    repository: string,
    identifier: string,
  ): string {
    const dir = this.getCacheDirectoryForType(type, repository);
    return path.join(dir, `${identifier}.json`);
  }

  /**
   * Saves data to the cache with the given type and commitHash.
   * @param type - The type of scan (commit or repo)
   * @param repository - The repository name
   * @param identifier - The commit hash or job ID to use as the file name
   * @param data - The data to cache (must match ScanCacheEntry format)
   */
  async save(
    type: ScanType,
    repository: string,
    identifier: string,
    data: ScanCacheEntry,
  ): Promise<void> {
    await this.ensureDirectory(type, repository);
    const filePath = this.getFilePath(type, repository, identifier);
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf-8');
  }

  /**
   * Reads cached data for a specific type and commitHash.
   * @param type - The type of scan (commit or repo)
   * @param repository - The repository name
   * @param identifier - The commit hash or job ID
   * @returns The cached data or null if not found
   */
  async get(
    type: ScanType,
    repository: string,
    identifier: string,
  ): Promise<ScanCacheEntry | null> {
    try {
      await this.ensureDirectory(type, repository);
      const filePath = this.getFilePath(type, repository, identifier);
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
        const scansDir = path.join(this.cacheDirectory, 'scans');
        const repoDirs = await fs.readdir(scansDir);

        for (const repoDir of repoDirs) {
          const dir = path.join(scansDir, repoDir, type === 'commit' ? 'commits' : 'full');
          try {
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
            // Ignore if the sub-directory doesn't exist
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
  async clear(
    type: ScanType,
    repository: string,
    identifier: string,
  ): Promise<void> {
    try {
      await this.ensureDirectory(type, repository);
      const filePath = this.getFilePath(type, repository, identifier);
      await fs.unlink(filePath);
    } catch {
      // Ignore errors when clearing
    }
  }

  /**
   * Gets the latest commit scan from the cache.
   * @returns The latest cached commit scan data or null if not found.
   */
  async getLatestCommitScan(
    repository: string,
  ): Promise<ScanCacheEntry | null> {
    try {
      const dir = this.getCacheDirectoryForType('commit', repository);
      await this.ensureDirectory('commit', repository);
      const files = (await fs.readdir(dir)).filter(f => f.endsWith('.json'));

      if (files.length === 0) {
        return null;
      }

      const fileStats = await Promise.all(
        files.map(async (file) => {
          const filePath = path.join(dir, file);
          const stats = await fs.stat(filePath);
          return { filePath, mtime: stats.mtime };
        })
      );

      fileStats.sort((a, b) => b.mtime.getTime() - a.mtime.getTime());

      const latestFile = fileStats[0];

      if (!latestFile) {
        return null;
      }

      const content = await fs.readFile(latestFile.filePath, 'utf-8');
      return JSON.parse(content) as ScanCacheEntry;
    } catch (error) {
      console.error(
        `Error getting latest commit scan for repository ${repository}: ${error}`,
      );
      return null;
    }
  }
}