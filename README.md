# Vulnzap JavaScript/TypeScript Client Library

Official client for integrating with the Vulnzap vulnerability scanning service from Node.js or the browser. Provides a simple API to submit scans and receive real-time updates via Server-Sent Events (SSE).

## Features

- **Commit and repository scanning**: Scan individual commits or full repositories for vulnerabilities
- **Real-time incremental scanning**: Security assistant mode for AI coding agents with live file monitoring
- **Event-driven updates**: Listen for `update`, `completed`, and `error` events via SSE
- **TypeScript support**: Fully typed API with comprehensive type definitions
- **Local caching**: Stores scan results locally for faster access and offline use
- **Session management**: Track incremental scans with persistent session state

## Installation

```bash
npm install @vulnzap/client
```

## Requirements

- Node.js 18+
- Vulnzap API key

Set your API key as an environment variable:

```bash
export VULNZAP_API_KEY=your_api_key_here
```

## Quick Start

```typescript
import { VulnzapClient } from "@vulnzap/client";

const client = new VulnzapClient({ 
  apiKey: process.env.VULNZAP_API_KEY! 
});

client.on("update", (evt) => {
  console.log("Scan progress:", evt);
});

client.on("completed", (evt) => {
  console.log("Scan completed:", evt);
});

client.on("error", (err) => {
  console.error("Scan error:", err);
});

await client.scanCommit({
  commitHash: "abc123",
  repository: "owner/repo",
  branch: "main",
  files: [
    { path: "src/app.js", content: "console.log('hello');" },
  ],
  userIdentifier: "user@example.com",
});
```

## API Reference

### VulnzapClient

#### Constructor

```typescript
new VulnzapClient(options: { apiKey: string; baseUrl?: string })
```

**Parameters:**
- `apiKey`: Your Vulnzap API key
- `baseUrl`: Optional custom API base URL (defaults to `https://engine.vulnzap.com`)

#### Methods

##### scanCommit

```typescript
scanCommit(payload: CommitScanPayload): Promise<ScanInitResponse>
```

Initiates a vulnerability scan for a commit. Automatically attaches an SSE listener for real-time updates.

**Parameters:**
```typescript
{
  commitHash: string;
  repository: string;
  branch?: string;
  files: Array<{ path: string; content: string }>;
  userIdentifier: string;
}
```

**Returns:** `Promise<{ success: boolean; data: { jobId: string; status: string } }>`

##### scanRepository

```typescript
scanRepository(payload: RepositoryScanPayload): Promise<ScanInitResponse>
```

Initiates a full repository scan. Automatically attaches an SSE listener for real-time updates.

**Parameters:**
```typescript
{
  repository: string;
  branch?: string;
  userIdentifier: string;
}
```

**Returns:** `Promise<{ success: boolean; data: { jobId: string; status: string } }>`

##### securityAssistant

```typescript
securityAssistant({
  sessionId: "23e23",
  dirPath: "sdknksdn",
  timeout: 60000,
}): boolean
```

Starts a security assistant session that monitors a directory for file changes and performs incremental scans. Designed for AI coding agents to provide real-time security feedback during development.

**Parameters:**
- `dirPath`: Directory to monitor
- `sessionId`: Unique session identifier
- `timeout`: The timeout after which watcher will stop if no changes are made.

**Returns:** `true` if watcher started successfully, `false` otherwise, errors are emitted which can be received via `client.on("error", ...)`

**Behavior:**
- Watches directory recursively for file changes
- Excludes `node_modules`, `.git`, `.md`, `.DS_Store`, and `.lock` files
- Tracks whether files are new or modified
- Automatically closes session after the timeout provided
- Sends incremental scan requests to backend with context

**Example:**
```typescript
const sessionId = "session_" + Date.now();
client.securityAssistant("./src", sessionId);

// Later, fetch results
const results = await client.getIncrementalScanResults(sessionId);
```

##### getIncrementalScanResults

```typescript
getIncrementalScanResults(sessionId: string): Promise<IncrementalScanResponse>
```

Retrieves incremental scan results for a security assistant session.

**Returns:**
```typescript
{
  success: boolean;
  data: {
    jobId: string;
    status: string;
    findings: any[];
  };
  error?: string;
}
```

##### getLatestCachedCommitScan

```typescript
getLatestCachedCommitScan(repository: string): Promise<ScanCacheEntry | null>
```

Retrieves the most recent commit scan from local cache for the specified repository.

##### getCompletedCommitScan

```typescript
getCompletedCommitScan(jobId: string): Promise<ScanApiJobResponse>
```

Retrieves completed scan results from the Vulnzap API for a given job ID.

#### Events

The client emits the following events:

- **`update`**: Emitted during scan progress with status updates
- **`completed`**: Emitted when scan finishes with final results
- **`error`**: Emitted on errors during scanning or SSE connection

**Event Types:**

```typescript
type ScanUpdateEvent = {
  jobId: string;
  status: "queued" | "scanning" | "analyzing" | "completed";
  progress?: number;
};

type ScanCompletedEvent = {
  jobId: string;
  status: "completed";
  findings: Array<{
    file: string;
    line: number;
    severity: "low" | "medium" | "high" | "critical";
    message: string;
  }>;
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
};
```

## Caching System

The client includes a local caching system that stores scan results in the user's home directory:

- **Commit scans**: `~/.vulnzap/client/scans/{repository}/commits/{commitHash}.json`
- **Repository scans**: `~/.vulnzap/client/scans/{repository}/full/{jobId}.json`
- **Sessions**: `~/.vulnzap/client/sessions/{sessionId}.json`

Repository names are sanitized by replacing `/` with `_` for filesystem compatibility.

## Usage Examples

### Basic Commit Scan

```typescript
const client = new VulnzapClient({ apiKey: process.env.VULNZAP_API_KEY! });

client.on("completed", (result) => {
  console.log(`Found ${result.summary.totalFindings} issues`);
  result.findings.forEach(finding => {
    console.log(`${finding.severity}: ${finding.message} at ${finding.file}:${finding.line}`);
  });
});

await client.scanCommit({
  commitHash: "abc123",
  repository: "owner/repo",
  files: [{ path: "index.js", content: "/* code */" }],
  userIdentifier: "user@example.com",
});
```

### Repository Scan

```typescript
await client.scanRepository({
  repository: "owner/repo",
  branch: "main",
  userIdentifier: "user@example.com",
});
```

### Security Assistant for AI Agents

```typescript
const client = new VulnzapClient({ apiKey: process.env.VULNZAP_API_KEY! });
const sessionId = `agent_${Date.now()}`;

// Start monitoring
client.securityAssistant("./src", sessionId);

// Agent makes changes to files...
// Changes are automatically scanned incrementally

// Fetch results when needed
const results = await client.getIncrementalScanResults(sessionId);
if (results.success) {
  console.log("Findings:", results.data.findings);
}
```

### Custom API Base URL

```typescript
const client = new VulnzapClient({
  apiKey: process.env.VULNZAP_API_KEY!,
  baseUrl: "https://custom.vulnzap.com",
});
```

### Error Handling

```typescript
client.on("error", (errorEvent) => {
  console.error("Scan error:", errorEvent.message);
  // Implement retry logic or alerting
});
```

### Accessing Cached Results

```typescript
const latestScan = await client.getLatestCachedCommitScan("owner/repo");
if (latestScan) {
  console.log("Cached scan from:", new Date(latestScan.timestamp));
  console.log("Results:", latestScan.results);
}
```

## TypeScript

The library ships with complete TypeScript definitions. All types are exported from the main package:

```typescript
import { 
  VulnzapClient,
  CommitScanPayload,
  ScanCompletedEvent,
  ScanUpdateEvent,
  IncrementalScanResponse
} from "@vulnzap/client";
```

## License

MIT
