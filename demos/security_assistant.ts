import { VulnzapClient } from "../src/client/VulnzapClient";
import * as fs from "fs";
import * as path from "path";

async function runTest() {
    const client = new VulnzapClient({ apiKey: "dummy", baseUrl: "http://localhost:3001" });
    const testDir = path.join(__dirname, "security_assistant");
    const sessionId = "session_1";

    if (!fs.existsSync(testDir)) {
        fs.mkdirSync(testDir);
    }

    console.log("Starting security assistant...");
    const started = client.securityAssistant({
        sessionId: sessionId,
        dirPath: testDir,
        timeout: 60000,
    });
    console.log("Watcher started:", started);

    console.log("Creating a file...");
    fs.writeFileSync(path.join(testDir, "test.txt"), "hello world");

    // Wait for watcher to pick up change
    console.log("Waiting for watcher...");
    await new Promise(resolve => setTimeout(resolve, 2000));

    console.log("Fetching incremental results (expecting network error)...");
    try {
        const e = await client.getIncrementalScanResults(sessionId);
        console.log("Incremental results:", e);
    } catch (e) {
        console.log("Caught expected error:", (e as any).message);
    }

    // Clean up
    fs.rmSync(testDir, { recursive: true, force: true });
    console.log("Test completed.");
}

runTest().catch(console.error);
