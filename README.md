# Cloud candidate monitor

This monitor tests the TLS and WebSocket handshake for an operator-controlled service on Cloudflare. Its probes carry no proxy credentials or traffic through a residential exit. Results describe the network of the GitHub-hosted runner.

The scheduled workflow checks the two active IPv4 endpoints every 30 minutes. It keeps the list when the reference probe fails or the alternatives offer no clear improvement. A repeatedly degraded endpoint can be replaced after the candidate passes two rounds of probes. Healthy peers stay in place.

The repository's `monitor-state` branch stores endpoint digests and recent timing samples. The public repository and job output contain no private target hostname, subscription address, or publish credential.

## Configuration

Set the `PREFERRED_FEED`, `PROBE_TARGET`, `PREFERRED_PUBLISH_KEY` and `CANDIDATE_SEEDS` repository secrets. Create the `monitor-state` branch. The feed serves two lines of `IPv4:port` at `/ips.txt` and accepts an authenticated `PUT` at `/api/ips`.

Run the workflow manually in `dry-run` mode to test the connection. The `MONITOR_ENABLED` repository variable enables scheduled runs when set to `true`.
