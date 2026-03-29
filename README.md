# apidiff

**Semantic API Diff** — A behavioral diffing tool for APIs that detects semantic regressions, not just schema changes.

Existing tools (like OpenAPI, Swagger, or `oasdiff`) only catch structural or schema changes (e.g. "Did this field get deleted?"). `apidiff` analyzes **real experimental API traffic** to detect invisible behavioral drift.

For example, `apidiff` will fail your CI/CD pipeline if:
* A status field renames its output from `"active"` to `"enabled"`.
* A safe endpoint loses its idempotency and starts duplicating records.
* A field suddenly stops appearing for premium users (conditional rules broken).
* Value distributions completely flip (e.g., a status goes from 90% "active" to 10% "active").
* Network latency violently spikes on specific endpoints.

---

## 🚀 How to Use It (Step-by-Step for Developers)

The easiest way to use `apidiff` is to provide it with two files containing your API's traffic in `.har` format representing your "V1" (Standard) API, and your "V2" (New/Candidate) API. 

### Step 1: Get Your API Traffic (Capture phase)
If you don't already have standard `.har` (HTTP Archive) files, you can use the built-in `capture` tool to generate them:

**Replay Mode (Great for Automated pipelines):**
Replay a seed HAR file of tests against your target URLs (auth headers are parsed and stripped):
```bash
apidiff capture --mode replay --seed tests.har --target https://api.v1.com --out v1_traffic.har
apidiff capture --mode replay --seed tests.har --target https://api.v2.com --out v2_traffic.har
```

**Proxy Mode (Great for local testing):**
Intercept live traffic (e.g., from an integration test suite) via a local mitmproxy:
```bash
# Set your HTTP client proxy to localhost:8080
apidiff capture --mode proxy --port 8080 --out traffic.har
```

### Step 2: Run the Semantic Diff
Now, manually invoke the pipeline or trigger it inside your GitHub actions against your two versions.

If your system path isn't mapped, run the raw python execution:
```bash
python -m cli.main run --v1-har v1_traffic.har --v2-har v2_traffic.har --out-dir apidiff-report
```

### Step 3: View the Dashboard Results!
Open the `apidiff-report` folder that was just created, and double-click the **`report.html`** file. 

This will open a self-contained, dependency-less web dashboard directly in your browser. You can filter, search, and see exactly which endpoints broke alongside the raw JSON showing the exact statistical evidence of the bug.

---

## 🧠 The 9 Core Detectors

`apidiff` runs nine distinct statistical engines during the diffing sequence:

1. 🛑 **Removed Endpoints** (Critical) - Previously requested endpoints vanished.
2. ✨ **Added Endpoints** (Low) - New endpoints were discovered.
3. 🔄 **Status Code Changes** (High) - e.g., an endpoint went from returning `200 OK` to `201 Created`.
4. 🏷️ **Enum Renames** (Critical) - String labels were shifted or renamed entirely.
5. 📊 **Value Distribution Shifts** (Medium) - Frequencies of values changed significantly (Calculated via Chi-squared validations).
6. 🔁 **Idempotency Broken** (Critical) - Identical GET payloads are returning varying outputs unexpectedly between versions.
7. 🔗 **Co-occurrence Invariants Broken** (High) - Historical conditional states (e.g., "Field B is present 95% of the time that Field A equals X") were violated.
8. ⏱️ **Latency Regressions** (Medium) - P99 latency spikes out of bounds.
9. ⚠️ **Error Rate Increases** (High) - Surges in unhandled 5xx server responses.

---

## 🏗️ Internal Architecture Layers

The tool operates exactly sequentially across 5 core Python layers maintaining high abstraction isolation:
1. **Capture**: Intercept traffic into standard `.har` format locally or remotely.
2. **Extractor**: Parse HARs, normalize paths (e.g., `/user/123/logs` → `/user/{id}/logs`), and build a hierarchical `RawSchema`.
3. **Fingerprint**: Compute extensive mathematical profiles (entropies, idempotency duplication arrays, metrics) into a mapped `Fingerprint`.
4. **Diff Engine**: Intercept two distinct `Fingerprints` and process them through the `detectors`.
5. **Reporter**: Render findings back into human-readable outputs (CLI tables, JSON bundles, `HTML` reports).

You can run these internal stages completely decoupled from each other natively:
```bash
apidiff extract v1.har --out schema.json
apidiff fingerprint v1.har --out v1_fingerprint.json
apidiff diff fp1.json fp2.json --out-dir report/
apidiff report report/findings.json --out final.html
```

---

## 🛠️ Installation

```bash
# Core installation
pip install apidiff

# With live proxy capture support (requires mitmproxy)
pip install "apidiff[proxy]"
```

---

## ⚙️ Automated Integration (CI/CD)

### GitHub Actions
To completely automate semantic safety nets and block broken Pull Requests, add this to your CI/CD repository pipelines:

```yaml
steps:
  - name: Run semantic diff
    run: |
      apidiff run --v1-har baseline.har --v2-har candidate.har --out-dir ./apidiff-report --fail-on high

  - name: Upload Report Dashboard
    if: always()
    uses: actions/upload-artifact@v4
    with:
      name: apidiff-report
      path: ./apidiff-report/
```

### Docker
A slim, cached Python Docker image is included natively allowing you to execute the exact same scripts completely agnostic of the user's base operating system:
```bash
docker run apidiff run --v1-har old.har --v2-har new.har ...
```

## License
MIT
