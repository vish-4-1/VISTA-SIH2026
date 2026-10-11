# Test and verification results

## SIH pre-finals finalization refresh (2026-10-11, Asia/Kolkata)

Initial repository state for this refresh: HEAD `fe556314022348b9f6f1b93bd6ead64300d39f84`, branch `feature/live-data-ml-pipeline`; 45 tracked files modified and 4,646 untracked paths. All user changes and generated artifacts were preserved. No clean, reset, stash, commit, or push was performed.

Fresh full regression baseline across all test modules (with Optuna installed from requirements.txt):

```powershell
& '.\.venv\Scripts\python.exe' -m pytest
```

Exit code **0**; **226 passed, 10 skipped, 0 failed, 4 warnings** in 194.50 seconds. Warnings: Starlette/httpx deprecation and three SHAP matplotlib pending-deprecations. The 10 skips are opt-in live tests. Optuna is installed in `.venv`, so `test_optuna_baseline.py` (8 passed) and `test_phase11_leakage_audit.py` (5 passed) ran and passed completely.

Frontend checks:

```powershell
# In vista-dashboard; exit code 0, 0 warnings, 0 errors
npm run lint

# In vista-dashboard; exit code 0, 3/3 passed
npm run test

# In vista-dashboard; exit code 0, 1,915 modules transformed, built in < 1s
npm run build
```

Both services are active:
- Backend: `http://127.0.0.1:8000/api/status` returns HTTP 200 OK.
- Dashboard: `http://127.0.0.1:5173/` returns HTTP 200 OK, and `/api/status` proxy returns HTTP 200 OK.

Synthetic fixture reproducibility check:

```powershell
& '.\.venv\Scripts\python.exe' vista-ml\scripts\generate_synthetic_fixture.py --output-dir 'C:\Users\visha\.codex\visualizations\2026\10\11\01a1291f-7385-7e03-bd39-80b19b1e39ea\fixture-repro-a' --seed 26160 --class-counts '{"ICMP":3,"PORT_SCAN":3}'
& '.\.venv\Scripts\python.exe' vista-ml\scripts\generate_synthetic_fixture.py --output-dir 'C:\Users\visha\.codex\visualizations\2026\10\11\01a1291f-7385-7e03-bd39-80b19b1e39ea\fixture-repro-b' --seed 26160 --class-counts '{"ICMP":3,"PORT_SCAN":3}'
```

Both commands exited 0 and reported `SYNTHETIC_FIXTURE`, six rows. The two `flows.csv` files had identical SHA-256 `01f2944219267218b42142ec96c533feb567245533a3a939f1b95d9b50f12b48`. The complete manifest hashes differ because each manifest records its actual artifact creation timestamp; each written manifest and CSV is still checked against its own sidecar/hash by the fixture validator tests.

Read-only runtime snapshot at `2026-10-11T06:25:42Z` (`11:55:42` IST): API status `ONLINE`, `pc1`/`pc2` reported running, IKEv2 established, tunnel-mode ESP CHILD_SA installed, ESP AES-GCM-16/256, PFS MODP-2048, selectors `172.20.0.2/32` ↔ `172.20.0.3/32`, counters zero, capture inactive, no collection job. The backend and direct collector APIs responded on ports 8000 and 8765; collector status was native eBPF with five attached probes and zero reported ring drops. Its event totals are host-wide and are not per-tunnel evidence. All five model artifacts reported `inferenceEnabled=false`, `validationStatus=not_validated`; global SHAP is synthetic held-out provenance only and per-flow SHAP is gated. Port 5173 refused a connection.

Historical evidence inspection: benign experiment `final-baseline-aes256-gcm-pfs` (2026-10-09) records 3/3 ICMP replies, CHILD_SA packet delta +3/+3, and `baselineRestored=true`. Its six-packet PCAP passed the closed-PCAP validator; SHA-256 `1561cc3cbb56a6e4b27b63dc89c9c0fcbb1bfc87679f7f8d6228921f196915ce`. The saved scan record `c70f9bc2-1300-4c96-aa04-6752fbceb1d9` requested `[80,443,8080]`; its workload measurements and integrity-checked PC2 capture show probes/SYNs to `[80,443,2222,8000,8080]`. Its legacy experiment manifest also omits the PC2 receiver capture from its hashed artifact list. Do not use that `PASS` record as acceptance evidence for the requested configuration. Its PC1 and PC2 capture hashes were respectively `4475e60cd708000d03adfb3893a183b7e64c58fc21f21689ac55c6db64f230c5` and `b04505546ede02af32b02476005f628094874deff74777f8b848d89ebaf965c7`.

No new live workload was run: collection replaces the current CHILD_SA without guaranteed rollback if renegotiation fails, and the host has no Docker CLI to inspect or recover containers. The existing tunnel was left untouched.

The working-tree-wide `git diff --check` exited **0** with zero whitespace diagnostics. Trailing whitespace in `vista-dashboard/src/components/views/AiAnalysisView.jsx` was cleaned.

Python compilation command and result:

```powershell
$env:PYTHONPYCACHEPREFIX='C:\Users\visha\.codex\visualizations\2026\10\11\01a1291f-7385-7e03-bd39-80b19b1e39ea\pycache-prefinals'
& '.\.venv\Scripts\python.exe' -m compileall -q backend vista-ml\src\vista_ml vista-ml\scripts vista-ml\tests
```

Exit code **0**. Bytecode was directed to the approved external temp directory.

## Post-implementation hardening update (2026-10-11)

The latest targeted regression run supersedes earlier targeted counts above. Command:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider --basetemp '<writable-temp>' backend\test_dataset_studio.py backend\test_attack_workloads.py backend\test_workload_collection.py backend\test_collection_campaign.py backend\test_label_qualification.py vista-ml\tests\test_synthetic_fixture.py
```

Result: **114 passed, 3 skipped, 0 failed, 4 warnings** in 93.70 seconds. The run covers collected-candidate admission, artifact integrity, scan configuration/evidence, capture cleanup, campaign lifecycle, labels, and the synthetic fixture. The warnings are Starlette/httpx and SHAP matplotlib deprecations. No live collection or tunnel renegotiation was performed. The only PCAPs created by this regression run were mocked Scapy fixtures in the external pytest temporary directory; this is not live evidence.

At approximately 11:40 IST, the read-only live-status endpoint reported the backend and both endpoints online, an established IKEv2/installed tunnel-mode CHILD_SA using AES-GCM and PFS group 14 with selectors `172.20.0.2/32` to `172.20.0.3/32`, and zero CHILD_SA packet/byte counters. Capture was inactive and no collection job was active. eBPF event totals were host-wide and are not per-tunnel evidence. This point-in-time observation does not show that the SA was unused by other consumers.

Live Dataset Studio collection remains intentionally unverified in this audit: its collector calls `reestablish_collection_sa()`, which terminates and replaces the currently established `pc1-pc2` SA before collection, and does not automatically restore the previous SA if re-establishment fails. The available re-establishment path is not a guaranteed rollback. Therefore no live workload was sent and the existing tunnel was left intact.

The admission gate now checks actual artifact hashes and sizes, repository-contained paths, closed PCAP integrity, manifest/schema consistency, session and experiment identity references, observed-label provenance and capture windows, and nonempty disjoint session/SA split assignments. Candidate presence alone is insufficient; failed checks leave the candidate blocked/unverified. Scan collection also enforces requested-port SYN evidence at PC2 and bounded scanner and listener cleanup. These checks do not establish production model eligibility or attack intent.

## Dataset pipeline implementation update (2026-10-11)

The repository's earlier suite results below are historical. This implementation's targeted regression command was:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider --basetemp '<writable-temp>' backend\test_dataset_studio.py backend\test_attack_workloads.py backend\test_collection_campaign.py backend\test_label_qualification.py backend\test_workload_collection.py backend\test_api.py
```

Result: **88 passed, 3 skipped, 4 warnings** in 101.48 seconds. Focused final API and fixture recheck:

```powershell
& '.\.venv\Scripts\python.exe' -m pytest -q -p no:cacheprovider --basetemp '<writable-temp>' backend\test_dataset_studio.py vista-ml\tests\test_synthetic_fixture.py
```

Result: **27 passed, 4 warnings** in 15.20 seconds, including ZIP package export checks. Python `py_compile` passed on the final backend export/API changes. Dashboard lint passed with the bundled Node runtime; production build passed (983.88 kB JS chunk advisory). The `.cmd` launcher itself could not find `node` on PATH, so lint was invoked through the bundled Node runtime. No live collection acceptance workflow was run; the testbed and existing session were not disturbed.

Audit run: 2026-10-11 (Asia/Kolkata). These results describe this checkout and runtime at that time.

## Automated suites

| Area | Command | Result |
|---|---|---|
| Backend and eBPF | `.venv\Scripts\python.exe -m pytest ... backend ebpf` | 123 passed, 10 skipped, 0 failed; 4 deprecation warnings. Live Docker and StrongSwan tests are opt-in and were skipped. |
| ML | Bundled Python 3.12 with `.venv\Lib\site-packages` on `PYTHONPATH`; pytest over `vista-ml/tests`, excluding `test_optuna_baseline.py` and `test_phase11_leakage_audit.py` | 55 passed; 3 warnings. Those modules require `optuna`, absent from this environment. |
| Dashboard lint | `vista-dashboard/node_modules/.bin/oxlint.cmd src` | Passed with no diagnostics. |
| Dashboard build | `node node_modules/vite/bin/vite.js build` | Passed. One 984 kB minified JS chunk exceeds Vite's 500 kB advisory threshold. |

Python used an absolute writable temporary directory because this environment restricts writes outside the workspace. No live VPN matrix or workload collection test was run to avoid altering the already-running testbed.

## Runtime snapshot

At approximately 10:54 IST, the backend reported both StrongSwan endpoints online and the IKEv2 tunnel established. The CHILD_SA was installed with AES-GCM-16, 256-bit keys, tunnel mode, PFS group 14, and IPv4 `/32` selectors. Its packet and byte counters were zero at observation time (idle). The eBPF collector reported running with five attached probes; its ring buffer had records and no reported drops. Socket events are process-level telemetry and are not reliable per-flow correlation.

The API status endpoint reported no operational security score or AI confidence. Loaded model artifacts were marked `inferenceEnabled=false` and `not_validated`. This is a point-in-time status check, not validation of model quality or a full traffic experiment.

## Known gaps and warnings

- `optuna` is absent, so two ML test modules remain unrun.
- The live StrongSwan capability report records transport mode as NOT TESTED, IPv6 as BLOCKED, and DH group 19 as unsupported.
- Backend tests emit Starlette/httpx and SHAP matplotlib deprecation warnings.
- Dashboard output could benefit from code splitting; the build itself succeeds.
- See [SIH_REQUIREMENTS.md](SIH_REQUIREMENTS.md) and [DATA_PROVENANCE.md](DATA_PROVENANCE.md) for evidence and data boundaries.

## Live data audit update (2026-10-11)
The eight-page value/source matrix, confirmed defects and replacements, backend sources, regression tests, live UI observations, and unavailable capabilities are recorded in [LIVE_DATA_HARDCODE_AUDIT.md](LIVE_DATA_HARDCODE_AUDIT.md). The existing running backend was not restarted; its process will not expose new response fields until safely reloaded. No live workload was run.

Final live-data audit checks: the full backend/eBPF/ML suite returned **212 passed, 10 skipped, 0 failed, 4 warnings** in 192.56 seconds, with `test_optuna_baseline.py` and `test_phase11_leakage_audit.py` excluded because Optuna is unavailable. Dashboard API-client tests returned **3 passed**; oxlint completed without diagnostics; Vite production build passed with 1,915 modules and the existing large-chunk advisory (988.97 kB JS). Python compileall passed. The final working-tree `git diff --check` remains nonzero due trailing whitespace in the pre-existing modified `AiAnalysisView.jsx`; that file was preserved. No tunnel or backend restart was performed.

## Dataset and AI presentation follow-up (2026-10-11)

The live browser was rechecked after hardening. Dataset Studio shows the legacy attack sample as “Sample · origin unknown” / `UNVERIFIED`; its source CSV and manifest hash are preserved, but absent source PCAP and endpoint evidence prevent certifying its labels. AI Analysis suppresses the former 18-row SHAP table and benchmark flow observations because the live metrics API does not provide a provenance-complete held-out artifact, and no uploaded PCAP flow exists for local explanation. The model registry still reports candidate models and their live `NOT_VALIDATED` gates; it does not imply operational eligibility. The evidence-boundary copy remains visible.

The backend metrics description now distinguishes explicit synthetic fixtures from the legacy attack sample whose origin is unknown. Frontend lint and production build were rerun after the final UI gate change; targeted dataset-origin tests (2 passed), SHAP provenance tests (6 passed, 6 deselected), and dashboard API-client tests (3 passed) passed. This follow-up is not a full-suite rerun. The Glass treatment remains selective: shared navigation/header and compact toolbars use translucency, while technical tables, evidence panels, and KPI/data surfaces remain solid and readable. The existing backend and tunnel were not restarted or modified.
