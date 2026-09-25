# Prism without an installed app: local dependency review

Reviewed 25 September 2026. This is a read-only source and existing artefact review; no device commands or acquisition were run. The proposed browser can become the host controller, but the current chain does not yet provide a complete package-free device worker.

## What the standalone pieces establish

`PrimitiveBinderBridge.receive/send` register a shell broadcast receiver and exchange a remote Binder, then verify a nonce and peer PID. This implements a transport building block; it does not perform acquisition, a privileged action, recovery or retirement. See [receiver registration](/Users/vandam/Developer/prism/tools/primitive/PrimitiveBinderBridge.java:216), [sender](/Users/vandam/Developer/prism/tools/primitive/PrimitiveBinderBridge.java:224) and [proof](/Users/vandam/Developer/prism/tools/primitive/PrimitiveBinderBridge.java:310).

The similarly named `route`, `route-hold` and route-template modes are **not package-free**: their explicit destination is the installed `com.vandam.prism.HarnessService`. See [route destination](/Users/vandam/Developer/prism/tools/primitive/PrimitiveBinderBridge.java:151) and [template destination](/Users/vandam/Developer/prism/tools/primitive/PrimitiveBinderBridge.java:81).

The native `probe` opens, queries, maps and closes Binder. `broker-probe` attempts service-manager registration. Neither performs acquisition. The native CLI has probe, route, clone, benchmark and action helper dispatch, with no full acquisition command. See [basic probe](/Users/vandam/Developer/prism/app/src/main/cpp/primitive_core.cpp:586), [broker probe](/Users/vandam/Developer/prism/app/src/main/cpp/primitive_core.cpp:645) and [CLI dispatch](/Users/vandam/Developer/prism/app/src/main/cpp/primitive_cli.cpp:629). Native holder/victim cohort interfaces exist, but take service routing templates; extracting native machinery has not removed the app's orchestration dependency. See [cohort interfaces](/Users/vandam/Developer/prism/app/src/main/cpp/primitive_core.h:48).

The action supervisor also presupposes an already privileged process; its root identity/capability check is not acquisition. See [root check](/Users/vandam/Developer/prism/app/src/main/cpp/primitive_cli.cpp:150).

## Dependencies that a browser controller cannot remove alone

| Dependency | Current evidence | Port implication |
| --- | --- | --- |
| Installed package and Android services | [Manifest](/Users/vandam/Developer/prism/app/src/main/AndroidManifest.xml:49) declares the harness and separate owner/client/target processes. [Harness](/Users/vandam/Developer/prism/app/src/main/java/com/vandam/prism/HarnessService.java:832) binds the owner; many subsequent phases bind other services. | A package-free worker needs equivalent process ownership, communication and teardown. Changing the host UI is insufficient. |
| App identity | [Private credential request](/Users/vandam/Developer/prism/app/src/main/java/com/vandam/prism/ShellBridgeMain.java:480) requires an application UID and [expected caller](/Users/vandam/Developer/prism/app/src/main/java/com/vandam/prism/ShellBridgeMain.java:633) checks the Prism process name. | A shell worker is rejected by current contracts. New identity contracts must bind the authorised session and its exact workers. |
| Installed APK path and resources | [Helper startup](/Users/vandam/Developer/prism/app/src/main/java/com/vandam/prism/DirectReSukiSuActivation.java:1256) requires `/data/app/.../base.apk` and supplies it as `CLASSPATH`. | A pushed JAR/native bundle requires an explicit packaging/resource path refactor. Merely running `app_process` does not make the chain independent of the APK. |
| Shell-to-app registration | [Shell helper registration](/Users/vandam/Developer/prism/app/src/main/java/com/vandam/prism/ShellBridgeMain.java:2414) starts the installed harness with Binder references. | This rendezvous must be replaced before removing the package. |
| Controller trust boundary | [App bridge](/Users/vandam/Developer/prism/app/src/main/java/com/vandam/prism/PrismAppBridgeService.java:1431) requires the live Binder caller to be shell. | Preserve caller/session checks when moving orchestration; do not broadly relax UID checks. |

## Existing evidence and its limit

The checked [five-run summary](/Users/vandam/Developer/prism/artifacts/prism-primitive-runs/20260824-061636/summary.json:2) reports five successful disclosure runs. Those are app-backed: the [runner requires Prism installed](/Users/vandam/Developer/prism/tools/prism_primitive_runs.py:65), uses `run-as`, and [starts the harness](/Users/vandam/Developer/prism/tools/prism_primitive_runs.py:95). Its [success criterion](/Users/vandam/Developer/prism/tools/prism_primitive_runs.py:118) is disclosure acquisition, not an end-to-end unlock. A [later inspected summary](/Users/vandam/Developer/prism/artifacts/prism-primitive-runs/20260824-164850/summary.json:2) reports a disclosure miss. Neither establishes package-free success.

A targeted search of existing artefacts found no textual `BRIDGE_PASS`/`BRIDGE_SEND` receipts. Consequently this review establishes the exchange probe's implemented scope, not a measured success rate. No full package-free acquisition receipt was found in the inspected material. This is a bounded review, not a claim that no other evidence exists.

## Smallest useful next port

First separate the browser's host transport and review/download UI from device execution. The current app-backed chain can remain a development reference, but it cannot be represented as an app-free deliverable.

For the strict app-free target, the smallest isolated milestone is a shell-owned worker bundle that demonstrates Binder exchange, process identity, bounded lifetime and complete retirement without a Prism package. The existing exchange probe is a starting point for that transport milestone. Only then port the app service orchestration and require new evidence for acquisition and recovery in that execution context. Keep transport success, disclosure success, privilege acquisition and unlock completion as separate receipts.

An unlock-only action can remove ReSukiSu installation and manager postflight from the eventual workflow, but does not eliminate the acquisition or recovery dependencies above. Treat unlock action design and app-free acquisition as separate workstreams; neither is currently proven by the standalone probes.
