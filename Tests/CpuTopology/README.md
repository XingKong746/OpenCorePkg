# CPU topology regression tests

These tests run the production CPU patch helper and masked byte scanner against
bounded instruction fixtures. A second adapter executes the real kernel-patch
caller to verify CPUID masks, emulation version bounds and failure handling.
The outer CPU routine is also tested to ensure topology failures retain their
status and do not enter TSC symbol lookup.

Requirements: 64-bit Windows, 64-bit Python 3, Clang with `opt.exe` and
`lld-link.exe` in the same directory, and EDK II headers compatible with this
OpenCore tree. The validated EDK revision is
`acidanthera/audk@dfd5516702b4911f1fc1919a429d637b456df913`.
No additional Python packages are required.

From the repository root, supply paths appropriate for your machine:

```powershell
python Tests/CpuTopology/test_cpu_topology.py --edk C:/path/to/audk --clang C:/path/to/llvm/bin/clang.exe --out C:/path/to/scratch/cpu-tests
```

All build outputs go under `--out`. The test DLLs have no entry point and no
runtime-library imports. Only exported test adapters and their reachable
production code are retained. The adapters bind the Mach-O symbol base to the
fixture offset and supply host memory operations; caller tests substitute the
CPUID patch and CPU-info write boundaries to inspect forwarded values.

The suite does not run firmware, privileged CPU instructions, or disk writes.
It does not establish full firmware build success or hardware boot stability.
Optional `--cpu-source` and `--caller-source` overlays support checking that the
tests detect regressions without changing the working source files.
