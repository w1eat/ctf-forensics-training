# Community plugin compatibility

Vol2 mimikatz retains the pinned upstream analysis code. Added a relative dependency search path, an isolated Cryptodome namespace, CPython 2.7 ctypes.util for the frozen executable, and an ASCII plugin-path help label for Windows paths containing Chinese characters. Construct 2.8.22 and PyCryptodomex 3.9.9 stay in the Vol2 dependency directory; the Python 3 runtime uses its own separate packages.

The Vol3 plugins and both BitLocker sources are unmodified. BitLocker output is a candidate and must be validated against the encrypted volume; no host key acquisition or live LSASS access is exposed by the workbench.
