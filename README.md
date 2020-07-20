### WARNING: Use at your own peril!  This layer is intended for quick triage not detailed analyses!
There is no short-cut for good work.

## vol3-fuzzy-linux-layers
Volatility 3 has a strict symbol table strict policy, where specific symbols must precisely match the specific Linux Kernel version and overall banner.  This policy is necessary to help keep wayward users from making mistakes.  However, for _power_ users or quick triage, this constraint can slow down the initial process.  

This layer helps relax that policy and removes any obligation of the project to deviate from a well intended policy. This layer give users the power to side-step te policy but places the responsibility on the user.

If a user leverages this layer, they should note the following issues:
1. The analysis results could be __very__ inaccurate and unrepresentative of what is actually present in memory
2. Volatility Analysis may be __erroneous__ and __buggy__ because symbols don't match the precise Linux Kernel
3. Results from this particular layer should not be used as evidence because of the uncertainty caused by using the symbol table of another Linux kernel

When ever this stacker is used, the user will get warnings like the following indicating that this module is in use:

```
(vol_dev) dso@mr-reimagined:~/linux_vol3_development/$ vol -f memory.img  -s ~/linux_vol3_development/volatility/symbols/ linux.pslist.PsList
Volatility 3 Framework 1.1.0-beta.1
WARNING  volatility.framework.layers.fuzzy_linux_layer: Performing fuzzy search and match on Linux Kernel Symbols
WARNING  volatility.framework.layers.fuzzy_linux_layer: Identified banner using fuzzy approach: b'Linux version 5.4.0-42-generic (root@hostname) (gcc version 9.3.0 (Ubuntu 9.3.0-10ubuntu2)) #46 SMP Fri Jul 17 22:26:43 CDT 2020 (Ubuntu 5.4.0-42.46-generic 5.4.44)\n\x00'
WARNING  volatility.framework.layers.fuzzy_linux_layer: DTB was found using fuzzy approach at: 0x10220a000
```

## Why do this if its prone to failure?
Sometimes an analyst is in a pinch, and they don't have time to track down the right kernel with the right symbols.  This helps an analyst get away with an approximate match in some cases, while higher priority tasks are being completed.  __NOTE:__ don't expect this approach to always work.  

## Installation

```
git clone https://github.com/volatilityfoundation/volatility3
git clone https://github.com/deeso/vol3-fuzzy-linux-layer
cp vol3-fuzzy-linux-layer/src/fuzzy_linux_layer.py volatility3/volatility/framework/layers/
python setup.py install
```
