### WARNING: Use at your own peril!  This layer is intended for quick triage not detailed analyses!
There is no short-cut for good work.

## vol3-fuzzy-linux-layers
Volatility 3 has a strict symbol table strict policy, where specific symbols must precisely match the specific Linux Kernel version and overall banner.  This policy is necessary to help keep wayward users from making mistakes.  However, for _power_ users or quick triage, this constraint can slow down the initial process.  

This layer helps relax that policy and removes any obligation of the project to deviate from a well intended policy. This layer give users the power to side-step the policy making the user responsibile for any outcomes and problems.

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

## How to use this in practice?

One of the most cumbersome taska in Linux memory analysis requires setting Linux Kernel (LK) profile.  This task is cumbersome because the LK changes frequently on platforms and distros.  These changes come in the form of recompilation of kernel code due to bug fixes, new features and security patches.  When the kernel is recompiled, structures and their location in memory can change.  Structures may be moved from one memory offset to another, and the size of structures could change (also changing offsets).  This mean one LK version can not be used to analyze all LK memory dumps.


All this being said, the LK may not change too drastically from one version to the next.  So, when there are small variations between the LK versions it might be possible to use a close relative.

### Use Case 
There is a LK memory dump for __Linux version 5.4.0-40-generic__ on Ubuntu, but this kernel does not have any debug symbols nor is there a package with debug symbols. _There_ is a software package for __Linux version 5.4.0-42-generic__ with debug symbols.  _Why not use this LK to generate the required symbols and then analyze the target image?_ Well, Volatility3 requires that the banner matches the LK exactly so it will fail to analyze.  

Prequisites to using this code:
1. Install the target kernel package or compile a similar LK locally.
2. Use `dwarf2json` to extract  the symbols from the LK binary with symbols
3. Copy the symbols into the volatility symbols directory
4. run `vol` after placing the `src/fuzzy_linux_layer.py` with `-s` flag pointing at the symbols directory

How this code works:
1. First it lets `vol` attempt to resolve the LK symbols for the memory dump in the natural way
2. If this fails, the `FuzzyLinuxIntelStacker` attempts to analyze the memory image
    1. This stacker uses a _regular expression_ (e.g. based on Linux version ...)
    2. As it iterates over each results, the stacker extracts the Linux _version_, _major-minor_ relase number (e.g. `5.4.0`), _tag_ (e.g. `generic`, `aws`, etc.) and distro (e.g. `Ubuntu`, `centos`, etc.)
    3. It then compares the attributes against the __known__ LK banners in the symbols.
    4. If identified banner matches the banner of a known set of symbols, then the known LK symbols set is used.  To match all of the following must be equal: _major-minor_ release, _tag_ and _distro_.
  
So, in this case __Linux version 5.4.0-40-generic__ can be matched with __Linux version 5.4.0-42-generic__ for a very quick triage. 
