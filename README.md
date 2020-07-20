## vol3-fuzzy-linux-layers
Volatility 3 has a very string policy where specific symbols must precisely match the specific Linux Kernel version and overall banner.  This policy is necessary to help keep wayward users from making mistakes.  However, for _power_ users or quick triage, this constraint can slow down the triage process.  This layer helps remove any obligation of the project and places the responsibility on the users of this layer.

This Volatility Layer helps tamp down the guard rails for the sake of triage.  If a user leverages this layer, they should note the following issues:
1. The results could be __very__ inaccurate and unrepresentative of what is actually present in memory
2. Volatility Analysis may be __erroneous__ and __buggy__ because symbols are not in there expected locations
3. Where litigation or investigative cases are concerned, users of this layer should expect the results to be invalidated since there could be doubt brought on by the analysis

