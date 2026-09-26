# FireDrv (IntekNodeManager)

## Overview

**FireDrv.sys** is a Windows kernel driver from Texas Instruments IEEE 1394 (firewire) OHCI host controllers. it ships signed by its vendors which makes it viable as BYOVD target. This driver creates a control device (\\.\IntekNodeManager) accessible to any user with no privilege checks. Exposing kernel memory primitives that enable pool address leaks, shared kernel/user memory, NonPagedPool spray, and a write-what-where via doubly-linked list unlink.

During this testing we will be using the 2017/2016 version.

| Field | Value |
|-------|-------|
| Name | firedrv.sys |
| SHA-256 | 7c66e32b91f59089665079b8d035816885aaf1cf8c1f8e880799d3f149deb289 |
| Arch | x64 |
| Windows Version | Windows 10, 11 |
| Class | Industrial Control / Fire Detection |
| Family | Intek |
| Signer | Allied Vision Technologies GmbH & Microsoft Windows Hardware Compatibility Publisher |
| Signed Date | ‎24 ‎February ‎2016 07:31:11 |

## Device Object

| Device | Type | Extension | Access | Requires HW |
|--------|------|-----------|--------|-------------|
| `\Device\IntekNodeManager` | `0x8001` | `0x1E8` | Any user | No |
| PnP FDO | `0x8002` | `0x560` | N/A | Yes |
| `\\.\FireCardXXXXXXXX` | `0x8000` | `0x18` | Any user | Yes |

The Device opens 3 main objects, its IntekNodeManager accessible to all users, PnP FDO accessible to all but requires a fireware PCI (hardware) and FireCardXXXXXXXX which is the firecard device itself.

## Primitives

### Non-Hardware locked

**1. Kernel Pool Address Leak**
0xDB returns the buffer object's kernel address at response offset +0x08. Partial KASLR bypass for NonPagedPool.

**2. Shared Kernel/User Memory**
0xDB with `user_va=0`: driver allocates pages via `MmAllocatePagesForMdl`, maps them into both kernel and user address space. Same physical pages. Write from usermode, kernel sees it instantly.

Path: `sub_26B8C` → `sub_23320`

**3. User Page Lock + Dual Map**
0xDB with `user_va!=0`: driver creates MDL around user pages, calls `MmProbeAndLockPages` + `MmMapLockedPagesSpecifyCache(KernelMode)`. User retains original VA, kernel gets a second VA to same physical pages. Pages pinned, survive working set trim. Magic `0xAC741001` set at +0x38.

Path: `sub_26B8C` → `sub_23518`

**4. NonPagedPool Spray**
Each 0xDB creates a 0x60-byte pool allocation (tag FDRV). Tested: 28/31 adjacent pairs at exactly 0x70 stride (0x60 + 0x10 pool header). Extremely deterministic.

**5. Write-What-Where via Unlink**
0xDC free performs doubly-linked list unlink under spinlock:
```
*Blink = Flink
*(Flink+8) = Blink
```
If Flink/Blink corrupted before free: arbitrary 8-byte write. Constraint: `*(Flink+8)` must be writable.

**6. Pool Feng Shui**
Controlled alloc/free patterns for deterministic object placement. Create contiguous holes, fill with target objects.

**7. No ACL on Device**
Any unprivileged user can open `\\.\IntekNodeManager`. Driver loading is admin-only; exploitation is not.

### Requires Hardware or Emulation

**8. Per-Card Function Pointer Calls (0x87/0x8D)**
Per-card IOCTLs invoke function pointers from card context. With QEMU emulation: attacker controls BAR registers → controls card context → direct kernel code execution. No unlink chain needed.

## The flaw

The primitives above give everything except a way to corrupt Flink/Blink from usermode through this driver alone, data pages (from MmAllocatePagesForMdl) and buffer objects (from ExAllocatePoolWithTag) live in separate memory regions, the user mapping points to data pages not pool. Lock mode maps user pages into system PTE space, not pool. This is our flaw stopping us from R/W esclations.

### How could we counter it?

Second vulnerable driver:
We could do a pool overflow into adjacent FDRV object but this wouldn't be self-contained.

PCILeech/DMA:
write to physical address of buffer object (kernel VA known from leak) - same as above not self-contained

QEMU emulation:
Commands 0x87/0x8D = function pointer calls from controlled card context - this could be a perfect way to stay self-contained while stepping up to Arbitrary R/W.
instead of QEMU emulation we could go out and buy a real firewire PCI card for around $15 saving us the emulation creation time.

## Key Functions

| Address | Purpose |
|---------|---------|
| `0x238FC` | Init, ctrl device, worker thread |
| `0x26D4C` | Control IOCTL (0xDB/0xDC inline) |
| `0x23320` | Alloc mode (MmAllocatePagesForMdl) |
| `0x23518` | Lock mode (MmProbeAndLockPages) |
| `0x23280` | Buffer free (unmap/unlock/free) |
| `0x2636C` | Worker thread (priority 31) |
| `0x27CC0` | AddDevice (PnP FDO) |
| `0x2B398` | Per-card device creation |
| `0x2B610` | Magic validation (0xAC741001) |
| `0x26C8C` | CREATE handler (0xD68 context) |
