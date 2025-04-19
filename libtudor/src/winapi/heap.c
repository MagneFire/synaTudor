#include <stdlib.h>
#include <string.h>
#include "internal.h"

#define PROC_HEAP_HANDLE ((HANDLE) (uintptr_t) 0x50524f4348454150) /* PROCHEAP */

#define HEAP_GENERATE_EXCEPTIONS 0x00000004
#define HEAP_NO_SERIALIZE 0x00000001
#define HEAP_ZERO_MEMORY 0x00000008

#define HEAP_TOTAL_SIZE 100

// TODO: Dynamically allocate more space
struct Heap_T
{
    void *mem;
    size_t size;
    bool used;
} heap[HEAP_TOTAL_SIZE] = {0};

struct Heap_T* heap_find(void *mem)
{
    for (int i = 0; i < HEAP_TOTAL_SIZE; i++)
    {
        if (heap[i].mem == mem)
            return &heap[i];
    }

    log_warn("heap %p not found", mem);
    return NULL;
}

struct Heap_T* heap_find_free()
{
    for (int i = 0; i < HEAP_TOTAL_SIZE; i++)
    {
        if (!heap[i].used)
            return &heap[i];
    }

    log_error("No free heap available!")
    return NULL;
}

void* heap_alloc(size_t size)
{
    struct Heap_T* heap = heap_find_free();
    if (heap == NULL)
    {
        log_error("Failed to allocate heap!");
        return NULL;
    }

    void *mem = malloc(size);

    if(mem) {
        heap->mem = mem;
        heap->size = size;
        heap->used = true;
        return mem;
    }

    return NULL;
}

void heap_free(void *mem)
{
    struct Heap_T* heap = heap_find(mem);
    if (heap == NULL)
    {
        log_error("Failed to free heap! Not in use?!");
        return;
    }
    if (heap->used == false)
    {
        log_error("Failed to free heap! Already freed?!");
    }

    free(heap->mem);
    heap->used = false;
}

size_t heap_size(void *mem)
{
    struct Heap_T* heap = heap_find(mem);
    if (heap == NULL)
    {
        log_error("Failed to get heap size!");
        return 0;
    }

    return heap->size;
}

__winfnc HANDLE GetProcessHeap() { return PROC_HEAP_HANDLE; }
WINAPI(GetProcessHeap)

__winfnc void *HeapAlloc(HANDLE heap, DWORD flags, SIZE_T size) {
    // static int heap_alloc_cnt = 0;
    // log_warn("HeapAlloc[%d]: Called %p, %d, %lu", heap_alloc_cnt++, heap, flags, size);
    if(heap != PROC_HEAP_HANDLE) {
        log_warn("HeapAlloc called with invalid heap handle");
        winerr_set();
        return NULL;
    }

    //Allocate the memory
    void *mem = heap_alloc(size);
    if(mem) {
        // log_warn("HeapAlloc: allocated %p", mem);
        if(flags & HEAP_ZERO_MEMORY) memset(mem, 0, size);
        return mem;
    }

    //There was an error allocating the memory
    if(flags & HEAP_GENERATE_EXCEPTIONS) {
        perror("Error allocating memory for HeapAlloc");
        log_error("HeapAlloc: HEAP_GENERATE_EXCEPTIONS flag set and memory allocation failed!");
        abort();
    }

    winerr_set_errno();
    return NULL;
}
WINAPI(HeapAlloc)

__winfnc void *HeapReAlloc(HANDLE heap, DWORD flags, void *mem, SIZE_T size) {
    log_warn("HeapReAlloc: Called %p, %d, %p, %lu", heap, flags, mem, size);
    // TODO: This potentially leaks memory as the old memory region isn't touched
    return HeapAlloc(heap, flags, size);
}

WINAPI(HeapReAlloc)

__winfnc BOOL HeapFree(HANDLE heap, DWORD flags, void *mem) {
    // log_warn("HeapFree: Called %p, %d %p", heap, flags, mem);
    if(heap != PROC_HEAP_HANDLE) {
        log_warn("HeapAlloc called with invalid heap handle");
        winerr_set();
        return FALSE;
    }

    // free(mem);
    heap_free(mem);
    return TRUE;
}
WINAPI(HeapFree)

__winfnc void *LocalFree(void *mem) {
    // free(mem);
    heap_free(mem);
    return NULL;
}
WINAPI(LocalFree)

__winfnc SIZE_T HeapSize(HANDLE heap, DWORD flags, void *mem) {
    // static int cnt = 0;
    // log_warn("HeapSize[%d]: Called %p, %d %p", cnt++, heap, flags, mem);
    size_t size = heap_size(mem);
    // log_warn("HeapSize: Called %p, %d %p: %lu", heap, flags, mem, size);
    return size;
}
WINAPI(HeapSize)