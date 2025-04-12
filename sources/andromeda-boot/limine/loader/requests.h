#pragma once

typedef enum {
    REQUEST_PAGING_MODE,
    REQUEST_STACK_SIZE,
    REQUEST_HHDM,
    REQUEST_EXECUTABLE_ADDRESS,
    REQUEST_ENTRY_POINT,
    REQUEST_FRAMEBUFFER,
    REQUEST_MEMORY_MAP,
    REQUEST_RSDP,
    REQUEST_MODULE,
    REQUEST_EXECUTABLE_FILE,
    REQUEST_EXECUTABLE_CMDLINE,
    REQUEST_SMP,
    REQUEST_MAX,
} request_t;

void init_requests();

void *get_request(request_t request);
void fill_response_pointers();
