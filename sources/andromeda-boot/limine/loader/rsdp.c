#include "rsdp.h"
#include "libboot.h"
#include "limine.h"
#include "main.h"
#include "requests.h"

void init_rsdp() {
    paddr_t address;
    if (!libboot_acpi_get_rsdp_addr(&address)) {
        struct limine_rsdp_request *request = get_request(REQUEST_RSDP);
        if (request) request->response = 0;
        return;
    }

    boot_info.responses.rsdp.address = address;
}
