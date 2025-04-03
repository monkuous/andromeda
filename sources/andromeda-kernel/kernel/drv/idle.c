#include "idle.h"
#include "drv/console.h"

void idle_poll_events() {
    console_poll_events();
}
