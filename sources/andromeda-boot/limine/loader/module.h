#pragma once

typedef struct module module_t;

module_t *add_module(const char *path);
void set_module_string(module_t *module, const char *string);

void init_module();
