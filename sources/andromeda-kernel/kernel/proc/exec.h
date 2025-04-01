#pragma once

#include "fs/vfs.h"
#include <andromeda/string.h>

int execute(
        file_t *file,
        const andromeda_tagged_string_t *argv,
        size_t nargv,
        const andromeda_tagged_string_t *envp,
        size_t nenvp
);
