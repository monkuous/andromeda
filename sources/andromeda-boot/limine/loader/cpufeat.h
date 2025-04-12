#pragma once

typedef struct {
    bool nx : 1;
    bool direct_1gb : 1;
    bool pat : 1;
    bool la57 : 1;
} cpufeat_t;

extern cpufeat_t cpufeat;

void init_cpufeat();
