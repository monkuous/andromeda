#pragma once

#include <stdint.h>
#include <time.h>

/* from https://howardhinnant.github.io/date_algorithms.html#days_from_civil */
static inline time_t get_time_from_date(int year, unsigned month, unsigned day) {
    year -= month <= 2;
    time_t era = (year >= 0 ? year : year - 399) / 400;
    unsigned yoe = year - era * 400;
    unsigned doy = (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    time_t ndays = era * 146097 + doe - 719468;
    return ndays * 86400;
}
