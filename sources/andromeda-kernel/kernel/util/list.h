#pragma once

#include "util/container.h"

typedef struct list_node {
    struct list_node *prev;
    struct list_node *next;
} list_node_t;

typedef struct {
    list_node_t *first;
    list_node_t *last;
} list_t;

#define list_foreach(list, type, member, name)                                                                         \
    for (type *name = container(type, member, (list).first); name != nullptr;                                          \
         name = container(type, member, name->member.next))

static inline bool list_is_empty(list_t *list) {
    return list->first == nullptr;
}

static inline void list_insert_head(list_t *list, list_node_t *node) {
    node->prev = nullptr;
    node->next = list->first;

    if (list->first) {
        list->first->prev = node;
    } else {
        list->last = node;
    }

    list->first = node;
}

static inline void list_insert_tail(list_t *list, list_node_t *node) {
    node->prev = list->last;
    node->next = nullptr;

    if (list->last) {
        list->last->next = node;
    } else {
        list->first = node;
    }

    list->last = node;
}

static inline void list_insert_before(list_t *list, list_node_t *before, list_node_t *node) {
    node->prev = before ? before->prev : list->last;
    node->next = before;

    if (node->prev) node->prev->next = node;
    else list->first = node;

    if (before) before->prev = node;
    else list->last = node;
}

static inline void list_insert_after(list_t *list, list_node_t *after, list_node_t *node) {
    node->prev = after;
    node->next = after ? after->next : list->first;

    if (after) after->next = node;
    else list->first = node;

    if (node->next) node->next->prev = node;
    else list->last = node;
}

static inline list_node_t *list_remove_head(list_t *list) {
    list_node_t *node = list->first;

    if (node) {
        list->first = node->next;

        if (node->next) node->next->prev = nullptr;
        else list->last = nullptr;
    }

    return node;
}

static inline list_node_t *list_remove_tail(list_t *list) {
    list_node_t *node = list->last;

    if (node) {
        list->last = node->prev;

        if (node->prev) node->prev->next = nullptr;
        else list->first = nullptr;
    }

    return node;
}

static inline void list_remove(list_t *list, list_node_t *node) {
    if (node->prev) node->prev->next = node->next;
    else list->first = node->next;

    if (node->next) node->next->prev = node->prev;
    else list->last = node->prev;
}
