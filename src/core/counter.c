#include "core/counter.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/helper.h"
#include "core/marsh.h"

void bf_counter_free(struct bf_counter **counter)
{
    bf_assert(counter);

    if (!*counter)
        return;

    freep((void *)counter);
}

int bf_counter_new(struct bf_counter **counter, uint64_t packets,
                   uint64_t bytes)
{
    _cleanup_free_ struct bf_counter *_counter = NULL;

    bf_assert(counter);

    _counter = malloc(sizeof(*_counter));
    // check for NULL
    if (!_counter)
        return -ENOMEM;

    _counter->bytes = bytes;
    _counter->packets = packets;

    *counter = TAKE_PTR(_counter);

    return 0;
}

int bf_counter_marsh(const struct bf_counter *counter, struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    bf_assert(counter && marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r < 0)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, &counter->packets,
                               sizeof(counter->packets));
    if (r < 0)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, &counter->bytes,
                               sizeof(counter->bytes));
    if (r < 0)
        return r;

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

int bf_counter_new_from_marsh(struct bf_counter **counter,
                              const struct bf_marsh *marsh)
{
    _cleanup_bf_counter_ struct bf_counter *_counter = NULL;
    struct bf_marsh *elem = NULL;

    bf_assert(counter && marsh);

    _counter = malloc(sizeof(*_counter));
    if (!_counter)
        return -ENOMEM;

    if (!(elem = bf_marsh_next_child(marsh, elem)))
        return -EINVAL;
    memcpy(&_counter->packets, elem->data, sizeof(_counter->packets));

    if (!(elem = bf_marsh_next_child(marsh, elem)))
        return -EINVAL;
    memcpy(&_counter->bytes, elem->data, sizeof(_counter->bytes));

    *counter = TAKE_PTR(_counter);

    return 0;
}
