#ifndef UTILS_H
#define UTILS_H

#include <iostream>

template <class R>
inline R get_unaligned_le(const void *p) {
    const unsigned char *ptr = (const unsigned char*)p;
    const std::size_t s = sizeof(R);

    R r = 0;
    for (std::size_t i = 0; i < s; i++)
        r |= (*ptr++ & 0xff) << (i * 8); // take the first 8-bits of the char
    return r;
}


int is_ndiswrapper(const char *iface, const char *path);

const char *search_recursively(const char *dir, const char *filename);
const char *get_witool_path(const char *tool);

void hide_cursor(void);

int check_crc_buf_osdep(unsigned char *buf, int len);

#endif // UTILS_H
