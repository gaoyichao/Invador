#ifndef UTILS_H
#define UTILS_H


int is_ndiswrapper(const char *iface, const char *path);

const char *search_recursively(const char *dir, const char *filename);
const char *get_witool_path(const char *tool);

void hide_cursor(void);

#endif // UTILS_H
