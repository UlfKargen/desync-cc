#ifndef DESYNC_TEST_BASIC2_OTHER_H
#define DESYNC_TEST_BASIC2_OTHER_H

#include <stddef.h>

void vec3_add(float* out, const float* a, const float* b);
void vec3_muls(float* out, const float* a, float s);
float vec3_dot(const float* a, const float* b);
float vec3_length2(const float* a);
float vec3_length(const float* a);
float vec3_normalize(float* out, const float* a);

void crazy_strcpy(char* dest, const char* src, size_t max_size);

#endif
