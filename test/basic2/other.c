#include "other.h"

#include <math.h>

void vec3_add(float* out, const float* a, const float* b) {
	out[0] = a[0] + b[0];
	out[1] = a[1] + b[1];
	out[2] = a[2] + b[2];
}

void vec3_muls(float* out, const float* a, float s) {
	out[0] = a[0] * s;
	out[1] = a[1] * s;
	out[2] = a[2] * s;
}

float vec3_dot(const float* a, const float* b) {
	return a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
}

float vec3_length2(const float* a) {
	return vec3_dot(a, a);
}

float vec3_length(const float* a) {
	return sqrtf(vec3_length2(a));
}

float vec3_normalize(float* out, const float* a) {
	const float length = vec3_length(a);
	vec3_muls(out, a, 1.0f / length);
	return length;
}

void crazy_strcpy(char* dest, const char* src, size_t max_size) {
	if (max_size > 0) {
		while (--max_size > 0 && *src != '\0') {
			*dest++ = *src++;
		}
		*dest = '\0';
	}
}
