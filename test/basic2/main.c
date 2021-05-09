#include "other.h"

#include <stdio.h>

int string_length(const char* p) {
	int result = 0;
	while (*p != '\0') {
		++p;
		++result;
	}
	return result;
}

int parse_int(const char* str) {
	int value = 0;
	int base = 1;
	for (int i = string_length(str); i-- > 0;) {
		value += (str[i] - '0') * base;
		base *= 10;
	}
	return value;
}

volatile int asdf = 0;

void test123() {
	++asdf;
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		printf("Usage: basic <x> <y> <z>\n");
		return -1;
	}

	test123();

	int vector[3] = {0, 0, 0};
	int* component = vector;
	for (int i = 1; i < argc; ++i) {
		*component++ = parse_int(argv[i]);
	}

	float fvec[3] = {vector[0], vector[1], vector[2]};
	vec3_muls(fvec, fvec, 8.0f);
	const float r = vec3_normalize(fvec, fvec);

	char buf[100];
	snprintf(buf, 100, "Result: x: %f, y: %f, z: %f, r: %f\n", fvec[0], fvec[1], fvec[2], r);

	char buf2[100];
	crazy_strcpy(buf2, buf, 100);

	printf("%s", buf2);
	return 0;
}
