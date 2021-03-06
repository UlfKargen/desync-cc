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

int vector3_square(int x, int y, int z) {
	return x * x + y * y + z * z;
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

	printf("Result: %d\n", vector3_square(vector[0], vector[1], vector[2]));
	return 0;
}