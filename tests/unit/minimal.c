extern long write(int, const void*, unsigned long);

int main() {
	write(1, "Hello World!", 12);
}
