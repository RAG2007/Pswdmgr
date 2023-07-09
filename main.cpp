#include <cerrno>
#include <cstdlib>
#include <ios>
#include <iostream>
#include <ostream>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/random.h>
#include <string.h>
#include <termios.h>
#include <sys/stat.h>

struct termios settings;

struct passwords_cyphered {
	unsigned char name_password[32];
	unsigned char password_saved[32];
};
struct passwords_decyphered {
	unsigned char name_password[16];
	unsigned char password_saved[16];
};
using namespace std;


void Cypher(unsigned char* password, unsigned char* input, unsigned int* res) {
	int Sbox[16][16] = {{0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76},
			    {0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0},
			    {0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15},
			    {0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75},
			    {0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84},
			    {0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf},
			    {0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8},
			    {0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2},
			    {0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73},
			    {0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb},
			    {0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79},
			    {0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08},
			    {0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a},
			    {0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e},
			    {0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf},
			    {0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16}};
	int state[4][4] = {{0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}};
	for (int i = 0; i < 16; i++) {
		state[i/4][i % 4] = input[i];
	}
	for(int k = 0; k < 14; k++) {
		int tmp2;
		for (int i = 0; i < 16; i++) {
			state[i / 4][i % 4] = Sbox[(int)state[i / 4][i % 4] / 16][(int)state[i / 4][i % 4] % 16];
		}

		int statesub[4][4];
		for(int i = 0; i < 16; i++) {
			statesub[i / 4][i % 4] = state[i / 4][i % 4];
		}
		statesub[0][1] = state[1][1];
		statesub[1][1] = state[2][1];
		statesub[2][1] = state[3][1];
		statesub[3][1] = state[0][1];

		statesub[0][2] = state[2][2];
		statesub[1][2] = state[3][2];
		statesub[2][2] = state[0][2];
		statesub[3][2] = state[1][2];

		statesub[0][3] = state[3][3];
		statesub[1][3] = state[0][3];
		statesub[2][3] = state[1][3];
		statesub[3][3] = state[2][3];

		for(int i = 0; i < 16; i++) {
			state[i / 4][i % 4] = statesub[i / 4][i % 4];
		}

		for(int i = 0; i < 16; i++) {
			state[i / 4][i % 4] = state[i / 4][i % 4] ^ password[i];
		}
	}
	for(int i = 0; i < 16; i++) {
		res[i] = state[i / 4][i % 4];
	}
}

void Decypher(unsigned char* password, unsigned char* input, unsigned char* output) {
	int InvSbox[16][16] = {{0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb},
			       {0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb},
			       {0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e},
			       {0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25},
			       {0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92},
			       {0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84},
			       {0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06},
			       {0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b},
			       {0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73},
			       {0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e},
			       {0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b},
			       {0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4},
			       {0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f},
			       {0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef},
			       {0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61},
			       {0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d}};
	unsigned char a;
	unsigned char b;
	for(int i = 0; i < 32; i += 2) {
		a = input[i];
		b = input[i + 1];
		if(a >= 'a') {
			a = a - 'a' + 10;
		} else {
			a = a - '0';
		}
		if(b >= 'a') {
			b = b - 'a' + 10;
		} else {
			b = b - '0';
		}
		input[i / 2] = a * 16 + b;
	}
	int state[4][4];
	int tmp = 0;
	for (int i = 0; i < 4; i++) {
		for(int a = 0; a < 4; a++) {
			state[i][a] = input[tmp];
			tmp++;
		}
	}

	for(int j = 0; j < 14; j++) {
		for(int i = 0; i < 16; i++) {
			state[i / 4][i % 4] = state[i / 4][i % 4] ^ password[i];
		}

		int statesub[4][4];
		for(int i = 0; i < 16; i++) {
			statesub[i / 4][i % 4] = state[i / 4][i % 4];
		}
		statesub[0][1] = state[3][1];
		statesub[1][1] = state[0][1];
		statesub[2][1] = state[1][1];
		statesub[3][1] = state[2][1];

		statesub[0][2] = state[2][2];
		statesub[1][2] = state[3][2];
		statesub[2][2] = state[0][2];
		statesub[3][2] = state[1][2];

		statesub[0][3] = state[1][3];
		statesub[1][3] = state[2][3];
		statesub[2][3] = state[3][3];
		statesub[3][3] = state[0][3];

		for(int i = 0; i < 16; i++) {
			state[i / 4][i % 4] = statesub[i / 4][i % 4];
		}

		for (int i = 0; i < 16; i++) {
			state[i / 4][i % 4] = InvSbox[(int)state[i / 4][i % 4] / 16][(int)state[i / 4][i % 4] % 16];
		}
	}
	for(int i = 0; i < 16; i++) {
		output[i] = state[i / 4][i % 4];
	}
}
unsigned char newpassword[8];
int main() {
	int fd;
	if((fd = open("/home/radek/Desktop/Overback", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)) == -1) {
		printf("ERROR: failed to open the file%s", strerror(errno));
		return -1;
	}
	char exist;
	unsigned long long bytes;
	if(read(fd, &exist, 1) < 1) {
		printf("This is your new password: ");
		if(getrandom(newpassword, 8, GRND_RANDOM ) != 8) {
			printf("ERRORRRRRRRRRR");
			return 1;
		}
		for(int i = 0; i < 8; i++) {
			printf("%02x", newpassword[i]);
		}
		printf("\n");
		unsigned char password[33];
		for(int i = 0; i < 8; i++) {
			sprintf((char*)&password[2 * i], "%02x", newpassword[i]);
		}
		unsigned int output_tmp[34];
		Cypher(password, password, output_tmp);
		for(int i = 0; i < 16; i++) {
			sprintf((char*)&password[2 * i], "%02x", output_tmp[i]);
		}
		write(fd, password, 32);
		sleep(10);
		printf("\x1b[F\x1b[K");
		return 0;
	} else {
		lseek(fd, 0, SEEK_SET);
		printf("Enter your password:\n");
		unsigned char password[33];
		if (tcgetattr(0, &settings) == -1)
			return 1;

		settings.c_lflag &= ~ECHO;

		if (tcsetattr(0, TCSANOW, &settings) == -1)
			return 1;

		cin >> password;
		settings.c_lflag |= ECHO;

		if (tcsetattr(0, TCSANOW, &settings) == -1)
			return 1;

		struct stat file_stat;
		if(fstat(fd, &file_stat) == -1) {
			printf("FILESTATS NOT AVAILABLE!! ERROR");
			return 1;
		}
		char *buffer = (char*)malloc(file_stat.st_size);
		read(fd, buffer, file_stat.st_size);
		unsigned char password_check_buffer[32];

		for(int i = 0; i < 32; i++)
			password_check_buffer[i] = buffer[i];

		unsigned char output[32];
		Decypher(password, password_check_buffer, output);

		if(strcmp((char*)password, (char*)output) == 0) {
			printf("ACCESS GRANTED");
			int if2pl = 0;
			while(1) {
				int choice;
				printf("\n1-write\n2-read\n3-create new password");
				printf("\n$- ");
				cin >> choice;
				printf("\x1b[F\x1b[K");
				if(choice == 1) {
					lseek(fd, 0, SEEK_END);
					unsigned char name_password[16];	
					unsigned char add_password[16];
					memset(name_password, 0, 16);
					memset(add_password, 0, 16);
					printf("Podaj nazwę hasła i hasło: ");
					cin >> name_password >> add_password;
					unsigned int name_password_buffer_tmp[16];
					unsigned int add_password_buffer_tmp[16];
					Cypher(password, name_password, name_password_buffer_tmp);
					Cypher(password, add_password, add_password_buffer_tmp);
					char name_password_buffer[33];
					char add_password_buffer[33];
					for(int i = 0; i < 16; i++) {
						sprintf(&name_password_buffer[i * 2], "%02x", name_password_buffer_tmp[i]);
						sprintf(&add_password_buffer[i * 2], "%02x", add_password_buffer_tmp[i]);
					}
					write(fd, name_password_buffer, 32);
					write(fd, add_password_buffer, 32);
					if2pl+= 64;
				} else if(choice == 2) {
					lseek(fd, 0, SEEK_SET);
					read(fd, buffer, file_stat.st_size + if2pl);
					char tmp_buffer[file_stat.st_size - 32 + if2pl];
					for (int i = 0; i < file_stat.st_size - 32 + if2pl; i++) {
						tmp_buffer[i] = buffer[i + 32];
					}
					struct passwords_cyphered buffer_passwords[(file_stat.st_size + if2pl - 32) / 64];
					for(int i = 0; i < (file_stat.st_size + if2pl - 32) / 64; i++) {
						for(int a = 0; a < 32; a++) {
							buffer_passwords[i].name_password[a] = tmp_buffer[(64*i) + a];
							buffer_passwords[i].password_saved[a] = tmp_buffer[(64*i) + 32 + a];
						}
					}
					struct passwords_decyphered saved_passwords_decyphered[(file_stat.st_size - 32) / 64];
					for(int i = 0; i < (file_stat.st_size + if2pl - 32) / 64; i++) {
						Decypher(password, buffer_passwords[i].name_password, saved_passwords_decyphered[i].name_password);
						Decypher(password, buffer_passwords[i].password_saved, saved_passwords_decyphered[i].password_saved);
					}
					for(int i = 0; i < (file_stat.st_size + if2pl - 32) / 64; i++) {
							printf("%s - %s\n", saved_passwords_decyphered[i].name_password, saved_passwords_decyphered[i].password_saved);
					}
				} else if(choice == 3) {
					printf("Here you go: ");
					if(getrandom(newpassword, 8, GRND_RANDOM ) != 8) {
						printf("ERRORRRRRRRRRR");
						return 1;
					}
					for(int i = 0; i < 8; i++) {
						printf("%02x", newpassword[i]);
					}
					printf("\n");
				} else {
					printf("Wrong command");
				}
			}
		} else {
				printf("ACCESS DENIED");
		}
		free(buffer);
	}
}
