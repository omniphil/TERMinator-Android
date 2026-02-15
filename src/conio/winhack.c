#include "windows.h"

int mainCRTStartup(void);
int WinMainCRTStartup(void);

int conioCRTStartup(void)
{
	LPWSTR cmdline;
	int i;
	int s = 0;
	int iscon = 0;

	cmdline = GetCommandLineW();

	for (i = 0; cmdline[i]; i++) {
		wchar_t c = cmdline[i];
		if (c == 'i')
			c = 'I';
		if (c == 'w')
			c = 'W';
		switch(s) {
			case 0:
				if (c == ' ')
					s++;
				break;
			case 1:
				if (c == '-')
					s++;
				break;
			case 2:
				if (c == 'I')
					s++;
				break;
			case 3:
				if (c == 'W')
					s++;
				else
					iscon = 0;
				break;
			case 4:
				if (c == ' ' || c == 0) {
					iscon = 1;
					s = 0;
				}
				break;
		}
		if (cmdline[i] == 0)
			break;
	}

	if (iscon) {
puts("mainCRTStartup()");
		return mainCRTStartup();
	}
puts("WinMainCRTStartup()");
	return WinMainCRTStartup();
}
