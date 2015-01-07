#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
	if(argc <= 1){
		printf("Plase enter the input\n");
	} else if(argv[1][0] == argv[1][1]){
		printf("===== [%c] == [%c] ======\n", argv[1][0], argv[1][1]);	
	}else if(argv[1][0] < argv[1][1]){
		printf("<<<<< [%c] << [%c] <<<<<<\n", argv[1][0], argv[1][1]);	
	}else
		printf(">>>>> [%c] >> [%c] >>>>>>\n", argv[1][0], argv[1][1]);
}
