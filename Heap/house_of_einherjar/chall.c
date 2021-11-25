#include <stdio.h>
#include <stdlib.h>

void *ptrs[9];

void init(){
	setvbuf(stdin,0,1,0);
	setvbuf(stdout,0,1,0);
	setvbuf(stderr,0,1,0);
}

void menu(){
	puts("1) Allocate");
	puts("2) Free");
	puts("3) Show");
	puts("4) Exit");
	printf("> ");
}

void allocate_chunk(){
	int idx = 10;

	for(int i=0;i<10;i++){
		if(ptrs[i] == NULL){
			idx = i;
			break;
		}
	}
	if(idx == 10){
		puts("Maximum entries reached!");
		return;
	}

	unsigned int size;
	char buf[512];
	printf("Size: ");
	scanf("%u",&size);
	getchar();
	if (size > 511){
		puts("Size too large!");
		return;
	}
	ptrs[idx] = malloc(size);

	printf("Content: ");
	fflush(stdout);
	size = read(0,buf,size);
	buf[size] = 0;
	strcpy(ptrs[idx],buf);
	printf("Index %d\n",idx);
}

int get_idx(){
	int idx;
	printf("Index: ");
	scanf("%d",&idx);

	if(ptrs[idx] == NULL){
		puts("No entry found at index!");
		return 10;
	}
	return idx;
}

void free_chunk(){
	int idx = get_idx();
	if (idx == 10) return;
	free(ptrs[idx]);
	ptrs[idx] = NULL;
}

void show(){
	int idx = get_idx();
	if (idx == 10) return;
	printf("Content:\n%s\n",ptrs[idx]);
}

int main(int argc, char *argv[]){
	init();
	while(1){
		int option;
		menu();
		scanf("%d",&option);

		if(option == 1){
			allocate_chunk();
		}
		else if(option == 2){
			free_chunk();
		}
		else if(option == 3){
			show();
		}
		else if(option == 4){
			exit(0);
		}
		else{
			puts("Invalid option!");
		}
	}
}