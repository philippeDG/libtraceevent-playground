#include<stdio.h> 
#include <traceevent/event-parse.h> 
int main(){
	struct tep_handle *curTep = tep_alloc();
	if(!curTep){
		die("dead");
	}
	printf("Hello fwends\n");
	tep_free(curTep);
	return 0;
}
