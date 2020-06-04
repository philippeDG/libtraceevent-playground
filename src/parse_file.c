#include<stdio.h>

#include <string.h>
#include <stdlib.h>
#include <glib.h>
//#include "traceevent/event-parse.h"

#define TRACE_FILE_PATH "../../trace.dat"
#define MAGIC_NUMBER 0x17, 0x08, 0x44

struct Initial_format {
	//file data
	char magicNumber[3];
	char identificationString[7];
	char version[2];
	char endianess;
	char usrLongSize;
	guint32 pageSize;
}; //18 byte long in file

struct Header_info_format {
	char identificationString[12];
	guint64 headerSize;
	char *ftraceFormat;
}; // 20 + headerSize byte long in file

struct Header_event_info {
	char identificationString[13];
	guint64 eventHeaderInfoSize;
	char *eventFormat;
}; // 21 + eventHeaderInfoSize


int header_parser() {

	FILE *fp;

	fp = fopen("../../trace.dat", "r");

	struct Initial_format initial_format;
	struct Header_info_format header_info_format;
	struct Header_event_info header_event_info;	

	fread(&initial_format.magicNumber, 1, sizeof(initial_format.magicNumber), fp);
	fread(&initial_format.identificationString, 1, sizeof(initial_format.identificationString), fp);

	fread(&initial_format.version, 1, sizeof(initial_format.version), fp); // TODO: may change
	fread(&initial_format.endianess, 1, sizeof(initial_format.endianess), fp);
	fread(&initial_format.usrLongSize, 1, sizeof(initial_format.usrLongSize), fp);
	fread(&initial_format.pageSize, 1, sizeof(initial_format.pageSize), fp);

	if(initial_format.endianess) { //big endian
		initial_format.pageSize = GINT32_FROM_BE(initial_format.pageSize);
	} else {
		initial_format.pageSize = GINT32_FROM_LE(initial_format.pageSize);
	}

	fread(&header_info_format.identificationString, 1, sizeof(header_info_format.identificationString), fp);	
	fread(&header_info_format.headerSize, 1, sizeof(header_info_format.headerSize), fp);

	header_info_format.ftraceFormat = (char*) g_malloc(header_info_format.headerSize);
	fread(header_info_format.ftraceFormat, 1, header_info_format.headerSize, fp);

	fread(&header_event_info.identificationString, 1, sizeof(header_event_info.identificationString), fp);
	fread(&header_event_info.eventHeaderInfoSize, 1, sizeof(header_event_info.eventHeaderInfoSize), fp);
	header_event_info.eventFormat = (char*) g_malloc(header_event_info.eventHeaderInfoSize);
	fread(header_event_info.eventFormat, 1, header_event_info.eventHeaderInfoSize, fp);
	
	fclose(fp);
	return 0;
}


int main(){
	header_parser();

	return 0;
}
