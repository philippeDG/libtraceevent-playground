#include<stdio.h>

#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include "traceevent/event-parse.h"

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

struct Header {
	struct Initial_format initial_format;
	struct Header_info_format header_info_format;
	struct Header_event_info header_event_info;
};

int headerParser(struct Header *header) {

	FILE *fp;

	fp = fopen("../../trace.dat", "r");

	fread(&header->initial_format.magicNumber, 1, sizeof(header->initial_format.magicNumber), fp);
	fread(&header->initial_format.identificationString, 1, sizeof(header->initial_format.identificationString), fp);

	fread(&header->initial_format.version, 1, sizeof(header->initial_format.version), fp); // TODO: may change
	fread(&header->initial_format.endianess, 1, sizeof(header->initial_format.endianess), fp);
	fread(&header->initial_format.usrLongSize, 1, sizeof(header->initial_format.usrLongSize), fp);
	fread(&header->initial_format.pageSize, 1, sizeof(header->initial_format.pageSize), fp);

	if(header->initial_format.endianess) { //big endian
		header->initial_format.pageSize = GINT32_FROM_BE(header->initial_format.pageSize);
	} else {
		header->initial_format.pageSize = GINT32_FROM_LE(header->initial_format.pageSize);
	}

	fread(&header->header_info_format.identificationString, 1, sizeof(header->header_info_format.identificationString), fp);	
	fread(&header->header_info_format.headerSize, 1, sizeof(header->header_info_format.headerSize), fp);

	header->header_info_format.ftraceFormat = (char*) g_malloc(header->header_info_format.headerSize);
	fread(header->header_info_format.ftraceFormat, 1, header->header_info_format.headerSize, fp);

	fread(&header->header_event_info.identificationString, 1, sizeof(header->header_event_info.identificationString), fp);
	fread(&header->header_event_info.eventHeaderInfoSize, 1, sizeof(header->header_event_info.eventHeaderInfoSize), fp);
	header->header_event_info.eventFormat = (char*) g_malloc(header->header_event_info.eventHeaderInfoSize);
	fread(header->header_event_info.eventFormat, 1, header->header_event_info.eventHeaderInfoSize, fp);
	
	fclose(fp);
	return 0;
}

bool validateMagicNumber(char header_magic_number[3]) {
	char magic_num[3] = {MAGIC_NUMBER};
	return (header_magic_number[0] == magic_num[0]) & (header_magic_number[1] == magic_num[1]) & (header_magic_number[2] == magic_num[2]) ;
}

int headerCheck(struct Header *header){
	if(!validateMagicNumber(header->initial_format.magicNumber)) {
		return false;//not an ftrace tace
	}

	return true;
}


int main(){
	struct Header header;
	headerParser(&header);
	if (headerCheck(&header)) {
		return -1; // TODO: assert
	}
	return 0;
}
