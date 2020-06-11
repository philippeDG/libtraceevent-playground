#include<stdio.h>

#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include "glibconfig.h"
#include "traceevent/event-parse.h"
#include <sanitizer/asan_interface.h>

#define TRACE_FILE_PATH "~/trace.dat"
#define MAGIC_NUMBER 0x17, 0x08, 0x44


void __asan_on_error() {}

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
	char *page_header_format;
}; // 20 + headerSize byte long in file

struct Header_event_info {
	char identificationString[13];
	guint64 eventHeaderInfoSize;
	char *event_header_format;
}; // 21 + eventHeaderInfoSize

struct Header {
	struct Initial_format initial_format;
	struct Header_info_format header_info_format;
	struct Header_event_info header_event_info;
};

struct Event_format {
	guint64 format_size;
	char *format;
	struct tep_event *tep_event;
};

struct Event_system {
	char *sys_name;
	guint32 event_format_count;
	struct Event_format *event_formats;
};

struct Event_systems {
	guint32 sys_count;
	struct Event_system *systems;
};

int headerParser(FILE  *fp, struct Header *header) {

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

	header->header_info_format.page_header_format = (char*) g_malloc(header->header_info_format.headerSize);
	fread(header->header_info_format.page_header_format, 1, header->header_info_format.headerSize, fp);

	fread(&header->header_event_info.identificationString, 1, sizeof(header->header_event_info.identificationString), fp);
	fread(&header->header_event_info.eventHeaderInfoSize, 1, sizeof(header->header_event_info.eventHeaderInfoSize), fp);
	header->header_event_info.event_header_format = (char*) g_malloc(header->header_event_info.eventHeaderInfoSize);
	fread(header->header_event_info.event_header_format, 1, header->header_event_info.eventHeaderInfoSize, fp);
	
	return 0;
}

int eventParser(FILE *fp, struct tep_handle *tep, struct Event_system *event_system){
	fread(&event_system->event_format_count, 1, sizeof(event_system->event_format_count), fp);
	
	event_system->event_formats = (struct Event_format*) g_malloc(event_system->event_format_count * sizeof(struct Event_format));

	for(int i=0; i < event_system->event_format_count; i++){
	 	struct Event_format *cur_event = &event_system->event_formats[i];
		fread(&cur_event->format_size, 1, sizeof(cur_event->format_size), fp);
	 	cur_event->format = (char*) g_malloc(cur_event->format_size);
	 	fread(cur_event->format, 1, cur_event->format_size, fp);

		enum tep_errno err = tep_parse_format(tep, &event_system->event_formats[i].tep_event, cur_event->format, cur_event->format_size, event_system->sys_name);
		if(err !=0) {
			printf("failed to parse\n");
			return 1;
		}
	}

	

	return 0;
}

gchar* readNullTerminated(FILE *fp) {
	gchar cur_char;
	GString *str = g_string_new(NULL);

	while ((cur_char = fgetc(fp)) != '\0') {
		g_string_append_c(str, cur_char);
	}

	return g_string_free(str, FALSE);
}

int systemParser(FILE *fp, struct tep_handle *tep, struct Event_systems *event_systems) {
	int err = fread(&event_systems->sys_count, sizeof(event_systems->sys_count), 1, fp);
	event_systems->systems = g_new(struct Event_system, event_systems->sys_count);

	for(int i = 0; i < event_systems->sys_count; i++) {
		event_systems->systems[i].sys_name = readNullTerminated(fp); //TODO: check error
		eventParser(fp, tep, &event_systems->systems[i]);
	}

	return 0;
}

int kallsysParser(FILE *fp) {
	guint32 size;
	fread(&size, 1, sizeof(size), fp);
	fseek(fp,size, SEEK_CUR);
	int i = ftell(fp);
	return 0;
}

int printkParser(FILE *fp) {
	guint32 size;
	fread(&size, 1, sizeof(size), fp);
	fseek(fp,size, SEEK_CUR);
	int i = ftell(fp);
	return 0;
}

int processInfoParser(FILE *fp) {
	guint64 size;
	fread(&size, 1, sizeof(size), fp);
	fseek(fp,size, SEEK_CUR);
	int i = ftell(fp);
	return 0;
}


bool validateMagicNumber(char header_magic_number[3]) {
	char magic_num[3] = {MAGIC_NUMBER};
	return (header_magic_number[0] == magic_num[0]) & (header_magic_number[1] == magic_num[1]) & (header_magic_number[2] == magic_num[2]) ;
}

int headerCheck(struct Header *header){
	if(!validateMagicNumber(header->initial_format.magicNumber)) {
		return true;//not an ftrace tace
	}

	return false;
}

void freeHeader(struct Header *header){
	free(header->header_info_format.page_header_format);
	free(header->header_event_info.event_header_format);
}


void freeEvents(struct Event_system *event_formats) {
	for(int i = 0; i < event_formats->event_format_count; i++) {
		free(event_formats->event_formats[i].format);
	}
	free(event_formats->event_formats);
}

void printFields(struct tep_format_field *format) {
	for (struct tep_format_field *field = format; field != NULL; field = field->next) {
		printf("      %s\n", field->name);
		printf("        type: %s\n", field->type);
		printf("        alias: %s\n", field->alias);
		printf("        offset: %d\n", field->offset);
		printf("        size: %d\n", field->size);
		printf("        arraylen: %u\n", field->arraylen);
		printf("        elemsize: %u\n", field->elementsize);
		printf("        flags: %lx\n", field->flags);
	}
}

void printEvent(const struct Event_format *event_format) {
	struct tep_event *event = event_format->tep_event;
	printf("  %s: %d\n", event->name, event->id);
	printf("    flag: %d\n", event->flags);
	
	printf("    fields:\n");
	
	printFields(event->format.common_fields);
	printFields(event->format.fields);
	
}

void printSystem(const struct Event_system * event_system) {
	printf("System: %s \n", event_system->sys_name);
	for (int i = 0; i < event_system->event_format_count; i++) {
		printEvent(&event_system->event_formats[i]);
	}
}

void printSystems(const struct Event_systems *event_systems) {
	for (int i = 0; i < event_systems->sys_count; i++) {
		printSystem(&event_systems->systems[i]);
	}
	
}

int main(int argc, char **argv){

	struct tep_handle *tep = tep_alloc();
	struct Header header;
	struct Event_system ftrace_event_formats;
	struct Event_systems event_systems;
	//CHECK ARGS
	FILE *fp = fopen(argv[1], "r");

	headerParser(fp, &header);
	if (headerCheck(&header)) {
		return -1; // TODO: assert
	}
	tep_parse_header_page(tep, header.header_info_format.page_header_format, header.header_info_format.headerSize, header.initial_format.usrLongSize);

	ftrace_event_formats.sys_name = "ftrace";
	eventParser(fp, tep, &ftrace_event_formats);
	printSystem(&ftrace_event_formats);

	systemParser(fp, tep, &event_systems);

	printSystems(&event_systems);


	kallsysParser(fp);

	printkParser(fp);

	processInfoParser(fp);

	guint32 cpu_count;
	fread(&cpu_count, 1, sizeof(cpu_count), fp);

	char *label = (char*)g_malloc(10);

	fread(label, 1, 10, fp);

	if(strcmp(label, "options  ")==0) {
		printf("option!\n");
		guint16 option_id;
		fread(&option_id, 1, sizeof(option_id), fp);

		guint32 option_size;
		if(option_id != 0){
			fread(&option_size, 1, sizeof(option_size), fp);
			fseek(fp,option_size, SEEK_CUR);
			int i = ftell(fp);
			int j = 9;
		}
	} 

	if(strcmp(label, "latency  ")) {
		printf("latency\n");
	} 
	if (strcmp(label, "flyrecord")) {
		printf("flyrecord\n");
	}

	free(label);
	fclose(fp);

	freeEvents(&ftrace_event_formats);
	freeHeader(&header);

	tep_free(tep);

	return 0;
}
