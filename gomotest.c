#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <curl/curl.h>
#include <pthread.h>
#include "jsmn.h"

static  CURL *curl;
static  CURLcode res;
#define logNow printf

static char sUrl_heartbeat[256]="";
static char sUrl_bookinglist[256]="";
static char sUrl_bookingaccept[256]="";
static char sUrl_bookingrelease[256]="";

struct MemoryStruct {
    char *memory;
    size_t size;
  };
static struct MemoryStruct chunk;

static void
stripQuotes (char *src, char *dest)
{
    int withinQuotes = 0;
    unsigned int i, j;

    for (i = 0, j = 0; i < strlen (src); i++)
    {
        // Detect any quotes
        if (src[i] == '"')
        {
            withinQuotes = !withinQuotes;
            continue;
        }

        if (!withinQuotes
                && (src[i] == ' ' || src[i] == '\t' || src[i] == '\n'
                    || src[i] == '\r'))
            continue;

        // Add the character
        dest[j++] = src[i];
    }

    dest[j] = '\0';
}

void *myrealloc(void *ptr, size_t size)
 {
   /* There might be a realloc() out there that doesn't like reallocing
      NULL pointers, so we take care of it here */
   if(ptr){
     return realloc(ptr, size);
   }
   else
     return calloc(size,1);
 }
 
size_t
WriteMemoryCallback(void *ptr, size_t size, size_t nmemb, void *data)
 {
   size_t realsize = size * nmemb;
   struct MemoryStruct *mem = (struct MemoryStruct *)data;
 
   mem->memory = (char *)myrealloc(mem->memory, mem->size + realsize + 1);
   if (mem->memory) {
     memcpy(&(mem->memory[mem->size]), ptr, realsize);
     mem->size += realsize;
     mem->memory[mem->size] = 0;
   }
   return realsize;
 }

int irisGomo_call(char *url,char* calltype,char *cli_string)
{
  chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */ 
  chunk.size = 0;    /* no data at this point */ 

  if(cli_string==NULL || strlen(cli_string)==0) {
    	if(chunk.memory) free(chunk.memory);
	return(-1);
  }

  if(calltype==NULL || strlen(calltype)==0 || ( strcmp(calltype,"PUT") && strcmp(calltype,"GET"))) {
    	if(chunk.memory) free(chunk.memory);
	return(-1);
  }

  curl = curl_easy_init();
  if(curl) {
 /* we want to use our own read function */ 
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);//setup curl connection with preferences
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, calltype);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, cli_string);

    /* Now run off and do what you've been told! */ 
    res = curl_easy_perform(curl);
    /* Check for errors */ 
    if(res != CURLE_OK)
      logNow( "GOMO:curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
   else {
    /*
     * Now, our chunk.memory points to a memory block that is chunk.size
     * bytes big and contains the remote file.
     *
     * Do something nice with it!
     */ 
 
      logNow("GOMO:%lu bytes retrieved[%s]\n", (long)chunk.size,chunk.memory);
    }
    //if(chunk.memory) free(chunk.memory);
 
    /* always cleanup */ 
    curl_easy_cleanup(curl);
  }

  return 0;
}

int irisGomo_get_id(char *tid ,char* gomo_driverid, char *gomo_terminalid)
{
	strcpy(gomo_driverid, "TA0001");
	strcpy(gomo_terminalid, "00000001");
	return(0);
}


int irisGomo_init()
{
	strcpy(sUrl_heartbeat,"http://gomoterminalproxy.elasticbeanstalk.com:80/v1/heartbeat/heartbeat");
	strcpy(sUrl_bookinglist,"http://dev.terminal.gm-mobile.com:80/v1/bookings/bookings");
	strcpy(sUrl_bookingaccept,"http://dev.terminal.gm-mobile.com:80/v1/bookings/accept");
	strcpy(sUrl_bookingrelease,"http://dev.terminal.gm-mobile.com:80/v1/bookings/release");
	return(0);
}

int irisGomo_convertJson_bookinglist(char *ser_string)
{
	char json[10240] = "";
	char iris_json[10240] = "";
	jsmn_parser p;
	jsmntok_t t[1024]; /* We expect no more than 1024 tokens */
	int i = 0,j=1;
	int icnt = 0;
	int booking_cnt = 0;

	strcpy( json,ser_string);
	jsmn_init(&p);
	icnt = jsmn_parse(&p, json, strlen(json), t, sizeof(t)/sizeof(t[0]));
	if (icnt < 0) {
		logNow("GOMO:Failed to parse JSON: %d\n", icnt);
		return 1;
	}

	/* Assume the top-level element is an object or array */
	if (icnt < 1 ) {
		return -1;
	}

	if(t[0].type == JSMN_OBJECT) {
		j = 1;
		booking_cnt = 1;
	}
	else if(t[0].type == JSMN_ARRAY) {
		j = 0;
		booking_cnt = t[0].size;
	} else {
		return(-1);
	}

	sprintf(iris_json,"{TYPE:DATA,NAME:GPS_RESP,STEP:BOOKINGLIST,COUNT:%d",booking_cnt); 

	for(i=1;i<icnt;i++) {
		char irisjson_tag[128]="";
		char irisjson_value[128]="";
		char stmp[128];

		if( t[i].type == JSMN_PRIMITIVE) {
			sprintf(stmp,"%.*s",t[i].end-t[i].start,json+t[i].start);
			sprintf(irisjson_value,"%s",stmp);
		} else if ( t[i].type == JSMN_OBJECT) {
			j++;
		} else if ( t[i].type == JSMN_ARRAY) {
		} else if ( t[i].type == JSMN_STRING) {
			sprintf(stmp,"%.*s",t[i].end-t[i].start,json+t[i].start);

			if( t[i].size == 1) {
				sprintf(irisjson_tag,"%s",stmp);
			} else {
				sprintf(irisjson_value,"%s",stmp);
			}
		}
		if(strlen(irisjson_tag)) {
			sprintf(stmp,",%s_%d:", irisjson_tag, j);
			strcat(iris_json,stmp);
		}
		if(strlen(irisjson_value)) {
			strcat(iris_json,irisjson_value);
		}
		
	}
	strcat(iris_json,"}");

	//logNow("newjson = [%s]", iris_json);
	strcpy(ser_string,iris_json);
	return(0);
}

int irisGomo_convertJson_bookingaccept(char *ser_string)
{
	char json[10240] = "";
	char iris_json[10240] = "";
	jsmn_parser p;
	jsmntok_t t[1024]; /* We expect no more than 1024 tokens */
	int i = 0,j=1;
	int icnt = 0;

	strcpy( json,ser_string);
	jsmn_init(&p);
	icnt = jsmn_parse(&p, json, strlen(json), t, sizeof(t)/sizeof(t[0]));
	if (icnt < 0) {
		logNow("GOMO:Failed to parse JSON: %d\n", icnt);
		return 1;
	}

	/* Assume the top-level element is an object or array */
	if (icnt < 1 ) {
		return -1;
	}

	if(t[0].type == JSMN_OBJECT) {
	}
	else if(t[0].type == JSMN_ARRAY) {
	} else {
		return(-1);
	}

	sprintf(iris_json,"{TYPE:DATA,NAME:GPS_RESP,STEP:BOOKINGACCEPT");

	for(i=1;i<icnt;i++) {
		char irisjson_tag[128]="";
		char irisjson_value[128]="";
		char stmp[128];

		if( t[i].type == JSMN_PRIMITIVE) {
			sprintf(stmp,"%.*s",t[i].end-t[i].start,json+t[i].start);
			sprintf(irisjson_value,"%s",stmp);
		} else if ( t[i].type == JSMN_OBJECT) {
		} else if ( t[i].type == JSMN_ARRAY) {
		} else if ( t[i].type == JSMN_STRING) {
			sprintf(stmp,"%.*s",t[i].end-t[i].start,json+t[i].start);

			if( t[i].size == 1) {
				sprintf(irisjson_tag,"%s",stmp);
			} else {
				char *p = stmp;
				while(*p!=0) {
					if(*p == ',') *p = ' '; //remove comma
					p++;
				}
				sprintf(irisjson_value,"%s",stmp);
			}
		}
		if(strlen(irisjson_tag)) {
			sprintf(stmp,",%s:", irisjson_tag);
			strcat(iris_json,stmp);
		}
		if(strlen(irisjson_value)) {
			strcat(iris_json,irisjson_value);
		}
		
	}
	strcat(iris_json,"}");

	//logNow("newjson = [%s]", iris_json);
	strcpy(ser_string,iris_json);
	return(0);
}

int irisGomo_heartbeat(char *cli_string,char *ser_string)
{
	int iret = 0;

	strcpy(ser_string,"");
	logNow("GOMO: heartbeat sending[%s]\n", cli_string);
	if(strlen(sUrl_heartbeat)==0) irisGomo_init();

	iret =  irisGomo_call(sUrl_heartbeat,"PUT",cli_string);
	if(iret==0) {
		if(chunk.memory) {
			stripQuotes(chunk.memory, ser_string);
			logNow("GOMO: heartbeat recv[%s]\n", ser_string);
		}
		
	}
	if(chunk.memory) {
		free(chunk.memory);
		chunk.memory = NULL;
	}
	return(0);

}

int irisGomo_bookinglist(char *cli_string,char *ser_string)
{
	int iret = 0;

	strcpy(ser_string,"");
	logNow("GOMO: bookinglist sending[%s]\n", cli_string);
	if(strlen(sUrl_bookinglist)==0) irisGomo_init();

	iret =  irisGomo_call(sUrl_bookinglist,"GET",cli_string);
	if(iret==0) {
		if(chunk.memory) {
			//stripQuotes(chunk.memory, ser_string);
			strcpy(ser_string,chunk.memory);
			logNow("GOMO: bookinglist recv[%s]\n", ser_string);
			if(strlen(ser_string)) {
				irisGomo_convertJson_bookinglist(ser_string);
			}
		}
		
	}
	if(chunk.memory) {
		free(chunk.memory);
		chunk.memory = NULL;
	}
	return(0);

}

int irisGomo_bookingaccept(char *booking_id,char *cli_string,char *ser_string)
{
	int iret = 0;
	char url[256] = "";

	strcpy(ser_string,"");
	logNow("GOMO: bookingaccept sending[%s]\n", cli_string);
	if(strlen(sUrl_bookingaccept)==0) irisGomo_init();
	sprintf(url,"%s/%s",sUrl_bookingaccept, booking_id);

	iret =  irisGomo_call(url,"PUT",cli_string);
	if(iret==0) {
		if(chunk.memory) {
			//stripQuotes(chunk.memory, ser_string);
			strcpy(ser_string,chunk.memory);
			if(strlen(ser_string)) {
				irisGomo_convertJson_bookingaccept(ser_string);
			}
			logNow("GOMO: bookingaccept recv[%s]\n", ser_string);
		}
		
	}
	if(chunk.memory) {
		free(chunk.memory);
		chunk.memory = NULL;
	}
	return(0);
}

int irisGomo_bookingrelease(char *cli_string,char *ser_string)
{
	int iret = 0;
	char url[256] = "";

	strcpy(ser_string,"");
	logNow("GOMO: bookingrelease sending[%s]\n", cli_string);

	if(strlen(sUrl_bookingrelease)==0) irisGomo_init();

	iret =  irisGomo_call(sUrl_bookingrelease,"PUT",cli_string);
	if(iret==0) {
		if(chunk.memory) {
			stripQuotes(chunk.memory, ser_string);
			logNow("GOMO: bookingrelease recv[%s]\n", ser_string);
		}
		
	}
	if(chunk.memory) {
		free(chunk.memory);
		chunk.memory = NULL;
	}
	return(0);
}


int main(void)
{
  irisGomo_call("http://gomoterminalproxy.elasticbeanstalk.com:80/v1/heartbeat/heartbeat", "PUT" , "driver_id=TA0001&terminal_id=00000001&latitude=11.123456&longitude=12.125412&availability=free" );
  irisGomo_call("http://dev.terminal.gm-mobile.com:80/v1/bookings/accept/181", "PUT" , "driver_id=TA0001" );

  return(0);
}
