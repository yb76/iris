/*
 * File: main.c
 * Description:	TCP/IP server for i-RIS
 */

//
// Standard include files
//
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/timeb.h>

#include <time.h>
#include <string.h>
#include <malloc.h>

#include "openssl/ssl.h"


//
// Project include files
//
#include "ws_util.h"
#ifdef USE_SQL_SERVER
	#include "sqlncli.h"
	#include "sql.h"
	#include "sqlext.h"
	#include "sqltypes.h"
#endif
#ifdef __REV
#include "revprepaymessage.h"
#endif
#ifdef __iREWARDS
#include "rewardmessage.h"
#endif
#ifdef __MEDICARE
#include "medicare_message.h"
#endif
#ifdef __DPS
#include "dps.h"
#endif
#ifdef __AMEX
#include "amex_m.h"
#endif

#ifdef USE_MYSQL
	#include <mysql.h>
	#define	db_error(mysql, res)					mysql_error(mysql)
void * get_thread_dbh();
void * set_thread_dbh();
MYSQL * get_new_mysql_dbh();
#endif

#ifdef WIN32
	#include "getopt.h"
	#define pthread_mutex_init(mutex, x)
	#define pthread_mutex_lock(mutex)
	#define pthread_mutex_unlock(mutex)
	#define pthread_mutex_destroy(mutex)
	#define pthread_self()	0
	struct CRYPTO_dynlock_value { int mutex; };

	#define MSG_NOSIGNAL	0
	#define	localtime_r(a,b)	localtime(a)
	#define sleep(x)			Sleep(x * 1000)
#else

#ifndef USE_MYSQL
	#define	MYSQL_RES								PGresult
	#define	MYSQL									PGconn
	#define	db_error(mysql, res)					PQresultErrorMessage(res)
	#define	mysql_close(mysql)						PQfinish(mysql)
	#include <libpq-fe.h>
#endif

#ifdef epay
	#include <risexec.h>
#endif

	#include <getopt.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <netdb.h>
	#include <pthread.h>
	#include <errno.h>
	#include <signal.h>
	static pthread_mutex_t logMutex;
	//static pthread_mutex_t dbMutex;
	static pthread_mutex_t counterMutex;
	static pthread_mutex_t hsmMutex;

	static pthread_mutex_t *mutex_buf = NULL;
	struct CRYPTO_dynlock_value
	{
		pthread_mutex_t mutex;
	};
#endif


//
// Local include files
//
#include "zlib.h"
#include "macro.h"
#include "3des.h"

typedef struct
{
	SOCKET sd;
	struct sockaddr_in sinRemote;
} T_THREAD_DATA;

//MYSQL * mysql;
int ris_amount = 20000;
int triggerb = 20000;
int rewardb = 2000;
int stan = 0;
int order = 243574;

const unsigned char master[16] =	{0x02, 0x04, 0x08, 0x10, 0x02, 0x04, 0x08, 0x10, 0x02, 0x04, 0x08, 0x10, 0x02, 0x04, 0x08, 0x10};
const unsigned char master_hsm[2][16] =	{	{0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04},
											{0x6B, 0xA1, 0x89, 0xF1, 0x5E, 0xCE, 0x0B, 0x3E, 0xAB, 0x08, 0xB6, 0xEA, 0xB5, 0x1F, 0x0D, 0x25}
										};
const unsigned char ppasn[8] =	{0x07, 0x25, 0x43, 0x61, 0x8F, 0xAB, 0xCD, 0xE9};


static FILE * stream = NULL;
int debug = 1;

int sleepTime = 0;
char * rewardIPAddress = "127.0.0.1";
char * rewardPortNumber = "32002";
char * medicareIPAddress = "127.0.0.1";
char * medicarePortNumber = "32000";
char * deviceGatewayIPAddress = "localhost";
int deviceGatewayPortNumber = 20301;
char * eracomIPAddress = "192.168.1.20";
int eracomPortNumber = 21100;
char * datawireIPAddress = "stagingsupport.datawire.net";
#define C_DATAWIRE_RX_BUF_SIZE	3000
//char * datawireIPAddress = "support.datawire.net";
char * portalIPAddress = "54.252.96.159";
char * portalPortNumber = "11000";
char * ttsIPAddress = "54.253.254.201";
char * ttsPortNumber = "44340";
int g_portal_sd = 0;

char * datawireDirectory = "/nocportal/SRS.do";
int datawireNewSSL = 0;
int datawireTimeout = 5;
char * revIPAddress = "127.0.0.1";
char * revPortNumber = "32001";
char * logFile = "/home/tareq/irisLog";
int strictSerialNumber = 1;
int noTrace = 0;
int running = 1;
int test = 0;
int scan = 0;
int hsm = 0;
int hsm_no = 0;
int hsm_sd = -1;
int ignoreHSM = 0;
int iRewards = 0;
int iScan = 0;
int dispMessage = 0;
int maxZipPacketSize = 5000;
int minZipPacketSize = 1000;

#define NORMAL_SOCKET_WAITTIME	1800
#define	END_SOCKET_WAITTIME		0
int waitTime = NORMAL_SOCKET_WAITTIME;

int counter = 0;

char reference[30];
char amount[30];
char fastcode[30];
char userid[30];
char password[30];
char quantity[30];
char selection[50];

char promocode[50];
char mobile[50];
char gender[20];
char location[20];

long delta_time = 0;
int background_update = 0;

//// Constants /////////////////////////////////////////////////////////
void logNow(const char * format, ...);

void* my_malloc (size_t size,int from)
{
	void* ptr = malloc(size);

	if(ptr) {
		logNow(	"\nmy_malloc line%ld:size%d:ptr%ld \n", from,size,(unsigned long)ptr);
		return(ptr);	
	}
	else {
		logNow(	"\nmy_malloc failed line%ld:size%d \n", from,size);
		return(NULL);
	}
}

void my_free (void* ptr,int from)
{
	logNow( "\nmy_free line%ld::ptr%ld \n", from,ptr);	
	return(free(ptr));	
}

/*
**-------------------------------------------------------------------------------------------
** FUNCTION   : UtilHexToString
**
** DESCRIPTION:	Transforms hex byte array to a string. Each byte is simply split in half.
**				The minimum size required is double that of the hex byte array
**
** PARAMETERS:	hex			<=	Array to store the converted hex data
**				string		=>	The number string.
**				length		<=	Length of hex byte array
**
** RETURNS:		The converted string
**-------------------------------------------------------------------------------------------
*/
char * UtilHexToString(unsigned char * hex, int length, char * string)
{
	int i;

	if (string)
	{
		string[0] = '\0';

		if (hex)
		{
			for (i = 0; i < length; i++)
				sprintf(&string[i*2], "%02X", hex[i]);
		}
	}

	return string;
}

static void counterIncrement(void)
{
	// Counter critical section
	pthread_mutex_lock(&counterMutex);
	counter++;
	pthread_mutex_unlock(&counterMutex);
}

static void counterDecrement(void)
{
	// Counter critical section
	pthread_mutex_lock(&counterMutex);
	counter--;
	pthread_mutex_unlock(&counterMutex);
}

static void logStart(void)
{
	// Initialise
	stream = stdout;

#ifndef WIN32
	// Open the appropriate stream
	if ((stream = fopen(logFile, "a+")) == NULL)
		stream = stdout;
#endif

	// Initialise the log mutex
	pthread_mutex_init(&logMutex, NULL);
}

void logEnd(void)
{
	fclose(stream);

	pthread_mutex_destroy(&logMutex);
}

static void dbStart(void)
{
	// Start of log critical section
	//pthread_mutex_lock(&dbMutex);
}

static void dbEnd(void)
{
	// free log mutex and unlock other threads
	//pthread_mutex_unlock(&dbMutex);
}

static char * timeString(char * string, int len)
{
	struct tm *newtime;
#ifndef WIN32
	struct tm temp;
#endif
	struct timeb tb;

	ftime(&tb);
	newtime = localtime_r(&tb.time, &temp);
	strftime(string, len, "%a, %d/%m/%Y %H:%M:%S", newtime);
	sprintf(&string[strlen(string)], ".%03ld", tb.millitm);

	return string;
}

int logArchive(FILE **stream, long maxSize)
{
#ifndef WIN32
	int result;

	if (stream && *stream != NULL && *stream != stderr && *stream != stdout && ftell(*stream) > maxSize)
	{
		char cmd[400];

		// Log file too large - gzip the current file and start over.
		// Archive name: <path>"<logfile>-DDMMYY.gz"
		if ((result = snprintf(cmd, sizeof(cmd), "gzip -f -S -`date +%%y%%m%%d%%H%%M`.gz %s", logFile)) < 0)
			return -1;

		fclose(*stream);

		system(cmd);

		/* Old log file discarded by gzip */
		if ((*stream = fopen(logFile, "a+")) == NULL)
			*stream = stdout;
	}
#else
	(void)stream;
	(void)maxSize;
#endif

	return 1;
}

void logNow(const char * format, ...)
{
	va_list args;
	va_start( args, format );

	// Start of log critical section
	pthread_mutex_lock(&logMutex);

	// Print formatted message
	vfprintf(stream, format, args);
	fflush(stream);

	// check and archive
	logArchive(&stream, (10000*1024L));

	// free log mutex and unlock other threads
	pthread_mutex_unlock(&logMutex);

	va_end(args);
}

static void displayComms(char * header, char * data, int len)
{
	int i, j, k;
	char * line;

	if (dispMessage == 0) return;

	line = my_malloc(strlen(header) + (4 * len) + (len / 16 * 4) + 200,__LINE__);
	if (line == NULL) return;

	strcpy(line, header);
	strcat(line, "\n");

	for (i = 0, k = strlen(line); i < len;)
	{
		for (j = 0; j < 16; j++, i++)
		{
			if (i < len)
				sprintf(&line[k], "%02.2X ", (BYTE) data[i]);
			else
				strcat(line, "   ");
			k += 3;
		}

		strcat(line, "   ");
		k += 3;

		for (j = 0, i -= 16; j < 16; j++, i++)
		{
			if (i < len)
			{
				if (data[i] == '%')
				{
					line[k++] = '%';
					line[k++] = '%';
				}
				else if (data[i] >= ' ' && data[i] <= '~')
					line[k++] = data[i];
				else
					line[k++] = '.';
			}
			else line[k++] = ' ';
		}

		line[k++] = '\n';
		line[k] = '\0';
	}

	strcat(line, "\n");
	logNow(line);
	my_free(line,__LINE__);
}


static unsigned long shrink(char * objects)
{
    z_stream c_stream; /* compression stream */
    int err;
    uLong len = (uLong)strlen(objects)+1;
	unsigned long comprLen = len + 200;		// It should be smaller but just in case it actually grows. Small data can possibly cause this.
	unsigned char * compr = my_malloc(comprLen,__LINE__);	

    c_stream.zalloc = (alloc_func)0;
    c_stream.zfree = (free_func)0;
    c_stream.opaque = (voidpf)0;

    err = deflateInit(&c_stream, Z_DEFAULT_COMPRESSION);
//    CHECK_ERR(err, "deflateInit");

    c_stream.next_in  = (Bytef*)objects;
    c_stream.next_out = compr;

    while (c_stream.total_in != len && c_stream.total_out < comprLen)
	{
        c_stream.avail_in = c_stream.avail_out = 1; /* force small buffers */
        err = deflate(&c_stream, Z_NO_FLUSH);
//      CHECK_ERR(err, "deflate");
    }

    /* Finish the stream, still forcing small buffers: */
	for (;;)
	{
		c_stream.avail_out = 1;
		err = deflate(&c_stream, Z_FINISH);
		if (err == Z_STREAM_END) break;
//		CHECK_ERR(err, "deflate");
	}

	err = deflateEnd(&c_stream);
//	CHECK_ERR(err, "deflateEnd");

	// Update the objects with the compressed objects data
	memcpy(objects, compr, c_stream.total_out);
	my_free(compr,__LINE__);

	return c_stream.total_out;
}

static int databaseInsert(MYSQL* dbh, char * query, char * errorMsg)
{
	int result;
#ifndef USE_MYSQL
	MYSQL_RES * res;
#endif

	//  Add the object
	if(dbh==NULL) return(FALSE);

	dbStart();
#if defined(USE_MYSQL)
	if (mysql_real_query(dbh, query, strlen(query)) == 0) // success
#endif
		result = TRUE;
	else
	{
		if (errorMsg) strcpy(errorMsg, db_error(dbh, res));
		result = FALSE;
	}

	dbEnd();

	return result;
}

static long databaseCount(MYSQL *dbh,char * query)
{
	long count = -1;
	MYSQL_RES * res;

	if(dbh==NULL) return(0);
	dbStart();

#ifdef USE_MYSQL
	if (mysql_real_query(dbh, query, strlen(query)) == 0) // success
	{
		MYSQL_ROW row;

		if (res = mysql_store_result(dbh))
		{
			if (row = mysql_fetch_row(res))
			{
				if(strlen(row[0])) count = atol(row[0]);
			}
			mysql_free_result(res);
		}
	}
#endif

	dbEnd();

	return count;
}

int getFileData(char **pfileData,char *filename,int *len)
{
	FILE *fp = fopen(filename,"rb");
	int fileLen = 0;
	int nRead = 0;
	char *dataBuffer = NULL;

	*len = 0;
	*pfileData = NULL;
	
	if(fp!= NULL ) {
		fseek (fp , 0 , SEEK_END);
		fileLen = ftell (fp);
		rewind (fp);
		*pfileData = my_malloc( fileLen + 1,__LINE__ );
		nRead = fread(*pfileData,1,fileLen,fp);
		*len = nRead;
		fclose(fp);
	}
	return(*len);
}

int getObjectField(char * data, int count, char * field, char ** srcPtr, const char * tag)
{
	char * ptr;
	int i = 0;
	int j = 0;

	if (srcPtr)
	{
		if ((*srcPtr = strstr(data, tag)) == NULL)
			return 0;
		else
			return (strlen(*srcPtr));
	}

	// Extract the TYPE
	if ((ptr = strstr(data, tag)) != NULL)
	{
		for (--count; ptr[i+strlen(tag)] != ',' && ptr[i+strlen(tag)] != ']' && ptr[i+strlen(tag)] != '}' ; i++)
		{
			for(; count; count--, i++)
			{
				for(; ptr[i+strlen(tag)] != ','; i++);
			}
			field[j++] = ptr[i+strlen(tag)];
		}
	}

	field[j] = '\0';

	return strlen(field);
}

int getNextObject(unsigned char * request, unsigned int requestLength, unsigned int * offset,
				  char * type, char * name, char * version, char * event, char * value, char * object, char * json,
				  unsigned char * iv, unsigned char * MKr, unsigned int * currIVByte, char * serialnumber)
{
	unsigned int i;
	char data;
	unsigned int length = 0;
	int marker = 0;
	char temp[50];

	if (debug) logNow(	"\n%s:: Next OBJECT:: ", timeString(temp, sizeof(temp)));

	for (i = *offset; i < requestLength; i++)
	{
		data = request[i];

		// If currentIV at the beginning of an 8-byte block, encrypt IV using MKr
		if (iv)
		{
			if (*currIVByte % 8 == 0)
				Des3Encrypt(MKr, iv, 8);

			// Get the data in the clear
			data ^= iv[(*currIVByte)%8];
			(*currIVByte)++;
		}

		// If the marker is detected, start storing the JSON object
		if (marker || data == '{')
			json[length++] = data;

		// If we detect the start of an object, increment the object marker
		if (data == '{')
			marker++;

		// If we detect graphic characters, do not process any further - corrupt message
		/* Bo Yang 29/03/2017 */
		else if (((unsigned char) data) > 0x7F)
		{
			logNow("Invalid JSON object: %02X. No further processing....\n", data);
			/*return -1;*/
		}
		else if (marker<=0)
		{
			logNow("Invalid JSON object: %c\n", data);
		}
		/**************/ 
		// IF we detect the end of an object, decrement the marker
		else if (data == '}')
		{
			marker--;
			if (marker < 0)
			{
				logNow("Incorrectly formated JSON object. Found end of object without finding beginning of object\n");
				return -1;
			}
			if (marker == 0)
			{
				i++;
				break;
			}
		}
	}

	// Set the start of the next object search
	*offset = i;

	// If the object exist...
	if (length)
	{
		// Terminate the "json" string
		json[length] = '\0';

		// Extract the type field
		getObjectField(json, 1, type, NULL, "TYPE:");

		if (strcmp(type, "IDENTITY") == 0)
		{
			// Extract the serial number field
			getObjectField(json, 1, name, NULL, "SERIALNUMBER:");

			// Extract the manufacturer field
			getObjectField(json, 1, version, NULL, "MANUFACTURER:");

			// Extract the model field
			getObjectField(json, 1, event, NULL, "MODEL:");

			// Output the data in the clear
			if (debug) logNow("%s\n", json);

			return 1;
		}
		else if (strcmp(type, "GETFILE") == 0)
		{
			// Extract the file name
			getObjectField(json, 1, name, NULL, "NAME:");

			// Output the data in the clear
			if (debug) logNow("%s\n", json);

			return 2;
		}
		else
		{
			// Extract the name field
			getObjectField(json, 1, name, NULL, "NAME:");

			// Extract the version field
			getObjectField(json, 1, version, NULL, "VERSION:");

			// Extract the event field
			getObjectField(json, 1, event, NULL, "EVENT:");

			// Extract the value field
			getObjectField(json, 1, value, NULL, "VALUE:");

			// Extract the object field
			getObjectField(json, 1, object, NULL, "OBJECT:");

			// Output the data in the clear
			if (debug)
			{
				if (strncmp(name, "iTAXI_TXN", strlen("iTAXI_TXN")) == 0)
				{
					char * comma = NULL;
					char * ptr = strstr(json, "PAN:");
					if (ptr) comma = strchr(ptr, ',');
					logNow("%.*s%s%s\n", ptr?(ptr-json):strlen(json), json, ptr?"PAN:REMOVED":"", comma?comma:"");
				}
				else if (strcmp(name, "iPAY_RIS_TXN_REQ") == 0)
				{
					unsigned int i;
					char temp[1000];
					int mask = 0;

					for (i = 0; i < strlen(json); i++)
					{
						int skip = 0;

						switch (mask)
						{
							default:
							case 0:
								if (strncmp(&json[i], "TRACK2:", 6) == 0 || strncmp(&json[i], "TRACK1:", 6) == 0 || strncmp(&json[i], "PAN:", 4) == 0 || strncmp(&json[i], "CCV:", 4) == 0 || strncmp(&json[i], "EXPIRY:", 7) == 0)
									mask = 1;
								break;
							case 1:
								if (json[i] == ':') mask = 2;
								break;
							case 2:
								if (json[i] == ',' || json[i] == '}')
									mask = 0;
								else
									temp[i] = '*', skip = 1;
								break;
						}

						if (!skip) temp[i] = json[i];
					}
					temp[i] = '\0';
					logNow(":+:+:%s:+:+:%s\n", serialnumber, temp);
				}
				else logNow(":+:+:%s:+:+:%s\n", serialnumber, json);
			}

			return 0;
		}
	}
	else logNow("No more...\n");

	return -99;
}

void OFBObjects(unsigned char * response, unsigned long length, char * serialnumber, unsigned char * ivTx)
{
	unsigned int i;
	unsigned char block[16];
	unsigned int currIVTxByte = 0;

	// Get the MKs encryption key to use for OFB encryption
	FILE * fp = fopen(serialnumber, "r+b");

	// If only we can find the file, and we should normally...
	if (fp)
	{
		// Read the encryption key..
		fseek(fp, 32, SEEK_SET);
		fread(block, 1, 16, fp);
		fclose(fp);

		// XOR the data
		for (i = 0; i < length; i++)
		{
			if (currIVTxByte % 8 == 0)
				Des3Encrypt(block, ivTx, 8);

			response[i] ^= ivTx[currIVTxByte%8];
			currIVTxByte++;
		}
	}
}

static void addObject(unsigned char ** response, char * data, int ofb, unsigned int offset, unsigned int maskLength)
{
	char temp[50];

	// If empty additional data, do not bother adding....
	if (data[0] == '\0')
		return;

	my_malloc_max( response, 10240, strlen(data)+1);

	// Output object to be sent
	if (debug)
	{
		if (maskLength)
			logNow("\n%s:: Sending Object:: %.*s **** OBJECT LOGGING TRUNCATED ****\n", timeString(temp, sizeof(temp)), maskLength, data);
		else
			logNow("\n%s:: Sending Object:: %s\n", timeString(temp, sizeof(temp)), data);
	}

	strcat(*response, data);

	if (ofb)
		(*response)[offset-9] = '1';
}

static void newRandomKey(FILE * fp, char * label, char * authMsg, unsigned char * key, unsigned char * variant)
{
	int i;
	unsigned char block[16];
	unsigned char varKey[16];

	// Prepare a Master variant of 0x82 to encrypt
	for (i = 0; i < 16; i++)
	{
		varKey[i] = key[i] ^ variant[0]; i++;
		varKey[i] = key[i] ^ variant[1];
	}

	// Generate a new random key for the terminal
	for (i = 0; i < 16; i++)
		block[i] = (unsigned char) rand();

	// Store new key for terminal
	fwrite(block, 1, 16, fp);

	// Encypt it for sending to the terminal
	Des3Encrypt(varKey, block, 16);

	// Add it to the authentication response object
	strcat(authMsg, label);
	for (i = 0; i < 16; i++)
		sprintf(&authMsg[strlen(authMsg)], "%0.2X", block[i]);
}

// ------------------------------------------------------------------------------------------
// SSL support functions
// ------------------------------------------------------------------------------------------


int my_malloc_max(unsigned char **buff, int maxlen, int currlen)
{
	int ilen = 0;

	if(*buff==NULL) {
		*buff = calloc( maxlen,1 );
		logNow(	"\nmy_malloc_max :size%d:ptr%ld \n", maxlen,(unsigned long)*buff);
	} else {
		ilen = strlen(*buff) + currlen + 1;
		if(ilen > maxlen) {
			*buff = realloc(*buff, ilen);
			logNow(	"\nmy_malloc_max exceed:size%d:ptr%ld \n", ilen,(unsigned long)*buff);
		}
	}

	return(0);
}

static FLAG examineAuth(unsigned char ** response, unsigned int * offset, char * json, char * serialnumber, unsigned char * iv)
{
	int i;
	FILE * fp;
	FLAG send = FALSE;
	FLAG newKEK = FALSE;
	char authMsg[300];
	char temp[100];
	char extra[100];
	unsigned char block[16];
	unsigned char key[16];
	unsigned char zero[8];

	// Prepare the authentication message
	strcpy(authMsg, "{TYPE:AUTH,RESULT:");

	// Check HSM availability
	/* Disabled 30/04/2017 */
	/*
	pthread_mutex_lock(&hsmMutex);
	if (hsm && ignoreHSM == 0 && SendToHSM())
	{
		pthread_mutex_unlock(&hsmMutex);
		strcat(authMsg, "HSM ERROR}000000000");

		my_malloc_max( response, 10240, strlen(authMsg)+1);

		strcat(*response, authMsg);
		*offset = strlen(*response);

		return TRUE;
	}
	pthread_mutex_unlock(&hsmMutex);
	*/


	if (json)
	{
		// Get the KVC string's value
		getObjectField(json, 1, extra, NULL, "KVC:");
		memset(zero, 0, sizeof(zero));

		temp[0] = '\0';
		if ((fp = fopen(serialnumber, "r+b")) != NULL)
		{
			fseek(fp, 16, SEEK_SET);
			fread(block, 1, 16, fp);
			Des3Encrypt(block, zero, 8);
			sprintf(temp, "%0.2X%0.2X%0.2X", zero[0], zero[1], zero[2]);
			fclose(fp);
		}

		// Lose the iPAY_CFG file if the terminal has been swapped out
		if (strcmp(extra, "000000") == 0)
		{
			FILE * fp;
			char fname[100];

			sprintf(fname, "%s.iPAY_CFG", serialnumber);

			if ((fp = fopen(fname, "rb")))
			{
				char cmd[300];
				struct tm *newtime;
#ifndef WIN32
				struct tm temp;
#endif
				struct timeb tb;

				logNow("\n%s:: ***SWAP OUT DETECTED*** for %s\n", timeString(cmd, sizeof(cmd)), serialnumber);

				fclose(fp);
				ftime(&tb);
				newtime = localtime_r(&tb.time, &temp);

				sprintf(cmd, "mv %s.iPAY_CFG keep/%s.iPAY_CFG.", serialnumber, serialnumber);
				strftime(&cmd[strlen(cmd)], 50, "%Y%m%d%H", newtime);
				system(cmd);
			}
		}
	}

	// If KVC does not match, update KEK and send along with PPASN to the terminal
	if (json == NULL || fp == NULL || strcmp(temp, extra))
	{
		// Tell the terminal that a new session is required
		strcat(authMsg, "NEW SESSION");
		send = newKEK = TRUE;

		// Store new KEK for terminal for use later on when exchanging session keys (MKr, MKs, and other for other applications....)
		if ((fp = fopen(serialnumber, "w+b")) == NULL) return TRUE;

		// Get a new random KEK, update auth message response and close the KEK storage file for the terminal
		newRandomKey(fp, ",KEK:", authMsg, (char *) (hsm? master_hsm[hsm_no]:master), "\x82\xC0");
		fclose(fp);

		// Prepare an encrypted PPASN but with varinat \x88\x88
		memcpy(block, ppasn, 8);
		for (i = 0; i < 16; i++) key[i] = (hsm? master_hsm[hsm_no][i]:master[i]) ^ 0x88;

		// Encrypt PPASN
		Des3Encrypt(key, block, 8);

		// Add encrypted PPASN to the authentication response object
		strcat(authMsg, ",PPASN:");
		for (i = 0; i < 8; i++)
			sprintf(&authMsg[strlen(authMsg)], "%0.2X", block[i]);				
	}

	if (send == FALSE)
	{
		// Get the PROOF string's value
		getObjectField(json, 1, extra, NULL, "PROOF:");
		for (i = 0; i < 16; i++)
		{
			temp[i] = (extra[i*2] >= 'A'? (extra[i*2] - 'A' + 0x0A):(extra[i*2] - '0')) << 4;
			temp[i] |= (extra[i*2+1] >= 'A'? (extra[i*2+1] - 'A' + 0x0A):(extra[i*2+1] - '0'));
		}

		// Open the key file for reading...Change to HSM later
		if ((fp = fopen(serialnumber, "r+b")) == NULL) return TRUE;
		fseek(fp, 48, SEEK_SET);
		fread(block, 1, 16, fp);
		fclose(fp);

		// Decrypt using MKr
		Des3Decrypt(block, &temp[8]);
		for (i = 0; i < 8; i++)
			temp[8+i] ^= temp[i];
		Des3Decrypt(block, temp);

		// Update the IV used for OFB'ing the rest of the objects from the terminal
		if (iv) memcpy(iv, temp, 8);

		if (memcmp(&temp[8], "\xCA\xFE\xBA\xBE\xDE\xAF\xF0\x01", 8))
			send = TRUE;
	}

	if (send == TRUE)
	{
		unsigned char ppasn_16[16];
		unsigned char ppasn_16_k[16];
		unsigned char ppasn_16_k2[16];

		// Open the key file for reading...Change to HSM later
		if ((fp = fopen(serialnumber, "r+b")) == NULL) return TRUE;

		// If a new KEK was added, then vary using KEK to get KEK1
		if (newKEK)
		{
			// Read KEK from the file
			fread(block, 1, 16, fp);

			// Vary KEK using PPASN|PPASN
			for (i = 0; i < 8; i++)
			{
				block[i] ^= ppasn[i];
				block[i+8] ^= ppasn[i];
			}
		}
		else
		{
			strcat(authMsg, "NEW SESSION");

			// Read the current KEK1 from the file
			fseek(fp, 16, SEEK_SET);
			fread(block, 1, 16, fp);
		}

		// Prepare some temporary PPASN blocks for use during OWF operation
		for (i = 0; i < 8; i++)
		{
			ppasn_16[i] = ppasn_16_k[i] = ppasn_16_k2[i] = ppasn[i];
			ppasn_16[i+8] = ppasn_16_k[i+8] = ppasn_16_k2[i+8] = ppasn[i];
		}

		// OWF, find the MAB
		Des3Encrypt(block, ppasn_16, 16);

		// Use MAB of PPASN|PPASN as an initial vector to encrypting PPASN again
		for (i = 0; i < 8; i++)
			ppasn_16_k[i] ^= ppasn_16[i+8];

		// Encrypt PPASN|PPASN again using the MAB of the first encryption as an IV.
		Des3Encrypt(block, ppasn_16_k, 16);

		// The result is the new KEK1 to use after XORING it with PPASN|PPASN
		for (i = 0; i < 16; i++)
			block[i] = ppasn_16_k[i] ^ ppasn_16_k2[i];

		// Read the new KEK1 int the file. Update within HSM later.
		fseek(fp, 16, SEEK_SET);
		fwrite(block, 1, 16, fp);

		// Send a new MKs session key
		newRandomKey(fp, ",MKs:", authMsg, block, "\x22\xC0");

		// Send a new MKr session key
		newRandomKey(fp, ",MKr:", authMsg, block, "\x44\xC0");

		// Close the authentication object
		strcat(authMsg, "}000000000");

		fclose(fp);

		my_malloc_max( response, 10240, strlen(authMsg)+200+1);

		strcat(*response, authMsg);
		*offset = strlen(*response);

		return TRUE;
	}

	// Return TRUE if a new session is required AND the server should not send further objects
	strcat(authMsg, "YES GRANTED}000000000");

	my_malloc_max( response, 10240, strlen(authMsg)+1);
	strcat(*response, authMsg);
	*offset = strlen(*response);

	return FALSE;
}

static void addQuotes(char * src, char * dest)
{
	unsigned int i,j;
	int tagValue = 0;

	for (i = 0, j = 0; i < strlen(src); i++)
	{
		if (tagValue == 0)
		{
			// Add an preceding quotes if required
			if (src[i] == ':')
			{
				dest[j++] = '"';
				tagValue = 1;
			}

			// Add the character from the identity object
			if (src[i] == '"' || src[i] == '\\')
				dest[j++] = '\\';
			dest[j++] = src[i];

			// Add a quote at the end if required
			if (src[i] == '{' || src[i] == ':')
				dest[j++] = '"';
		}
		else
		{
			// Add an preceding quotes if required
			if (src[i] == '}' || src[i] == ',')
			{
				dest[j++] = '"';
				tagValue = 0;
			}

			// Add the character from the identity object
			if (src[i] == '"' || src[i] == '\\')
				dest[j++] = '\\';
			dest[j++] = src[i];

			// Add a quote at the end if required
			if (src[i] == ',')
				dest[j++] = '"';
		}

	}

	dest[j] = '\0';
}

static void stripQuotes(char * src, char * dest)
{
	int withinQuotes = 0;
	unsigned int i,j;

	for (i = 0, j = 0; i < strlen(src); i++)
	{
		// Detect any quotes
		if (src[i] == '"')
		{
			withinQuotes = !withinQuotes;
			continue;
		}

		if (!withinQuotes && (src[i] == ' ' || src[i] == '\t' || src[i] == '\n' || src[i] == '\r'))
			continue;

		// Add the character
		dest[j++] = src[i];
	}

	dest[j] = '\0';
}

int upgrade(unsigned char ** response, unsigned int offset, char * serialnumber, int bigPacket, int * percentage, int terminal_count, long * new_position, int phase)
{
	FILE * fp;
	char temp[300];
	long position = 0;
	int count = 0;
	int retVal = 0;

	// Initialisation
	if (percentage) *percentage = 0;

	// Get the file packet next position if available
	sprintf(temp, "%s.upg", serialnumber);
	if ((fp = fopen(temp, "r")) != NULL)
	{
		fgets(temp, sizeof(temp), fp);
		position = atol(temp);
		if (new_position && phase == 0) *new_position = position;

		fgets(temp, sizeof(temp), fp);
		count = atoi(temp);

		fclose(fp);
	}

	// Update the server count/position with the terminal count/position if available just in case of comms failure
	sprintf(temp, "%s.upg", serialnumber);
	if (terminal_count >= 0 && terminal_count <= count && new_position && *new_position && (fp = fopen(temp, "w")) != NULL)
	{
		if (!background_update || (minZipPacketSize == maxZipPacketSize))
		{
			if ((*new_position / maxZipPacketSize) < terminal_count)
				terminal_count = (*new_position / maxZipPacketSize);
			*new_position = (terminal_count * maxZipPacketSize);
		}

		fprintf(fp, "%ld\n", *new_position);
		position = *new_position;

		fprintf(fp, "%d\n", terminal_count);
		count = terminal_count;
		fclose(fp);
	}

	// Now read xxx bytes from the file starting at the last offest
	sprintf(temp, "%s.zip", serialnumber);

	// For phase 2, download the app
	if (phase == 2)
	{
		// Remove the upgrade files...all done.
		remove(temp);
		sprintf(temp, "%s.upg", serialnumber);
		remove(temp);

		// Merge the file...
		sprintf(temp, "{TYPE:MERGE,NAME:%s.zip,MAX:%d}", serialnumber, count);
		addObject(response, temp, 1, offset, 0);

		// Tell the operating system what to unzip
		sprintf(temp, "{TYPE:ENV,KEY:*UNZIP,VALUE:%s.zip}", serialnumber);
		addObject(response, temp, 1, offset, 0);

		// Remove the hot key message
		addObject(response, "{TYPE:EXPIRE,NAME:iRIS_OFFER}", 1, offset, 0);

		// Tell the terminal to reboot
		addObject(response, "{TYPE:SHUTDOWN}", 1, offset, 0);

		return 0;
	}

	if ((fp = fopen(temp, "rb")) != NULL)
	{
		int i, size, index;
		unsigned char * data = my_malloc(bigPacket?maxZipPacketSize:minZipPacketSize,__LINE__);

		// Get the file size
		if (percentage && fseek(fp, 0, SEEK_END) == 0)
		{
			long fileSize = ftell(fp);
			*percentage = position * 100 / fileSize;
		}

		// If we have already transmitted the file....
		if (fseek(fp, position, SEEK_SET) != 0 || (size = fread(data, 1, bigPacket?maxZipPacketSize:minZipPacketSize, fp)) < 1)
		{
			retVal = 3;
		}
		else if (phase == 1)
		{
			char * fileObject = my_malloc((bigPacket?maxZipPacketSize:minZipPacketSize) * 2 + 100,__LINE__);

			// Prepare the header of the next file packet
			sprintf(fileObject, "{TYPE:FILE,NAME:%s.zip_%d,DATA:", serialnumber, count);

			// Convert the file data to ASCII
			for (i = 0, index = strlen(fileObject); i < size; i++)
			{
				fileObject[index++] = (data[i] >= 0xA0)? ((data[i] >> 4) - 0x0A + 'A'):((data[i] >> 4) + '0');
				fileObject[index++] = ((data[i] & 0x0F) >= 0x0A)? ((data[i] & 0x0F) - 0x0A + 'A'):((data[i] & 0x0F) + '0');
			}

			// Add the trailer of the next file packet.
			fileObject[index++] = '}';
			fileObject[index] = '\0';

			// Add the next file packet in the object queue to be transmitted to the terminal
			if (new_position || background_update)
				addObject(response, fileObject, 1, offset, 0);
			if (bigPacket) retVal = 2;
			else retVal = 1;

			// Clearing house
			free(fileObject);

			if (new_position) *new_position = position + (bigPacket?maxZipPacketSize:minZipPacketSize);
		}
		else retVal = -1;

		// Clearing house...
		free(data);
		fclose(fp);
	}

	return retVal;
}

void upgrade_advance(char * serialnumber, int packetSize)
{
	FILE * fp;
	char temp[30];
	long position = 0;
	int count = 0;

	// Get the current upgrade count value
	sprintf(temp, "%s.upg", serialnumber);
	if ((fp = fopen(temp, "r")) != NULL)
	{
		char string[20];
		fgets(string, sizeof(string), fp);
		position = atol(string);
		fgets(string, sizeof(string), fp);
		count = atoi(string);
		fclose(fp);
	}

	// Increment and update the upgrade count file...
	if ((fp = fopen(temp, "w")) != NULL)
	{
		fprintf(fp, "%ld\n", (background_update && (minZipPacketSize != maxZipPacketSize))?(position + packetSize):((count+1) * packetSize));
		fprintf(fp, "%d\n", ++count);
		fclose(fp);
	}
}

static int new_tagValue(FILE * fp1, FILE * fp2, char * tag, char * value, int replace)
{
	int i, j;
	int size;
	unsigned char data;

	// Get the original tag
	for (size = fread(&data, 1, 1, fp1), i = 0; size == 1 && data != ':' && data != '}'; i++, size = fread(&data, 1, 1, fp1))
	{
		if (data != '{' && data != ',')
			tag[i] = data;
		else i = -1;
	}
	if (i == 0 || size != 1) return 0;
	tag[i++] = ':';
	tag[i] = '\0';

	// Get the original value
	for (size = fread(&data, 1, 1, fp1), i = 0; data != ',' && data != '}'; i++, size = fread(&data, 1, 1, fp1))
		value[i] = data;
	if (size != 1) return 0;
	value[i] = '\0';

	// Search for the tag in the other file...
	for (fseek(fp2, 0, SEEK_SET), size = fread(&data, 1, 1, fp2), i = 0, j = 0; size == 1; i++, size = fread(&data, 1, 1, fp2))
	{
		if (tag[j] == data)
			j++;
		else j = 0;

		if (tag[j] == '\0') break;
	}

	// If found, replace the original value with the new value found in the other file, but only if requested
	if (j && tag[j] == '\0')
	{
		if (!replace) return 2;

		for (size = fread(&data, 1, 1, fp2), i = 0; size == 1 && data != ','  && data != '}'; i++, size = fread(&data, 1, 1, fp2))
			value[i] = data;
		if (size != 1) return 0;
		value[i] = '\0';
	}

	return 1;
}

void send_out_object(char * fileName, char * inFileName, char * outFileName, unsigned char ** response, unsigned int offset)
{
	FILE * fp;
	FILE * in_fp;
	FILE * out_fp;
	int first = 1;

	// Make sure the in file is available
	if ((in_fp = fopen(inFileName, "rb")) != NULL)
	{
		// Make sure we can create an out file
		if ((out_fp = fopen(outFileName, "w+b")) != NULL)
		{
			// Make sure we can read the original file
			if ((fp = fopen(fileName, "rb")) != NULL)
			{
				unsigned char tag[100];
				unsigned char value[1000];
				unsigned char tagValue[1150];

				// Replace original tag values with new ones
				for(;;)
				{
					if (new_tagValue(fp, in_fp, tag, value, 1) == 0)
						break;

					// Write the "out" tag:value pair
					sprintf(tagValue, "%c%s%s", first?'{':',', tag, value);
					fwrite(tagValue, 1, strlen(tagValue), out_fp);
					first = 0;
				}
							
				// Add new tag:value pairs
				for(fseek(in_fp, 0, SEEK_SET);;)
				{
					int result = new_tagValue(in_fp, fp, tag, value, 0);
					if (result == 0)
						break;

					if (result == 1)
					{
						// Write the "out" tag:value pair
						sprintf(tagValue, ",%s%s", tag, value);
						fwrite(tagValue, 1, strlen(tagValue), out_fp);
					}
				}

				// Close the "out" object
				fwrite("}", 1, 1, out_fp);

				fclose(fp);
			}

			fclose(out_fp);

			// Send the new file
			if ((out_fp = fopen(outFileName, "rb")) != NULL)
			{
				char line[300];

				while (fgets(line, 300, out_fp) != NULL)
					addObject(response, line, 1, offset, 0);

				fclose(out_fp);
				remove(outFileName);
			}
		}

		fclose(in_fp);
		remove(inFileName);
	}
}

void get_mid_tid(char * serialnumber, char * __mid, char * __tid)
{
	FILE * fp;
	char tmp[1000];
	int i;

	// Get the current terminal TID and MID
	sprintf(tmp, "%s.iPAY_CFG", serialnumber);
	if ((fp = fopen(tmp, "r")) != NULL)
	{
		if (fgets(tmp, sizeof(tmp), fp))
		{
			char * tid = strstr(tmp, "TID:");
			char * mid = strstr(tmp, "MID:");
			if (__tid)
			{
				if (tid)
					sprintf(__tid, "%8.8s", &tid[4]);
				else strcpy(__tid, "");
			}
			if (__mid)
			{
				if (mid)
				{
					for (i = 4; mid[i] != ',' && mid[i] != '}' && mid[i]; i++)
						__mid[i-4] = mid[i];
					__mid[i-4] = '\0';
				}
				else strcpy(__mid, "");
			}
		}
		fclose(fp);
	}
}


int processRequest(SOCKET sd, unsigned char * request, unsigned int requestLength, char * serialnumber, int * unauthorised)
{
	char type[100];
	union
	{
		char name[100];
		char serialnumber[100];
	}u;
	union
	{
		char version[100];
		char manufacturer[100];
	}u2;
	union
	{
		char event[100];
		char model[100];
	}u3;
	char value[100];
	char object[100];
	char json[4000];
	char query[5000];
	unsigned int requestOffset = 0;
	unsigned char * response = NULL;
	unsigned int offset = 0;
	unsigned long length = 0;
	int objectType, lastObjectType;
	char model[20];
	unsigned char iv[8];
	unsigned char ivTx[8];
	unsigned char MKr[16];
	unsigned int currIVByte = 0;
	FLAG ofb = FALSE;
	char identity[500];
	int update = 0;
	int sd_dg = -1;
	int sd_rx = 0;
	int iPAY_CFG_RECEIVED = 0;
	int iTAXI_batchno = 0;
	int iSCAN_SAF_RECEIVED = 0;
	int iFUEL_SAF_RECEIVED = 0;
	//MessageMCA mcamsg;
	//MYSQL *dbh = (MYSQL *)get_thread_dbh();
	MYSQL *dbh = NULL;
	int nextmsg = 0;
	T_WEBREQUEST xmlreq;
	T_WEBRESP xmlresp;
	char tid[30]="";
	char temp[50]="";
	int dldexist = 0;
	int send_once = 0;
	char appversion[30]="";
	int nosend = 0;

	// Increment the unauthorised flag
	(*unauthorised)++;

	// Examine request an object at a time for trigger to download objects
	while((objectType = getNextObject(request, requestLength, &requestOffset, type, u.name, u2.version, u3.event, value, object, json, ofb?iv:NULL, MKr, &currIVByte, serialnumber)) >= 0)
	{
		int id = 0;

		// Process the device identity
		lastObjectType = objectType;
		if (objectType == 1)
		{
			// Add it in. If a duplicate, it does not matter but just get the ID back later
			strcpy(serialnumber, u.serialnumber);
			strcpy(model, u3.model);

			// Display merchant details TID, MID and ADDRESS for debugging purposes if available
			{
				FILE * fp;
				char tmp[1000];

				sprintf(tmp, "%s.iPAY_CFG", serialnumber);
				if ((fp = fopen(tmp, "r")) != NULL)
				{
					if (fgets(tmp, sizeof(tmp), fp))
					{
						char * tid = strstr(tmp, "TID:");
						char * addr2 = strstr(tmp, "ADDR2:");
						char * addr3 = strstr(tmp, "ADDR3:");

						logNow("*+*+*+*+*+*+*+*+*+*+*+*+* %12.12s,%26.26s,%26.26s +*+*+*+*+*+*+*+*+*+*+*+*\n", tid?tid:"oOoOoOoO", addr2?addr2:"", addr3?addr3:"");
					}
					fclose(fp);
				}
			}

			strcpy(identity, json);

			continue;
		}

		// Do not allow the object download to continue if the device has not identified itself
		if (serialnumber[0] == '\0')
			continue;

		// If this is an authorisation, then examine the proof
		if (strcmp(type, "AUTH") == 0 )
		{
			FILE * fp;
			char temp[300];
			int position = 0;

			// If a new session is required, stop here and send the new session details to the terminal
			if (examineAuth(&response, &offset, json, serialnumber, iv) == TRUE)
				break;

			// Set the TX Initial Vector
			memcpy(ivTx, iv, sizeof(iv));

			// No new sesion required, so enable OFB'ing the rest of the message to get the clear objects out
			ofb = TRUE;

			// If there is a specific message to the terminal, add it now
			sprintf(temp, "%s.dld", serialnumber);
			if ((fp = fopen(temp, "rb")) != NULL)
			{
				char line[300];

				while (fgets(line, 300, fp) != NULL)
					addObject(&response, line, 1, offset, 0);

				fclose(fp);
				remove(temp);
				dldexist = 1;
			} else {
				char tid[100] ="";
				char mid[100] ="";
				get_mid_tid(serialnumber, mid, tid);
				if(strlen(tid)) {
				  sprintf(temp, "T%s.dld", tid);
				  if ((fp = fopen(temp, "rb")) != NULL)
				  {
					char line[1024];
					while (fgets(line, 1024, fp) != NULL)
						addObject(&response, line, 1, offset, 0);
					fclose(fp);
					remove(temp);
					dldexist = 1;
				  }

				}
			}

			// Get the MKr key to use for OFB decryption
			if ((fp = fopen(serialnumber, "r+b")) == NULL)
				break;
			fseek(fp, 48, SEEK_SET);
			fread(MKr, 1, 16, fp);
			fclose(fp);
			continue;
		}

		// From this point onward, OFB must have been enabled and objects received from terminal must have been OFB'd properly
		if (ofb == FALSE)
			continue;
		(*unauthorised) = 0;

		// If the type == DATA, then just store it in the object list for further processing at a later time
		if (strcmp(type, "DATA") == 0)
		{
			char extra[100];

			//db connection check
			if(dbh==NULL && (
				(strcmp(u.name, "iPAY_CFG") == 0) ||
				(strcmp(u.name, "iTAXI_CFG") == 0) ||
				(strncmp(u.name, "iTAXI_TXN", strlen("iTAXI_TXN")) == 0) ||
				(strncmp(u.name, "iTAXI_TPAY", strlen("iTAXI_TPAY")) == 0)
			)) {
				dbh = (MYSQL *) get_new_mysql_dbh();
			}

			// Process transactions
			if (strcmp(u.name, "iPAY_CFG") == 0)
			{
				FILE * fp;
				char fname[100];
				char temp[100];

				sprintf(fname, "%s.iPAY_CFG", serialnumber);

				// Download any initial updates
				if ((fp = fopen(fname, "rb")) == NULL)
				{
					if ((fp = fopen("UPDATE.INI", "rb")) != NULL)
					{
						char line[300];

						while (fgets(line, 300, fp) != NULL)
							addObject(&response, line, 1, offset, 0);

						fclose(fp);
					}
				}
				else fclose(fp);

				fp = fopen(fname, "w+b");
				fwrite(json, 1, strlen(json), fp);
				fclose(fp);

				iPAY_CFG_RECEIVED = 1;
				getObjectField(json, 1, tid, NULL, "TID:");

				{
					char DBError[200];

					sprintf(query,"INSERT INTO terminal_connection(serial,tid,time) VALUES ('%s','%s',now()) ON DUPLICATE KEY UPDATE tid='%s',time=now()",serialnumber,tid,tid);

					// Add the object
					if (databaseInsert(dbh,query, DBError))
						logNow( "PAY_CFG ==> SN:%s, TID:%s **ADDED**\n", serialnumber, tid);
					else
						logNow( "Failed to insert PAY_CFG object.  Error: %s\n", DBError);
				}

			}

			else if (strcmp(u.name, "iRIS_POWERON") == 0)
			{
				FILE * fp;

				if ((fp = fopen("BOOT.INI", "rb")) != NULL)
				{
					char line[300];

					while (fgets(line, 300, fp) != NULL)
						addObject(&response, line, 1, offset, 0);

					fclose(fp);
				}
			}
			else if (strcmp(u.name, "IRIS_CFG") == 0)
			{
				FILE * fp;
				char fname[100];
				char inFileName[100];
				char outFileName[100];

				sprintf(fname, "%s.iRIS_CFG", serialnumber);
				fp = fopen(fname, "w+b");
				fwrite(json, 1, strlen(json), fp);
				fclose(fp);

			}
			else if (strcmp(u.name, "iTAXI_CFG_INIT") == 0)
			{
				char tid[10] = "";
				char query[100];
				long batchno=1;
				long inv_no=1;

				getObjectField(json, 1, tid, NULL, "TID:");
				sprintf(query, "SELECT ifnull(max(batchno),0) FROM batch WHERE tid='%s' ", tid);
				batchno = databaseCount(dbh,query);
				if(batchno<1) batchno=1;
				sprintf(query, "{TYPE:SETJSON,NAME:iTAXI_CFG,TAG:BATCH,VALUE:%06d}", batchno);
				addObject(&response, query, 1, offset, 0);

				sprintf(query, "SELECT ifnull(max(invoice),0) FROM transaction WHERE tid='%s' ", tid);
				inv_no = databaseCount(dbh,query);
				if(inv_no>=1) {
					sprintf(query, "{TYPE:SETJSON,NAME:iTAXI_CFG,TAG:INV,VALUE:%d}", inv_no+1);
					addObject(&response, query, 1, offset, 0);
					sprintf(query, "{TYPE:SETJSON,NAME:iTAXI_CFG,TAG:LAST_INV,VALUE:%06d}", inv_no);
					addObject(&response, query, 1, offset, 0);
				}
				{
				FILE * fp;
				char tmp[1000];
				int i;

				sprintf(tmp, "%s.iTAXI_CFG", serialnumber);
				if ((fp = fopen(tmp, "r")) != NULL)
				{
				  if (fgets(tmp, sizeof(tmp), fp))
				  {
					char comm[10] =  "";
					char header0[30] = "";
					char header1[30] = "";
					getObjectField(tmp, 1, comm, NULL, "COMM:");
					getObjectField(tmp, 1, header0, NULL, "HEADER0:");
					getObjectField(tmp, 1, header1, NULL, "HEADER1:");
					if(strlen(comm)) {
					  sprintf(query, "{TYPE:SETJSON,NAME:iTAXI_CFG,TAG:COMM,VALUE:%s}", comm);
					  addObject(&response, query, 1, offset, 0);
					}
					if(strlen(header0)) {
					  sprintf(query, "{TYPE:SETJSON,NAME:iTAXI_CFG,TAG:HEADER0,VALUE:%s}", header0);
					  addObject(&response, query, 1, offset, 0);
					}
					if(strlen(header1)) {
					  sprintf(query, "{TYPE:SETJSON,NAME:iTAXI_CFG,TAG:HEADER1,VALUE:%s}", header1);
					  addObject(&response, query, 1, offset, 0);
					}
				  }
				  fclose(fp);
				}
				}
				sprintf(query, "{TYPE:SHUTDOWN}");
				addObject(&response, query, 1, offset, 0);
			}
			else if (strcmp(u.name, "iTAXI_CFG") == 0)
			{
				FILE * fp;
				char fname[100];
				char inFileName[100];
				char outFileName[100];
				char terminalID[10] = "????????";
				char toinv[20] = "";
				char batch[20] = "";
				char version[20];
				int batchno = 0;
				int frominv = 1;

				getObjectField(json, 1, toinv, NULL, "LAST_INV:");
				getObjectField(json, 1, batch, NULL, "BATCH_SENT:");
				getObjectField(json, 1, version, NULL, "VERSION:");
				strcpy(appversion,version);

				if(version && version[0] >= '2') {
					batchno = atoi(batch) - 1;
				} else if(strlen(batch))
					batchno = atoi(batch);
				iTAXI_batchno = batchno;

				if(strlen(toinv)&&strlen(batch)) {
					sprintf(fname, "%s.iTAXI_CFG", serialnumber);
					fp = fopen(fname, "w+b");
					fwrite(json, 1, strlen(json), fp);
					fclose(fp);
				}

				if (iPAY_CFG_RECEIVED == 0 && batchno >= 1 && toinv[0])
				{
					FILE * fp;
					char fname[100];

					sprintf(fname, "%s.iPAY_CFG", serialnumber);

					// Download the heartbeat to the terminal to refresh it.
					if ((fp = fopen(fname, "rb")) != NULL)
					{
						char heartbeat[500];
						char new_heartbeat[500];

						if (fread(heartbeat, 1, sizeof(heartbeat), fp) >= 50)
						{
							char * prchnum = strstr(heartbeat, "PRCHNUM:");
							char * transnum = strstr(heartbeat, "TRANSNUM:");

							if (prchnum && transnum)
							{
								char lastinv[20] = "1";
								char temp[40];
								char * transnum_start = strchr(prchnum, ',');

								if (transnum_start)
								{
									getObjectField(json, 1, lastinv, NULL, "LAST_INV:");

									memset(new_heartbeat, 0, sizeof(new_heartbeat));
									memcpy(new_heartbeat, heartbeat, prchnum - heartbeat);
									sprintf(temp, "PRCHNUM:%s", lastinv);
									strcat(new_heartbeat, temp);
									memcpy(&new_heartbeat[strlen(new_heartbeat)], transnum_start, transnum - transnum_start);
									sprintf(temp, "TRANSNUM:%s}", lastinv);
									strcat(new_heartbeat, temp);

									addObject(&response, new_heartbeat, 1, offset, 0);
								}
							}
							else addObject(&response, heartbeat, 1, offset, 0);
						}

						fclose(fp);
					}
				}

				// Send the out object if an "in" file object exists
				sprintf(inFileName, "%s.iTAXI_CFG.in", serialnumber);
				sprintf(outFileName, "%s.iTAXI_CFG.out", serialnumber);
				send_out_object(fname, inFileName, outFileName, &response, offset);

				if (batchno >= 1 && toinv[0])
				{
					char DBError[200];

					// Get current terminal TID
					get_mid_tid(serialnumber, NULL, terminalID);

					// Get the starting invoice number
					if (batchno == 1)
						frominv = 1;
					else if (terminalID[0])
					{
						MYSQL_RES * res;

						sprintf(query, "SELECT toinv FROM batch WHERE tid='%s' AND batchno < '%d' order by batchno desc limit 1", terminalID, batchno);

						dbStart();
						#ifdef USE_MYSQL
							if (dbh!=NULL && mysql_real_query(dbh, query, strlen(query)) == 0) // success
							{
								MYSQL_ROW row;

								if (res = mysql_store_result(dbh))
								{
									if (row = mysql_fetch_row(res))
										frominv = atoi(row[0]) + 1;
									mysql_free_result(res);
								}
							}
						#endif
						dbEnd();
					}

					// Insert it into the database
				      if(frominv==atoi(toinv)+1) { //strange , same invoice as last batch, probably empty trans with TPAY trans
					char resp_ok[256];
					logNow( "Same invoice as last batch , no need to insert batch\n");
					sprintf(resp_ok, "{TYPE:DATA,NAME:iTAXI_RESULT,VERSION:1.0,TEXT:OK}");
					addObject(&response, resp_ok, 1, offset, 0);
				      } else {
					int iret = 0;
					if(frominv>atoi(toinv)) {
						frominv = 1;
						logNow( "BATCH insert, frominv = %d, old [%d]\n", frominv,atoi(toinv));
					}
					sprintf(query,	"INSERT INTO batch values('%d','%s',now(),'%d','%d', '0',now(),'system')", batchno, terminalID, frominv, atoi(toinv));

					// Add the batch
					iret = databaseInsert(dbh,query, DBError);
					if (iret || (strncmp(DBError, "Duplicate entry", 15) == 0))
					{
						char resp_ok[256];
						logNow( "BATCH ==> TID:%s, Batch:%d, From:%d, To:%s ***ADDED***\n", terminalID, batchno, frominv, toinv); 
						sprintf(resp_ok, "{TYPE:DATA,NAME:iTAXI_RESULT,VERSION:1.0,TEXT:OK}");
						addObject(&response, resp_ok, 1, offset, 0);
					}
					else 
						logNow( "Failed to insert BATCH object.  Error: %s\n", DBError);
				      }
				}
				/*********
				if(version && version[0] >= '2' && model) {
					char updfile[30];
					char line[300];
					sprintf(updfile,"UPDATE.iTAXI_CFG.%s.%s",model,version);
					if ((fp = fopen(updfile, "rb")) != NULL) {
						logNow( "ITAXI UPDATE old version %s,TID:%s, update file: %s\n", version, terminalID,updfile);
						while (fgets(line, 300, fp) != NULL) addObject(&response, line, 1, offset, 0);
						fclose(fp);
					}

				}
				**********/

				// terminal connection
				if (iPAY_CFG_RECEIVED) {
					char DBError[200];
					sprintf(query,"UPDATE terminal_connection set version='%s',TaxiCfg='%s',Time=now() where Serial='%s'",
						version,json,serialnumber);

					// Add the object
					if (databaseInsert(dbh,query, DBError))
						logNow( "TAXI_CFG ==> SN:%s, VERSION:%s **UPDATEED**\n", serialnumber, version);
					else
						logNow( "Failed to update PAY_CFG object.  Error: %s\n", DBError);
				}
			}

			else if (strncmp(u.name, "iTAXI_TXN", strlen("iTAXI_TXN")) == 0)
			{
				char DBError[200];
				struct tm txn_time, * txn_time_ptr;
				char driver[100];
				char abn[60];
				char date[20];
				char mytime[20];
				char tid[20];
				char stan[20];
				char invoice[20];
				char meter[30];
				char fare[30];
				char total[30];
				char comm[30];
				char pickup[60];
				char dropoff[60];
				char pan[60];
				char cardno[60];
				char * panLength = NULL, * last4Digits = NULL;
				char account[20];
				char rc[10];
				char authid[20];
				time_t now = time(NULL);

				// Get the fields
				getObjectField(json, 1, driver, NULL, "DRIVER:");
				getObjectField(json, 1, abn, NULL, "ABN:");
				getObjectField(json, 1, date, NULL, "DATE:");
				getObjectField(json, 1, mytime, NULL, "TIME:");
				getObjectField(json, 1, tid, NULL, "TID:");
				getObjectField(json, 1, stan, NULL, "STAN:");
				getObjectField(json, 1, invoice, NULL, "INV:");
				getObjectField(json, 1, meter, NULL, "METER:");
				getObjectField(json, 1, fare, NULL, "FARE:");
				getObjectField(json, 1, total, NULL, "TOTAL:");
				getObjectField(json, 1, comm, NULL, "COMM:");
				getObjectField(json, 1, pickup, NULL, "PICK_UP:");
				getObjectField(json, 1, dropoff, NULL, "DROP_OFF:");
				getObjectField(json, 1, pan, NULL, "PAN:");
				getObjectField(json, 1, cardno, NULL, "CARDNO:");
				getObjectField(json, 1, account, NULL, "ACCOUNT:");
				getObjectField(json, 1, rc, NULL, "RC:");
				getObjectField(json, 1, authid, NULL, "AUTHID:");

				// Lose the PAN until we get Diners back on board
				memset(pan, 0, sizeof(pan));

				// Work out the time in seconds
				txn_time_ptr = localtime(&now);
				txn_time.tm_mday = (date[0] - '0') * 10 + date[1] - '0';
				txn_time.tm_mon = (date[2] - '0') * 10 + date[3] - '0' - 1;
				txn_time.tm_year = txn_time_ptr->tm_year;
				if (txn_time_ptr->tm_mon < txn_time.tm_mon)
					txn_time.tm_year--;

				txn_time.tm_hour = (mytime[0] - '0') * 10 + mytime[1] - '0';
				txn_time.tm_min = (mytime[2] - '0') * 10 + mytime[3] - '0';
				txn_time.tm_sec = (mytime[4] - '0') * 10 + mytime[5] - '0';

				// Work out the card details
				last4Digits = strrchr(cardno, ' ');
				if (last4Digits) *last4Digits = '\0', panLength = strrchr(cardno, ' ');
				if (panLength) *panLength = '\0';

				// Insert it into the database
#ifdef USE_MYSQL
				sprintf(query,	"INSERT INTO transaction values(default,'%8.8s','%d-%02d-%02d %02d:%02d:%02d','%s','%s','%d','%d'"
								",'%d','%d','%d','%d'"
								",'%s','%s','%s'"
								",'%s','%s','%s'"
								",'%s','%s','%s')",
								tid,
								txn_time.tm_year + 1900, txn_time.tm_mon + 1, txn_time.tm_mday, txn_time.tm_hour, txn_time.tm_min, txn_time.tm_sec,
								driver, abn, atoi(stan), atoi(invoice),
								atoi(meter), atoi(fare), atoi(total), atoi(comm),
								pickup, dropoff, pan,
								cardno, panLength?panLength+1:"0", last4Digits?last4Digits+1:"0",
								account, rc, authid);
#else
				sprintf(query,	"INSERT INTO txn values(default,'%8.8s','%d','%s','%s','%d','%d'"
								",'%d','%d','%d','%d'"
								",'%s','%s','%s'"
								",'%s','%s','%s'"
								",'%s','%s','%s')",
								tid, mktime(&txn_time), driver, abn, atoi(stan), atoi(invoice),
								atoi(meter), atoi(fare), atoi(total), atoi(comm),
								pickup, dropoff, pan,
								cardno, panLength?panLength+1:"0", last4Digits?last4Digits+1:"0",
								account, rc, authid);
#endif

				// Add the transaction
				if (databaseInsert(dbh,query, DBError))
				{
					if (strcmp(u.name, "iTAXI_TXN0") == 0)
					{
						char resp_ok[256];
						sprintf(resp_ok, "{TYPE:DATA,NAME:iTAXI_RESULT,VERSION:1.0,TEXT:OK}");
						addObject(&response, resp_ok, 1, offset, 0);
					}
					logNow( "TXN ==> TID:%s, Invoice:%s ***ADDED***\n", tid, invoice);

					//TIPS
					{
						char tips[20]="";
						getObjectField(json, 1, tips, NULL, "TIP:");
						if(strlen(tips)>0) {
							sprintf(query,	"INSERT INTO transtips ( transid,tid,time,invoice,tips) values "
							" (LAST_INSERT_ID(),'%8.8s','%d-%02d-%02d %02d:%02d:%02d','%d','%d')",
							tid,txn_time.tm_year+1900,txn_time.tm_mon+1,txn_time.tm_mday,txn_time.tm_hour,txn_time.tm_min,txn_time.tm_sec,
							atoi(invoice),atoi(tips));
							if (databaseInsert(dbh,query, DBError)) {
								logNow( "TIP ==> TID:%s, Invoice:%s ***ADDED***\n", tid, invoice);
							} else {
								logNow( "Failed to insert TXN object.  Error: %s\n", DBError);
								logNow( "date = [%s], sql= [%s]\n", date,query);
							}
						}
					}
				}
				else
				{
					logNow( "Failed to insert TXN object.  Error: %s\n", DBError);
					logNow( "date = [%s], sql= [%s]\n", date,query);
					if (strncmp(DBError, "Duplicate entry", 15) == 0)
					{
						if (strcmp(u.name, "iTAXI_TXN0") == 0)
						{
							char resp_ok[256];
							sprintf(resp_ok, "{TYPE:DATA,NAME:iTAXI_RESULT,VERSION:1.0,TEXT:OK}");
							addObject(&response, resp_ok, 1, offset, 0);
						}
					}
				}
			}

			else if (strncmp(u.name, "iTAXI_TPAY", strlen("iTAXI_TPAY")) == 0)
			{
				char DBError[200];
				char date[20]="0";
				char tid[20]="0";
				char jobid[20]="0";
				char meter[30]="0";
				char fare[30]="0";
				char pretip[30]="0";

				// Get the fields
				getObjectField(json, 1, date, NULL, "DATE:");
				getObjectField(json, 1, tid, NULL, "TID:");
				getObjectField(json, 1, jobid, NULL, "JOBID:");
				getObjectField(json, 1, meter, NULL, "METER:");
				getObjectField(json, 1, fare, NULL, "FARE:");
				getObjectField(json, 1, pretip, NULL, "PRETIP:");

				if(!strlen(jobid)) strcpy(jobid,"0");
				if(!strlen(date)) strcpy(date,"0101010101");
				if(!strlen(meter)) strcpy(meter,"0");
				if(!strlen(fare)) strcpy(fare,"0");
				if(!strlen(pretip)) strcpy(pretip,"0");

				// Insert it into the database
				sprintf(query,	"INSERT INTO gomo_tpaytrans (id,tid,jobid,devicetime,meter,pretip,fare,modifytime) values(default,'%8.8s',%s,'%s',%s,%s,%s,now())", tid,jobid,date,meter,pretip,fare);

				// Add the transaction
				if (databaseInsert(dbh,query, DBError))
				{
					if (send_once == 0)
					{
						char resp_ok[256];
						sprintf(resp_ok, "{TYPE:DATA,NAME:iTAXI_RESULT,VERSION:1.0,TEXT:OK}");
						addObject(&response, resp_ok, 1, offset, 0);
						send_once = 1;
					}
					logNow( "TPAY ==> TID:%s, JOB:%s ***ADDED***\n", tid, jobid);

				}
				else
				{
					logNow( "Failed to insert TPAY object.  Error: %s\n", DBError);
					logNow( " sql= [%s]\n", query);
					if (strncmp(DBError, "Duplicate entry", 15) == 0)
					{
						if (send_once == 0)
						{
							char resp_ok[256];
							sprintf(resp_ok, "{TYPE:DATA,NAME:iTAXI_RESULT,VERSION:1.0,TEXT:OK}");
							addObject(&response, resp_ok, 1, offset, 0);
							send_once = 1;
						}
					}
				}
			}

			else if (strcmp(u.name, "iPAY_CFG") == 0)
			{
				// If we are in the middle of upgrading, just say so...
				if ((update = upgrade(&response, offset, serialnumber, 0, NULL, -1, NULL, 1)) != 0)
				{
					if (update == 1)
						sprintf(query, "{TYPE:DATA,NAME:iRIS_OFFER,GROUP:iRIS,HOT:UPDATE IN PROGRESS ->,F1:iRIS_HOT}");
					else
						sprintf(query, "{TYPE:DATA,NAME:iRIS_OFFER,GROUP:iRIS,HOT:UPDATE COMPLETE ->,F1:iRIS_HOT}");
					addObject(&response, query, 1, offset, 0);
					continue;
				}

				if (test == 0)
					continue;

			}

#ifdef __GPS
			else if ( 0 && strcmp(u.name, "GPS_REQ") == 0) /* Disabled 30/04/2017 */
			{
				int tts_sd = 0;
				tts_sd = tcp_connect( ttsIPAddress , atoi( ttsPortNumber ));
				if(tts_sd>0)
				{
					char line[10240];
					int msgsent = 0;
					char header[3];
					int iLen = 0;
					int iRet = 0;
					struct timeval timeout;


					iLen = strlen(json)+1;
					header[0] = iLen / 256;
					header[1] = iLen % 256;
					iRet = tcp_send ( tts_sd, 2, header);
					if(iRet>0) {
						iRet = tcp_send ( tts_sd, iLen, json);
						logNow( "GOMO_SEND[%s] \n", json);
						if(iRet==iLen) {
							timeout.tv_sec = 20;
							timeout.tv_usec = 100;
							setsockopt(tts_sd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
							int nReadBytes = tcp_recv(tts_sd, 2, header);
							if(nReadBytes>0) {
								iLen = (unsigned char )header[0] * 256 + (unsigned char )header[1];
								memset(line,0,sizeof(line));
								nReadBytes = tcp_recv(tts_sd, iLen, line);
								if(strlen(line) && line[0] == '{') {
									logNow( "GOMO_RECEIVED[%s] \n", line);
									addObject(&response, line, 1, offset, 0);
								}
							}
						}
					}
					tcp_close(tts_sd);
				}

			
			}
#endif

			continue;
		}

	}

	if (iPAY_CFG_RECEIVED == 1 && dldexist == 0 ) { // local download
	//if ( dldexist == 0 ) { // local download
				FILE * fp;
				char fname[100];
				int downloadqueue = 0;
				char dq_id[32]="";
				char dq_fname[64]="";
				char dq_object[64]="";

				sprintf(fname,"%s.mdld", serialnumber);
				fp = fopen(fname, "rb");
				if(fp==NULL)  {
					sprintf(fname,"T%s.mdld", tid);
					fp = fopen(fname, "rb");
				}

				if(fp==NULL) {
					char queue[1024]="";

					// Check if we have the service provider URLs available
					sprintf(query, "select id,filename,type from downloadqueue where tid = '%s' and endtime is null and queueid = ( select min(queueid) from downloadqueue where tid = '%s' and endtime is null);", tid,tid);
					dbStart();
					#ifdef USE_MYSQL
					if (dbh!=NULL && mysql_real_query(dbh, query, strlen(query)) == 0) // success
					{
						MYSQL_RES * res;
						MYSQL_ROW row;

						if (res = mysql_store_result(dbh))
						{
							if (row = mysql_fetch_row(res))
							{
								if (row[0])
								{
									strcpy(dq_id, row[0]);
									strcpy(dq_fname, row[1]);
								}
								if (row[2])
									strcpy(dq_object, row[2]);
							}
							mysql_free_result(res);
						}
					}
					#endif
					dbEnd();

					if(strlen(dq_fname) && 
					  (strlen(dq_object)==0 || strcmp(u.name,dq_object)==0)) {
						downloadqueue = 1;
						strcpy( fname, dq_fname);
						fp = fopen(fname, "rb");
					}
				}

				if (fp!= NULL)
				{
					char line[4096];
					int filesend;
					struct timeval timeout;
					char * fp_line = NULL;

					timeout.tv_sec = 15;     // If the connection stays for more than 15 seconds, lose it.
					timeout.tv_usec = 100;
					setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

					// for EFB enabled message iTAXI_RESULT
					if(response&&strlen(response)> 10) {
						char resultstr[64];
						char *ptr = NULL;

						response[offset-9] = '0';

						strcpy(resultstr, "{TYPE:DATA,NAME:iTAXI_RESULT,VERSION:1.0,TEXT:OK}");
						ptr = strstr(response,resultstr);
						if(ptr) {
							strcpy(ptr, "{TYPE:DATA,NAME:iTAXI_RESULT,NEXTMSG:1,VERSION:1.0,TEXT:OK}");
							response[offset-9] = '0';
							addObject(&response, resultstr, 0, offset, 200);
						}
					}

					while((fp_line = fgets(line,4096,fp))!=NULL) {
						char *filedata = NULL;
						char *data_type = NULL;
						char rfile[30] = "DATA:READFROMFILE";
						char sShutdown[30] = "TYPE:SHUTDOWN";
						char data_filename[30] = "";
						int fileLen = 0;

						// right trim
						while(line[strlen(line)-1] == '\n' || line[strlen(line)-1] == '\r' || line[strlen(line)-1] == ' ') line[strlen(line)-1] = '\0';
						if(strlen(line) == 0) continue;

						data_type = strstr(line,rfile);
						getObjectField(line, 1, data_filename, NULL, "NAME:");

						if( data_type != NULL && strlen(data_filename) ) {
							char fpath[100]="";
							char flocalpath[60]="";
							char findex[10]="";
							getObjectField(line, 1, findex, NULL, "INDEX:");
							getObjectField(line, 1, flocalpath, NULL, "LOCALPATH:");
							if(strlen(flocalpath)) strcat(flocalpath,"/");
							sprintf(fpath,"tmp/%s%s_%s",flocalpath,data_filename,findex);
							if(getFileData(&filedata,fpath,&fileLen)) {
								char filedata_h[10480];
								char msglen[10480];
								*data_type = 0;

								UtilHexToString(filedata, fileLen, filedata_h);
								sprintf(msglen,"%sDATA:%s%s", line,filedata_h,data_type+strlen(rfile));
								addObject(&response, msglen, 0, offset, 200);
								my_free(filedata,__LINE__);
							}
						} else if (line[0] == '{') {
							addObject(&response, line, 0, offset, 200);
						} else continue; // only send JSON files

						if(response&&strlen(response) < 10) continue;

						sendToTerminal( sd,&response, offset, length, 0);
						if(response!=NULL) { // for next sending
							strcpy( response, "00000000");
							offset = 8;
						}
						filesend = 1;
						//Must in last line {TYPE:SHUTDOWN}
						if(strstr(line,sShutdown)!=NULL) {
							fp_line = NULL;
							break;
						}

						unsigned char acReadBuffer[10];
						int nReadBytes = tcp_recv(sd, 3, acReadBuffer);
						if(nReadBytes <3) {
							//last line probably completed - no response
							fp_line = fgets(line,4096,fp);
							break;
						}

						if( memcmp(acReadBuffer,"\x00\x01",2)) {
							int leftlen = acReadBuffer[0] * 256 + acReadBuffer[1] -1 ;

							memset(line,0,sizeof(line));
							nReadBytes = tcp_recv(sd, leftlen,&line[1]);
							line[0] = acReadBuffer[2];
							logNow("\n multiple downloading : received %d [%02x%02x %s]\n",nReadBytes, acReadBuffer[0],acReadBuffer[1],line);
							if(nReadBytes>10 && strstr(line,"RESULT:NOK")) { //something wrong, maybe merge file failed
								logNow("\n multiple downloading : received error [%s]\n",line);
								break;
							}
						} 
						else logNow("\n multiple downloading : received ack [%02x%02x %02x]\n",acReadBuffer[0],acReadBuffer[1],acReadBuffer[2]);

					}

					// not completed

					fclose(fp);
					if(fp_line == NULL)
					{
						if(downloadqueue) {
							char DBError[200];
							sprintf(query, "UPDATE downloadqueue set endtime = now() where id = %s", dq_id);
							if (databaseInsert(dbh,query, DBError))
								logNow( "DOWNLOADQUEUE ==> ID:%s **RECORDED**\n", dq_id);
							else
							{
								logNow( "Failed to update 'DOWNLOADQUEUE' table.  Error: %s\n", DBError);
							}
						} else {
							char cmd[200];
							sprintf(cmd, "mv %s %s.done", fname, fname);
							system(cmd);
							logNow("\n mdld ok0 [%s]", cmd);
						}
					
					}
					if(response) my_free(response,__LINE__); 
					response = NULL;

					logNow("\n mdld ok " );
					nosend = 1;
					//return(0);
				}
	}

#ifdef __iMANAGE
	if ( 0 && iPAY_CFG_RECEIVED == 1 && g_portal_sd ) /* Disabled 30/04/2017 */
	{ //iManage download
				memset(&xmlreq,0,sizeof(xmlreq));
				memset(&xmlresp,0,sizeof(xmlresp));
				strcpy(xmlreq.tid, tid );
				strcpy(xmlreq.serialNumber, serialnumber);
				strcpy(xmlreq.manufacturer, u2.manufacturer);
				strcpy(xmlreq.model, model );
				strcpy(xmlreq.appversion, appversion );

				int portal_sd = 0;
				portal_sd = tcp_connect( portalIPAddress , atoi( portalPortNumber ));
				if(portal_sd>0) //PORTAL TESTING
				{
					char line[10240];
					int msgsent = 0;

					struct timeval timeout;
					timeout.tv_sec = 5;
					timeout.tv_usec = 100;

					setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

					timeout.tv_sec = 5;
					if(portal_sd) setsockopt(portal_sd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

					int nextmsg = 0;
					int lastmsg = 0;

					do {

						nextmsg = -1;
						strcpy(line,"");

						memset(&xmlresp,0,sizeof(xmlresp));
						logNow("\n%s:: iManage terminal request sent to portal ....\n",timeString(temp, sizeof(temp)));	
						int iret = sendXmlToPortal(portal_sd,WEBREQUEST_MSGTYPE_HEARTBEAT,&xmlreq,lastmsg?NULL: &xmlresp) ;
						logNow(".done\n");

						if(xmlreq.jsontext) my_free(xmlreq.jsontext,__LINE__);
						if(iret<0 || xmlresp.jsontext == NULL || lastmsg) break;

						strcpy(line,xmlresp.jsontext);
						memset(&xmlreq,0,sizeof(xmlreq));
						if(xmlresp.nextmsg=='1') nextmsg = 1;
						if(xmlresp.nextmsg=='0') nextmsg = 0;

						if(xmlresp.jsontext) my_free (xmlresp.jsontext,__LINE__);

						addObject(&response, line, 0, offset, 200);

						sendToTerminal( sd,&response, offset, length, 0);
						msgsent ++;
						if(response!=NULL) { // for next sending
							strcpy( response, "00000000");
							offset = 8;
						}

						if(nextmsg <0) break;

						unsigned char acReadBuffer[10];
						int nReadBytes = tcp_recv(sd, 3, acReadBuffer);
						if(nReadBytes <3) break;

						logNow("\n iManage multiple downloading : received ack [%02x%02x %02x]\n",acReadBuffer[0],acReadBuffer[1],acReadBuffer[2]);

						//if( memcmp(acReadBuffer,"\x00\x01",2)) 
						{
							int leftlen = acReadBuffer[0] * 256 + acReadBuffer[1] -1 ;

							memset(line,0,sizeof(line));
							if(leftlen) {
								nReadBytes = tcp_recv(sd, leftlen,&line[1]);
								line[0] = acReadBuffer[2];
							}

							if(nextmsg == 0) lastmsg = 1;
							if(lastmsg) nextmsg =1 ; // send last ACK

							//if(strlen(line)) 
							{
								memset(&xmlreq,0,sizeof(xmlreq));
								memset(&xmlresp,0,sizeof(xmlresp));
								strcpy(xmlreq.serialNumber, serialnumber);
								strcpy(xmlreq.model, model );
								strcpy(xmlreq.result, "1" );
								if(strlen(line)) {
									xmlreq.jsontext = my_malloc( strlen(line) + 1 ,__LINE__);
									strcpy(xmlreq.jsontext, line);
								}
							}
						} 

					} while(nextmsg > 0);

					logNow("iManange download complete\n");
					if(portal_sd) tcp_close(portal_sd);
					if(msgsent) {
						if(response) my_free(response,__LINE__); 
						response = NULL;
						nosend = 1;
						//return(0);
					}
				}
	}
#endif

	if (response)
	{
		// If an empty response, add some dummy bytes to ensure the compressor does not complain
		if (strlen(&response[offset]) == 0)
			addObject(&response, "Empty!!", 1, offset, 0);

		// Store the original length of the objects to allow for better allocation of memory at the device
		sprintf(&response[offset-8], "%07ld", strlen(&response[offset]) + 1);

		// Compress the objects
		logNow("response=[%s] \n", &response[offset]);

		logNow("\nCompressing from %d ", strlen(&response[offset]));
		length = shrink(&response[offset]);
		logNow("to %d\n", length);
	//	length = strlen(&response[offset]);

		// OFB the objects
		if (response[offset-9] == '1')
			OFBObjects(&response[offset-8], length+8, serialnumber, ivTx);

		// Adjust the length
		length += offset;
	}

	if(nosend) {
	}
	else if (length > 0)
	{
		char title[200];
		char temp[50];

		response = realloc(response, length+2);
		memmove(&response[2], response, length);
		response[0] = (unsigned char) (length / 256);
		response[1] = (unsigned char) (length % 256);

		sprintf(title,	"\n\n---------------------------"
						"\n%s"
						"\nSending updates to terminal:"
						"\n---------------------------\n", timeString(temp, sizeof(temp)));
		displayComms(title, response, length+2);

		if (send(sd, response, length+2, MSG_NOSIGNAL) == (int) (length+2))
		{
			// Advance the update zip file position if successful sending during slow upgrades
			if (update == 1 && background_update)
				upgrade_advance(serialnumber, minZipPacketSize);

			logNow(	"\n%s:: ***SENT***", timeString(temp, sizeof(temp)));
		}
		else
			logNow(	"\n%s:: ***SEND FAILED***", timeString(temp, sizeof(temp)));

		my_free(response,__LINE__);
	}
	else
	{
		char title[200];
		char temp[50];
		unsigned char resp[2];

		resp[0] = 0;
		resp[1] = 0;

		sprintf(title,	"\n\n---------------------------"
						"\n%s"
						"\nSending updates to terminal:"
						"\n---------------------------\n", timeString(temp, sizeof(temp)));
		displayComms(title, resp, 2);

		send(sd, resp, 2, MSG_NOSIGNAL);
		logNow(	"\n%s:: ***SENT***", timeString(temp, sizeof(temp)));
	}

	if(dbh!=NULL) {
		mysql_close(dbh);
	}

	return update;
}

int sendToTerminal( int sd,char **sendResponse, int offset, int length, int endflag)
{
	unsigned char *response = *sendResponse;

	if (response)
	{
		// If an empty response, add some dummy bytes to ensure the compressor does not complain
		if (strlen(&response[offset]) == 0)
			addObject(&response, "Empty!!", 1, offset, 0);

		// Store the original length of the objects to allow for better allocation of memory at the device
		sprintf(&response[offset-8], "%07ld", strlen(&response[offset]) + 1);

		// Compress the objects
		logNow("\nCompressing from %d ", strlen(&response[offset]));
		length = shrink(&response[offset]);
		logNow("to %d\n", length);

		// Adjust the length
		length += offset;
	}

	if (length > 0)
	{
		char title[200];
		char temp[50];

		memmove(&response[2], response, length);
		response[0] = (unsigned char) (length / 256);
		response[1] = (unsigned char) (length % 256);

		sprintf(title,	"\n\n---------------------------"
						"\n%s"
						"\nSending updates to terminal:"
						"\n---------------------------\n", timeString(temp, sizeof(temp)));
		displayComms(title, response, length+2);

		if (send(sd, response, length+2, MSG_NOSIGNAL) == (int) (length+2))
		{
			logNow(	"\n%s:: ***SENT***", timeString(temp, sizeof(temp)));
		}
		else
			logNow(	"\n%s:: ***SEND FAILED***", timeString(temp, sizeof(temp)));

		return(1);
	}
	return(0);
}

#ifdef epay
void freeiVstockMemory(hVendMod h, sVendArg arg)
{
	if (h)
	{
		char out[2048];
		int szeOut = sizeof(out);
		int s;

		arg.dbh = 0;
		arg.Msg = "ABORT";
		s = risExecMsgSession(h, &arg, out, &szeOut);
		out[szeOut] = '\0';
	}
}
#endif

//// EchoIncomingPackets ///////////////////////////////////////////////
// Bounces any incoming packets back to the client.  We return false
// on errors, or true if the client closed the socket normally.
static int EchoIncomingPackets(SOCKET sd)
{
    // Read data from client
	unsigned char acReadBuffer[BUFFER_SIZE];
	int nReadBytes;
	int lengthBytes = 2;
	int length = 0;
	unsigned char * request = NULL;
	unsigned int requestLength = 0;
	char serialnumber[100];
	int update = 0;
	int unauthorised = 0;
#ifdef epay
	hVendMod h = 0;
	sVendArg arg;
	int epayStatus = 1;
#endif
	char temp[50];

	// Initialisation
	serialnumber[0] = '\0';

	/****
	logNow("\n%s:: Get thread DBHandler start\n", timeString(temp, sizeof(temp)));
	if( set_thread_dbh() == NULL) {
		logNow("\n%s:: Get DBHandler failed !!\n", timeString(temp, sizeof(temp)));
		return FALSE;
	}
	logNow("\n%s:: Get thread DBHandler ok!\n", timeString(temp, sizeof(temp)));
        */


	while(1)
	{
#ifndef WIN32
		struct timeval timeout;
#endif

		// If we are unauthorised for more than 10 times, drop the session
		if (unauthorised >= 10)
		{
			logNow("\n%s:: Too many unauthorised sessions - possibly tampered!!\n", timeString(temp, sizeof(temp)));
			return FALSE;
		}

		// Get the length first
		do
		{
#ifndef WIN32
			//timeout.tv_sec = waitTime;	// If the connection stays for more than 30 minutes, lose it.
			timeout.tv_sec = 30;	// If the connection stays for more than 30 seconds, lose it.
			timeout.tv_usec = 100;
			setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
#endif
	
			nReadBytes = recv(sd, acReadBuffer, lengthBytes, 0);
			if (nReadBytes == 0)
			{
				logNow("\n%s:: Connection closed by peer (1).\n", timeString(temp, sizeof(temp)));
#ifdef epay
				if (epayStatus == 0) freeiVstockMemory(h, arg);
#endif
				return TRUE;
			}
			else if (nReadBytes > 0)
			{
				length = length * 256 + acReadBuffer[0];
				if (--lengthBytes && --nReadBytes)
				{
					length = length * 256 + acReadBuffer[1];
					--lengthBytes;
				}
			}
			else if (nReadBytes == SOCKET_ERROR  || nReadBytes < 0)
			{
				logNow("\n%s:: Connection closed by peer (socket - %d).\n", timeString(temp, sizeof(temp)), errno);
#ifdef epay
				if (epayStatus == 0) freeiVstockMemory(h, arg);
#endif
				return FALSE;
			}	
		} while (lengthBytes);

		logNow(	"\n--------------------------------"
				"\n%s"
				"\nReceiving request from terminal:"
				"\n--------------------------------"
				"\nExpected request length = %d bytes from client.\n", timeString(temp, sizeof(temp)), length);

		do
		{
			if (length <= 0)
			{
				logNow(	"\n---------------------------------"
						"\n%s"
						"\nProcessing request from terminal:"
						"\n---------------------------------\n", timeString(temp, sizeof(temp)));
				displayComms("Message Received:\n", request, requestLength);

				// Only update the upgrade counter from the second packet onwards until the last one. The first upgrade counter will be zero or wherever we left at the time of failure (see processRequest())...
				if (serialnumber[0] != '\0' && update == 2)
				{
					FILE * fp;
					char temp[300];
					long position = 0;
					int count = 0;

					// Update the counter only if an upgrade is required
					sprintf(temp, "%s.zip", serialnumber);
					if ((fp = fopen(temp, "rb")) != NULL)
					{
						fclose(fp);
						upgrade_advance(serialnumber, maxZipPacketSize);
					}
				}
				update = processRequest(sd, request, requestLength, serialnumber, &unauthorised );

				// Reinitialise for the next request
				lengthBytes = 2;
				my_free(request,__LINE__);
				request = NULL;
				requestLength = 0;

#ifndef WIN32
				// Flush the buffer
				timeout.tv_sec = 0;	// If the connection stays for more than 30 minutes, lose it.
				timeout.tv_usec = 1;
				setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
				while (recv(sd, acReadBuffer, 1, 0) > 0);
#endif	
				break;
			}

#ifndef WIN32
			timeout.tv_sec = 5;
			timeout.tv_usec = 100;
			setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
#endif
	
			nReadBytes = recv(sd, acReadBuffer, length, 0);
			if (nReadBytes > 0)
			{
				length -= nReadBytes;

				acReadBuffer[nReadBytes] = '\0';

				if (request == NULL)
					request = my_malloc(nReadBytes,__LINE__);
				else
					request = realloc(request, requestLength + nReadBytes);

				memcpy(&request[requestLength], acReadBuffer, nReadBytes);
				requestLength += nReadBytes;
			}
			else if (nReadBytes == SOCKET_ERROR || nReadBytes < 0)
			{
				if (request) my_free(request,__LINE__);
				logNow("\n%s:: Connection closed by peer (socket2 - %d).\n", timeString(temp, sizeof(temp)), errno);
#ifdef epay
				if (epayStatus == 0) freeiVstockMemory(h, arg);
#endif
				return FALSE;
			}
		} while (nReadBytes != 0);
	}

	logNow("Connection closed by peer.\n");
	if (request) my_free(request,__LINE__);
#ifdef epay
	if (epayStatus == 0) freeiVstockMemory(h, arg);
#endif
	return TRUE;
}

//// EchoHandler ///////////////////////////////////////////////////////
// Handles the incoming data by reflecting it back to the sender.

DWORD WINAPI EchoHandler(void * threadData_)
{
	char temp[50];
	int result;
	int nRetval = 0;
	T_THREAD_DATA threadData = *((T_THREAD_DATA *)threadData_);
	SOCKET sd = threadData.sd;

	// Clean up
	free(threadData_);

//	logNow("sd = %d\n", sd);

	if (!(result = EchoIncomingPackets(sd)))
	{
		logNow("\n%s\n", WSAGetLastErrorMessage("Echo incoming packets failed"));
		nRetval = 3;
    	}
	
	//close_thread_dbh();

	logNow("Shutting connection down...");
    	if (ShutdownConnection(sd, result))
		logNow("Connection is down.\n");
	else
	{
		logNow("\n%s\n", WSAGetLastErrorMessage("Connection shutdown failed"));
		nRetval = 3;
	}

	counterDecrement();
	logNow("\n%s:: Number of sessions left after closing (%ld.%ld.%ld.%ld:%d) = %d.\n", timeString(temp, sizeof(temp)), ntohl(threadData.sinRemote.sin_addr.s_addr) >> 24, (ntohl(threadData.sinRemote.sin_addr.s_addr) >> 16) & 0xff,
					(ntohl(threadData.sinRemote.sin_addr.s_addr) >> 8) & 0xff, ntohl(threadData.sinRemote.sin_addr.s_addr) & 0xff, ntohs(threadData.sinRemote.sin_port), counter);

	pthread_exit((void*)1);
	return nRetval;
}

#ifdef USE_MYSQL
//// Continuous MySQL Access to stop database connection losses
static DWORD WINAPI ping_mysql(void * threadData_)
{
	unsigned long id;

#ifdef __DELETED
	while(1)
	{
		dbStart();
		id = mysql_thread_id(mysql);

		if (mysql_ping(mysql))
			logNow("\nMySQL connection ping failed!");
//		else
//			logNow("\nMySQL connection ping OK!");

		if (id != mysql_thread_id(mysql))
			logNow("\nMySQL reconnection occurred!");
		dbEnd();

		sleep(sleepTime);
	}

#endif
	return 0;
}
#endif


//// AcceptConnections /////////////////////////////////////////////////
// Spins forever waiting for connections.  For each one that comes in, 
// we create a thread to handle it and go back to waiting for
// connections.  If an error occurs, we return.

static void AcceptConnections(SOCKET ListeningSocket)
{
	T_THREAD_DATA threadData;
    int nAddrSize = sizeof(struct sockaddr_in);


	//DO NOT create ping thread any more: 2013-02-11
	sleepTime = 0;
	// Create a thread that accesses the database continuously to stop MySQL timeout
#ifdef USE_MYSQL
	if (sleepTime)
	{
		T_THREAD_DATA myThreadData;
#ifdef WIN32
		DWORD nThreadID;
		CreateThread(0, 0, ping_mysql, (void*)&myThreadData, 0, &nThreadID);
#else
		pthread_t thread;
		pthread_attr_t tattr;
		int status;

		pthread_attr_init(&tattr);
		pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
		status = pthread_create(&thread, &tattr, (void *(*)(void*))ping_mysql, (void *) &myThreadData);
		if (status)
		{
			logNow("pthread_create() failed with error number = %d", status);
			return;
		}
		pthread_attr_destroy(&tattr);
#endif
	}
#endif

    while (running)
	{
		threadData.sd = accept(ListeningSocket, (struct sockaddr *)&threadData.sinRemote, &nAddrSize);
        if (threadData.sd != INVALID_SOCKET)
		{
			char temp[50];
			T_THREAD_DATA * threadDataCopy;
#ifdef WIN32
			DWORD nThreadID;
#else
			pthread_t thread;
			pthread_attr_t tattr;
			int status;
#endif
			counterIncrement();
			if( counter > 200 ) {//30->200
				logNow(	"\nToomany sessions blocking...%d,"
				"\n**************************"
				"\nExiting program now..."
				"\n**************************\n\n", counter);
				sleep(2);
				exit(1);
			}
			logNow("\n%s:: Received TCP packet from %ld.%ld.%ld.%ld:%d - Number of Sessions = %d\n", timeString(temp, sizeof(temp)), ntohl(threadData.sinRemote.sin_addr.s_addr) >> 24, (ntohl(threadData.sinRemote.sin_addr.s_addr) >> 16) & 0xff,
					(ntohl(threadData.sinRemote.sin_addr.s_addr) >> 8) & 0xff, ntohl(threadData.sinRemote.sin_addr.s_addr) & 0xff, ntohs(threadData.sinRemote.sin_port), counter);
			threadDataCopy = malloc(sizeof(T_THREAD_DATA));
			*threadDataCopy = threadData;
//			logNow("Accepted connection from %s:%d.\n", inet_ntoa(threadData.sinRemote.sin_addr), ntohs(threadData.sinRemote.sin_port));
//			sleep(1);
#ifdef WIN32
            CreateThread(0, 0, EchoHandler, (void*)threadDataCopy, 0, &nThreadID);
#else
//			logNow("A thread is about to be created.....%d\n", threadData.sd);
			pthread_attr_init(&tattr);
			pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
			status = pthread_create(&thread, &tattr, (void *(*)(void*))EchoHandler, (void *) threadDataCopy);
			if (status)
			{
				logNow("pthread_create() failed with error number = %d", status);
				return;
			}
			pthread_attr_destroy(&tattr);
#endif

        }
        else
		{
            logNow("%s\n", WSAGetLastErrorMessage("accept() failed"));
            return;
        }
    }
}

//// SetUpListener /////////////////////////////////////////////////////
// Sets up a listener on the given interface and port, returning the
// listening socket if successful; if not, returns INVALID_SOCKET.
static SOCKET SetUpListener(const char * pcAddress, int nPort)
{
	u_long nInterfaceAddr = inet_addr(pcAddress);

	if (nInterfaceAddr != INADDR_NONE)
	{
		SOCKET sd = socket(AF_INET, SOCK_STREAM, 0);
		if (sd != INVALID_SOCKET)
		{
			struct sockaddr_in sinInterface;
			int reuse;

			reuse = 1;
			setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

			sinInterface.sin_family = AF_INET;
			sinInterface.sin_addr.s_addr = nInterfaceAddr;
			sinInterface.sin_port = nPort;
			if (bind(sd, (struct sockaddr *)&sinInterface, sizeof(struct sockaddr_in)) != SOCKET_ERROR)
			{
				listen(sd, SOMAXCONN);
				return sd;
			}
			else
			{
				logNow("%s\n", WSAGetLastErrorMessage("bind() failed"));
			}
		}
	}

	return INVALID_SOCKET;
}

#ifndef WIN32
void signalHandler(int s)
{
	logNow("%s\n", WSAGetLastErrorMessage(	"\n******************"
											"\ni-RIS stopping...."
											"\n******************\n"));
	waitTime = END_SOCKET_WAITTIME;
	running = 0;
	sleep(5);

	//mysql_close(mysql);

	//pthread_mutex_destroy(&dbMutex);
	pthread_mutex_destroy(&counterMutex);
	pthread_mutex_destroy(&hsmMutex);

	logEnd();

	exit(0);
}
#endif

//// DoWinsock /////////////////////////////////////////////////////////
// The module's driver function -- we just call other functions and
// interpret their results.

static int DoWinsock(const char * schema, const char * pcAddress, int nPort)
{
	char temp[50];
	SOCKET listeningSocket;

	logNow("\n\n%s:: Establishing the %s listener using port %d ...\n", timeString(temp, sizeof(temp)), schema, nPort);
	listeningSocket = SetUpListener(pcAddress, htons((u_short) nPort));
	if (listeningSocket == INVALID_SOCKET)
	{
		logNow("\n%s\n", WSAGetLastErrorMessage("establish listener"));
		return 3;
	}

#ifndef WIN32
	signal(SIGINT, signalHandler);
	signal(SIGUSR1, signalHandler);
#endif

	logNow("Waiting for connections...");
	AcceptConnections(listeningSocket);

	return 0;   // warning eater
}

//// main //////////////////////////////////////////////////////////////

int main(int argc, char* argv[])
{
	char * database = "i-ris";
	char * databaseIPAddress = "localhost";
	int databasePortNumber = 5432;
	char * serverIPAddress = "localhost";
	int serverPortNumber = 44555;
	char * user = "root";
	char * password = "password.01";
	int db_reconnect;
	time_t mytime;
	struct tm local_time;
	struct tm utc_time;

#ifdef USE_SQL_SERVER
	SQLHANDLE sqlHandleEnv;
	SQLHANDLE sqlHandleDbc;
#endif

#ifdef WIN32
	struct WSAData wsaData;
#endif
	int arg;
	int nCode;
	int retval;
	char * unix_socket = NULL;

	// Initialisation
	pthread_mutex_init(&hsmMutex, NULL);
	pthread_mutex_init(&counterMutex, NULL);
	//pthread_mutex_init(&dbMutex, NULL);
	mytime = time(NULL);
	utc_time = *gmtime(&mytime);
	local_time = *localtime(&mytime);

	while((arg = getopt(argc, argv, "a:A:C:d:D:e:E:F:f:G:g:W:w:Q:q:z:Z:i:o:s:S:p:P:l:L:u:U:k:M:I:Y:x:X:BrRcmnNtHTh?")) != -1)
	{
		switch(arg)
		{
			case 'A':
				datawireNewSSL = atoi(optarg);
				break;
			case 'B':
				background_update = 1;
				break;
			case 'D':
				datawireIPAddress = optarg;
				break;
			case 'F':
				datawireTimeout = atoi(optarg);
				break;
			case 'C':
				datawireDirectory = optarg;
				break;
			case 'c':
				scan = 1;
				break;
			case 'z':
				minZipPacketSize = atoi(optarg);
				break;
			case 'Z':
				maxZipPacketSize = atoi(optarg);
				break;
			case 'd':
				database = optarg;
				break;
			case 'i':
				databaseIPAddress = optarg;
				break;
			case 'o':
				databasePortNumber = atoi(optarg);
				break;
			case 'M':
				medicareIPAddress = optarg;
				break;
			case 'I':
				medicarePortNumber = optarg;
				break;
			case 's':
				serverIPAddress = optarg;
				break;
			case 'p':
				serverPortNumber = atoi(optarg);
				break;
			case 'S':
				deviceGatewayIPAddress = optarg;
				break;
			case 'P':
				deviceGatewayPortNumber = atoi(optarg);
				break;
			case 'e':
				eracomIPAddress = optarg;
				break;
			case 'E':
				eracomPortNumber = atoi(optarg);
				break;
			case 'l':
				sleepTime = atoi(optarg);
				break;
			case 'L':
				logFile = optarg;
				break;
			case 'r':
				strictSerialNumber = 0;
				break;
			case 'm':
				dispMessage = 1;
				break;
			case 'n':
				noTrace = 1;
				break;
			case 't':
				test = 1;
				break;
			case 'H':
				hsm = 1;
				break;
			case 'a':
				hsm_no = atoi(optarg);
				break;
			case 'T':
				ignoreHSM = 1;
				break;
			case 'u':
				user = optarg;
				break;
			case 'U':
				password = optarg;
				break;
			case 'k':
				unix_socket = optarg;
				break;
			case 'q':
				revIPAddress = optarg;
				break;
			case 'Q':
				revPortNumber = optarg;
				break;
			case 'w':
				rewardIPAddress = optarg;
				break;
			case 'W':
				rewardPortNumber = optarg;
				break;
			case 'R':
				iRewards = 1;
				break;
			case 'N':
				iScan = 1;
				break;
			case 'x':
				portalIPAddress = optarg;
				break;
			case 'X':
				portalPortNumber = optarg;
				break;
#ifdef __GPS
			case 'G':
				SetGomoUrl(optarg);
				break;
			case 'g':
				ttsIPAddress = optarg;
				break;
			case 'f':
				ttsPortNumber = optarg;
				break;
#endif
			case 'h':
			case '?':
			default:
				printf(	"Usage: %s [-h=help] [-?=help] [-d database=i-ris] [-L logFileName] [-r=relaxSerialNumber]\n"
						"            [-n=no trace] [-i databaseIPAddress=localhost] [-o databasePortNumber=5432]\n"
						"            [-s serverIPAddress=localhost] [-p serverPortNumber=44555]\n"
						"            [-u databaseUserID=root] [-U databaseuserPassword=password.01]\n"
						"            [-q revIPAddress=localhost] [-Q revPortNumber=32001]\n"
						"            [-w rewardIPAddress=localhost] [-W rewardPortNumber=32002]\n"
						"            [-S deviceGatewayIPAddress=localhost] [-P deviceGatewayPortNumber]\n", argv[0]);
				exit(-1);
		}
	}

#ifdef WIN32
    // Start Winsock up
	if ((nCode = WSAStartup(MAKEWORD(1, 1), &wsaData)) != 0)
	{
		printf("WSAStartup() returned error code %d\n", nCode);
		return 255;
	}
#endif

#ifdef USE_SQL_SERVER
#elif defined(USE_MYSQL)
	{
	MYSQL *dbh = NULL;
	// mysql initialisation
	if ((dbh = mysql_init(NULL)) == NULL)
	{
		printf("MySql Initialisation error. Exiting...\n");
		exit(-1);
	}

	// mysql database connection options
	db_reconnect = 1;
	mysql_options(dbh, MYSQL_OPT_RECONNECT, &db_reconnect);

	// mysql database connection
	if (!mysql_real_connect(dbh, databaseIPAddress, user, password, database, 0, unix_socket, 0))
	{
		fprintf(stderr, "%s\n", db_error(dbh, res));
		exit(-2);
	}
	set_db_connect_param( databaseIPAddress, user, password, database, unix_socket);


	mysql_close(dbh);
	}
#else
	{
		char connectString[200];

		sprintf(connectString, "host=%s port=%d dbname=%s user=postgres connect_timeout=5", databaseIPAddress, databasePortNumber, database);
		mysql = PQconnectdb(connectString);

		if (PQstatus(mysql) != CONNECTION_OK)
		{
			printf("\ni-ris connection status failed\n");
			exit(-1);
		}
//		else
//			printf("\ni-ris connection result = %X\n", mysql);
	}
#endif

	// Start the log & counter
	logStart();

	/* Disabled 30/04/2017 */
	/*
	**g_portal_sd = tcp_connect( portalIPAddress , atoi( portalPortNumber ));
	**if(g_portal_sd>0) //PORTAL TESTING
	**	tcp_close(g_portal_sd);
	**else g_portal_sd = 0;
	*/

    // Call the main example routine.
	retval = DoWinsock(database, serverIPAddress, serverPortNumber);

	// Shut Winsock back down and take off.
#ifdef WIN32
	WSACleanup();
#endif

	logNow(	"\n**************************"
			"\nExiting program now..."
			"\n**************************\n\n");


	//pthread_mutex_destroy(&dbMutex);
	pthread_mutex_destroy(&counterMutex);
	pthread_mutex_destroy(&hsmMutex);

	logEnd();

	return retval;
}
