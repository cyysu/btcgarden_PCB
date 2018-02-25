#ifndef __CHIPMINER_H__
#define __CHIPMINER_H__

#include "serial.h"
#ifdef RT_USING_DFS
#include <dfs_fs.h>
#endif
#ifdef RT_USING_COMPONENTS_INIT
#include <components.h>
#endif 
#include "usart.h"
#include <rtdef.h>
extern void lwip_sys_init(void);

#include <stdio.h>
#include <string.h>
#include <nanohttp/nanohttp-client.h>
#include <nanohttp/nanohttp-logging.h>
#include <cJSON.h>
#include "utils.h"
#include "sha2.h"

/************Get Work result Example ***************
{
   "result": {
      "data": "000000020ad41ea2975a456cf0ffce2524cf907314ed3603b840f8060000001c00000000c522c9590257cfafcc4c0ced0f09bd0a6e93a1af0a3053db72d000b170792d7852025e4f1972dbf200000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000",
      "hash1": "00000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000010000",
      "target": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000",
      "midstate": "5bfb720c6b24d91df4c9e229a609a1f1c9b8f3025684fb941ed74f2a8382374f"
   },
   "error": null,
   "id": 0
}     
**********************************************/
#define GW_ID "id"
#define GW_ERROR "error"
#define GW_RESULT "result"
#define GW_RESULT_data "data"
#define GW_RESULT_hash1 "hash1"
#define GW_RESULT_target "target"
#define GW_RESULT_midstate "midstate"

/***********************************************/

#define CHIP_MINER_HW  "uart1"
// The size of a successful nonce read
#define CHIP_READ_SIZE 4

#define CHIP_GETS_ERROR -1
#define CHIP_GETS_OK 0
#define CHIP_GETS_RESTART 1
#define CHIP_GETS_TIMEOUT 2

typedef enum
{
CLOCK_200M,
CLOCK_225M,
CLOCK_250M,
CLOCK_275M,
CLOCK_300M,
CLOCK_350M,
CLOCK_400M,
MAX_CLOCK,
}eClock;

typedef struct{
eClock clock;
uint32_t clock_real;  //MHZ
char PD2;
char PD3;
char PD4;
uint32_t wait_time;
}tClockTable;

struct chip_reset_pin
{
    GPIO_TypeDef * GPIOx;
    uint16_t GPIO_Pin;
};

struct work {
	unsigned char	data[128];
	unsigned char	midstate[32];
	unsigned char	target[32];
	unsigned char	hash[32];
	uint32_t nonce;

//	unsigned int	work_block;
	int		id;
};

#define MAX_BUFFER_SIZE 2048

#define PRC_CALL_RETRY_MAX 2
#define CHIP_DETECT_RETRY_MAX 20
#define MINER_FOREVER 100000

#define likely(x) (x)
#define unlikely(x) (x)
#define __maybe_unused 

#define DPRINTF(__X__)  //rt_kprintf __X__
#define FPRINTF(__X__)  rt_kprintf __X__
#define TRACE()  //rt_kprintf("TRACE: (%s):%d \n",__FUNCTION__,__LINE__);

#if 0
extern void list_mem(void);
#define TRACE_MEM()  \
	DPRINTF(("\n========= MEM STA (%s):%d ==========\n",__FUNCTION__,__LINE__)); \
	list_mem();  \
    DPRINTF(("==============================================\n"));
#else
#define TRACE_MEM()
#endif

typedef unsigned int bool; 
#define false 0
#define true  1


#define HAVE_WEB_SRV
#ifdef HAVE_WEB_SRV
#include <pthread.h>
#include <nanohttp/nanohttp-server.h>
extern void get_base_network_info(char* ip, char* mask, char* gw, char* dns1, char* dns2);

typedef struct __Settings{
uint32_t MAGIC_CODE;
char ip[16];
char mask[16];
char gateway[16];
char DNS1[16];
char pool_url[64];
char username[32];
char password[32];
eClock clock;
uint32_t wait_time;
}tSettings;

typedef struct __HashSpeed{
uint32_t dnonce;
unsigned long long total_nonce;
unsigned long long total_time;
rt_tick_t prevendtick;
rt_tick_t endtick;
rt_tick_t starttick;
uint32_t current_speed;
}tHashSpeed;


typedef struct __StatisInfo{
uint32_t total_mhs;
uint32_t total_getworks;
uint32_t total_accepted;
uint32_t total_rejected;
uint32_t chip_detect_error;
tHashSpeed hashspeed;
char  up_time[32];   //xxxday,xxh,xxmin,xxs
char  current_pool[64];
char  current_user[32];
char  current_pass[32];
bool  scanhash_run;
uint32_t chip_version;
char ip[16];
char mask[16];
char gateway[16];
char DNS1[16];
char DNS2[16];
uint32_t webserver_port;
char* pool_url;
char* username;
char* password;
}tStatisInfo;

typedef union __uSettings{
tSettings settings;
uint32_t words[sizeof(tSettings)/sizeof(uint32_t)];
}uSettings;

#define MINER_SW_VERSION  "1.1.0"
#define SETTING_PAGE_ADDR 0x0803F800
#define SETTING_MAGIC_CODE 0xa55aa110       //setting version: 501 
#define SETTING_CHIP_VERSION 2013090001
#if 0
#define SETTING_DEFAULT_POOL_URL  "http://192.168.1.109:8332"
#define SETTING_DEFAULT_USER  "xranger@126.com_17" //"chipcircle_17"//
#define SETTING_DEFAULT_PASSWORD "123456"
#else
#define SETTING_DEFAULT_POOL_URL  "http://192.168.1.250:9332"
#define SETTING_DEFAULT_USER  "lianyi_006"
#define SETTING_DEFAULT_PASSWORD "123456"
#endif
#define SETTING_DEFAULT_CHIP_CLOCK CLOCK_275M
#define SETTING_DEFAULT_WAIT_TIME_MS (478)

#define SETTING_DEFAULT_IP  "192.168.1.236"
#define SETTING_DEFAULT_NETMASK  "255.255.255.0" //"chipcircle_17"//
#define SETTING_DEFAULT_GW "192.168.1.1"
#define SETTING_DEFAULT_DNS1 "192.168.1.1"

#define GET_WORK_REQ "{\"method\": \"getwork\", \"params\": [], \"id\":1}\n"

/* seconds per day */
#define SPD 24*60*60
#define WEB_SERVER_AUTH_USER   "Chipcircle"
#define WEB_SERVER_AUTH_PASS   "567890"

/*"<meta http-equiv=\"refresh\" content=\"5\">"*/ //auto refresh method

#define MAIN_PAGE_TEMPL       \
"<HTML><HEAD><TITLE>Configuration</TITLE>"                                                        \
"<META content=\"text/HTML; charset=gb2312\" http-equiv=Content-Type>"                              \
"<META name=GENERATOR content=\"MSHTML 9.00.8112.16421\">"                                          \
"</HEAD>"                                                                                           \
"<BODY bgColor=#ffe983 text=#0000ff>"                                                               \
"<CENTER></FONT><FONT color=white size=2 face=courier new></FONT>"                                  \
"<TABLE style=\"FONT-FAMILY: sans-serif; COLOR: blue; FONT-SIZE: 14pt; FONT-WEIGHT: bold\">"        \
"<TBODY>"                                                                                           \
"  <TR> "                                                                                           \
"    <TD align=right>Total MHS:</TD> "                                                        \
"    <TD align=left>%d</TD></TR>     "                                                        \
"  <TR>                              "                                                        \
"    <TD align=right>Up Time:</TD>   "                                                        \
"    <TD align=left>%s</TD>          "                                                        \
"  </TR>"                                                                                           \
" </TBODY>"                                                                                         \
" </TABLE>"                                                                                         \
"<BR>Current Server:%s"                                                                             \
"<BR>Clock selected: %d"                                                                          \
"<BR>Chip: %d "                                                                                     \
"<FORM method=post name=upload action=\"\\\"></CENTER>            "          \
"<TABLE border=0 cellSpacing=0 align=center>                           "          \
"  <TBODY>                                                             "          \
"  <TR>                                                                "          \
"    <TD align=right>IP</TD>                                           "          \
"    <TD align=left><INPUT name=CRIP value=%s size=30><BR></TD></TR>   "          \
"  <TR>                                                                "          \
"    <TD align=right>Mask</TD>                                         "          \
"    <TD align=left><INPUT name=CMSK value=%s size=30><BR></TD></TR>   "          \
"  <TR>                                                                "          \
"    <TD align=right>Gateway</TD>                                      "          \
"    <TD align=left><INPUT name=CGTW value=%s size=30><BR></TD></TR>   "          \
"  <TR>                                                                "          \
"    <TD align=right>WEB Port</TD>                                     "          \
"    <TD align=left><INPUT name=WPRT value=%d size=30><BR></TD></TR>"          \
"  <TR>                                                                "          \
"    <TD align=right>Primary DNS</TD>                                  "          \
"    <TD align=left><INPUT name=PDNS value=%s size=30><BR></TD></TR>   "          \
"  <TR>                                                                "          \
"    <TD align=right>Server URL</TD>                                   "          \
"    <TD align=left><INPUT name=PURL value=%s size=30><BR></TD></TR>"   \
"  <TR>                                                             "  \
"    <TD align=right>User</TD>"                                        \
"    <TD align=left><INPUT name=USER value=%s size=30><BR></TD></TR>"  \
"  <TR>"                                                                \
"    <TD align=right>Password</TD>"                                     \
"    <TD align=left><INPUT name=PASS value=%s size=30><BR></TD></TR>   "          \
"  <TR>"                                                                \
"    <TD align=right>WaitTime(ms)</TD>"                                     \
"    <TD align=left><INPUT name=WATM value=%d size=30><BR></TD></TR>   "          \
"  <TR>"																\
"	 <TD align=right>Clock(1~5)</TD>" 									\
"	 <TD align=left><INPUT name=CLCK value=%d size=30><BR></TD></TR>   "		  \
"  <TR>                                                                "          \
"    <TD align=right></TD></TR>                                        "          \
"  <TR>  "                                                                          \
"    <TD colSpan=2 align=center>"                                                                   \
"    <INPUT onclick=\"window.location.href='\'\" value=Refresh type=button>"                          \
     "<INPUT name=update value=UpdateRestart type=submit>"                                          \
     "</TD></TR></FORM></TBODY></TABLE></BODY></HTML>"


//"<INPUT onclick=\"window.location.href='Sw_Pool'\" value=\"Switch Server\" type=button>"	   \
//"<INPUT onclick=\"window.location.href='Sw_Clock'\" value=\"Switch Clock\" type=button>"	   \


#define UP_TIME_TEMPL       "%03dday,%02dh,%02dm,%02ds"

#endif

#define HAVE_WORK_QUEUE
#define MAX_WORK_QUEUE_LEN   16

#define WORK_QUEUE_FULL_Threshold  (16)
#define WORK_FREE_MBOX_NAME "workq_free"
#define WORK_MID_MBOX_NAME "workq_mid"
#define WORK_FULL_MBOX_NAME "workq_full"

//#define HAVE_WWDG
#define HAVE_IWDG

#endif /* __CHIPMINER_H__ */
