/*
 * File      : application.c
 * This file is part of RT-Thread RTOS
 * COPYRIGHT (C) 2006 - 2013, RT-Thread Development Team
 *
 * The license and distribution terms for this file may be
 * found in the file LICENSE in this distribution or at
 * http://www.rt-thread.org/license/LICENSE
 *
 * Change Logs:
 * Date           Author       Notes
 * 2009-01-05     Bernard      the first version
 */

/**
 * @addtogroup STM32
 */
/*@{*/

#include <board.h>
#include <rtthread.h>
#include "chipminer.h"


//static char *getwork_req = "{\"method\": \"getwork\", \"params\": [], \"id\":0}\n";

#define WORK_DEBUG        0
#if (WORK_DEBUG == 1) 
static char show_http_status_code = 1;
static char show_headers = 1;
static char show_content = 1;
static char show_json = 1;
static char show_work_data= 0;
static char show_chip_data= 1;
#else 
static char show_http_status_code = 0;
static char show_headers = 0;
static char show_content = 0;
static char show_json = 0;
static char show_work_data= 0;
static char show_chip_data= 0;
#endif

#ifndef HAVE_WORK_QUEUE 
static struct work miner_work[MAX_WORK_QUEUE_LEN];
#else
static struct work miner_work[MAX_WORK_QUEUE_LEN];
//rt_sem_t workq_full_sem;
//rt_sem_t workq_free_sem;
rt_mailbox_t workq_full_mbox; 
rt_mailbox_t workq_mid_mbox;
rt_mailbox_t workq_free_mbox;

#endif

static rt_device_t chip;

/////// only for debug malloc ////////
/////// give a large array not used ///////////
//#define TEST_MEM
#ifdef TEST_MEM
#define NOT_USE_MEM  4//7*1024//9*1024 //10*1024 just ok 1 time
char NOT_USE_ARRAY[NOT_USE_MEM];
#endif

#ifdef HAVE_WEB_SRV
char MAIN_page[sizeof(MAIN_PAGE_TEMPL)+ 256];
uSettings chip_settings;
tStatisInfo statis_info;
rt_tick_t power_on_tick;
bool restart_miner=false;
pthread_mutex_t network_acc_lock;
#endif


///////////////////////// WWDG //////////////////////////////
#ifdef HAVE_WWDG
#include "stm32f10x_wwdg.h"
#include "stm32f10x_rcc.h"

int WWDG_leak_times=0;

void WWDG_config()             
{
   RCC_APB1PeriphResetCmd(RCC_APB1Periph_WWDG, ENABLE);   
   WWDG_SetPrescaler(WWDG_Prescaler_8); 
   // (PCLK1/4096)/8= 2197 Hz (~0.4 ms)
   WWDG_SetWindowValue(0x7a);             
   WWDG_Enable(0x65); 
   WWDG_leak_times=0;
   // WWDG timeout = ~0.4 ms * 127 = 50 ms
   WWDG_ClearFlag();                
   WWDG_EnableIT();  
   rt_kprintf("\n!!!! EN WWDG !!!!\n");
}

#if 1
void WWDG_IRQHandler(void)
{
     /* enter interrupt */
    rt_interrupt_enter();

    if(WWDG_leak_times<20){
       WWDG_leak_times++;
	   WWDG_SetCounter(0x65);
	   WWDG_ClearFlag();
	}
	else{
 	}
    /* leave interrupt */
    rt_interrupt_leave();
    
}
#endif

void WWDG_feed(void)
{
   WWDG_SetCounter(0x7F); 
   WWDG_leak_times=0;
   WWDG_ClearFlag();
}
#endif



#ifdef HAVE_IWDG

#define IWDG_WAIT_SECOND(x)  (156*(x))   

void IWDG_init() 
{
   IWDG_WriteAccessCmd(IWDG_WriteAccess_Enable);
   IWDG_SetPrescaler(IWDG_Prescaler_256);// 6.4ms (1000/(40000/256) )
   //  1sec  test 
   IWDG_SetReload(0xff0);  //MAX:  6.4ms * 0xfff = 26secs
   IWDG_ReloadCounter();
   IWDG_Enable();
}

void IWDG_feed()
{
   IWDG_ReloadCounter();
}

#endif


///////////////////////// Utils /////////////////////////////////

// TODO: Move to utils.c

/* Returns a malloced array string of a binary value of arbitrary length. The
 * array is rounded up to a 4 byte size to appease architectures that need
 * aligned array  sizes */
char *bin2hex(const unsigned char *p, size_t len)
{
	unsigned int i;
	unsigned int slen;
	char *s;

	slen = len * 2 + 1;
	if (slen % 4)
		slen += 4 - (slen % 4);
	s = rt_calloc(slen, 1);
	if (unlikely(!s)){
		rt_kprintf("Failed to calloc in bin2hex");
        return NULL;
	}
	for (i = 0; i < len; i++)
		sprintf(s + (i * 2), "%02x", (unsigned int) p[i]);

	return s;
}


/* Does the reverse of bin2hex but does not allocate any ram */
bool hex2bin(unsigned char *p, const char *hexstr, size_t len)
{
	bool ret = false;

	while (*hexstr && len) {
		char hex_byte[4];
		unsigned int v;

		if (unlikely(!hexstr[1])) {
			DPRINTF(("hex2bin str truncated"));
			return ret;
		}

		memset(hex_byte, 0, 4);
		hex_byte[0] = hexstr[0];
		hex_byte[1] = hexstr[1];

		if (unlikely(sscanf(hex_byte, "%x", &v) != 1)) {
			DPRINTF(("hex2bin sscanf '%s' failed", hex_byte));
			return ret;
		}

		*p = (unsigned char) v;

		p++;
		hexstr += 2;
		len--;
	}

	if (likely(len == 0 && *hexstr == 0))
		ret = true;
	return ret;
}


static bool jobj_binary(cJSON *obj, const char *key,
			void *buf, size_t buflen, bool required)
{
	const char *hexstr;
	cJSON *tmp;

	tmp = cJSON_GetObjectItem(obj, key);
	if (unlikely(!tmp)) {
		if (unlikely(required))
			DPRINTF(("JSON key '%s' not found\n", key));
		return false;
	}
	hexstr = tmp->valuestring;
	if (unlikely(!hexstr)) {
		DPRINTF(("JSON key '%s' is not a string\n", key));
		return false;
	}
	if (!hex2bin(buf, hexstr, buflen))
		return false;

	return true;
}


/* Realloc an existing string to fit an extra string s, appending s to it. */
void *realloc_strcat(char *ptr, char *s)
{
	size_t old = strlen(ptr), len = strlen(s);
	char *ret;

	if (!len)
		return ptr;

	len += old + 1;
	align_len(&len);

	ret = rt_malloc(len);
	if (unlikely(!ret))
		FPRINTF(("Failed to malloc in realloc_strcat\n"));

	sprintf(ret, "%s%s", ptr, s);
	rt_free(ptr);
	return ret;
}


///////////////////////// Work related //////////////////////////////////

static void calc_midstate(struct work *work)
{
	unsigned char data[64];
	uint32_t *data32 = (uint32_t *)data;
	sha2_context ctx;
// 	 rt_tick_t rt_now_tick;
//    rt_now_tick = rt_tick_get();
//    DPRINTF(("Start calc : %d\n",rt_now_tick));
	flip64(data32, work->data);
	sha2_starts(&ctx);
	sha2_update(&ctx, data, 64);
	memcpy(work->midstate, ctx.state, 32);
	endian_flip32(work->midstate, work->midstate);
//	DPRINTF(("Stop calc : %d\n",rt_tick_get()));
}


static bool getwork_decode(struct work *work, cJSON *res_val)
{
	if (unlikely(!jobj_binary(res_val, "data", work->data, sizeof(work->data), true))) {
		log_error1("JSON inval data");
		return false;
	}

	if (!jobj_binary(res_val, "midstate", work->midstate, sizeof(work->midstate), false)) {
		// Calculate it ourselves
		DPRINTF(("Calculating midstate locally\n"));
		calc_midstate(work);
		//log_error1("JSON inval data");
		
	}
	if (unlikely(!jobj_binary(res_val, "target", work->target, sizeof(work->target), true))) {
		log_error1("JSON inval target");
		return false;
	}
	return true;
}

static bool work_decode(struct work *work, cJSON *res_val)
{
    bool ret = false;
	if(!work || !res_val || cJSON_is_null(res_val)) goto out;
    if (!getwork_decode(work,res_val))
		goto out;
	memset(work->hash, 0, sizeof(work->hash));
	ret = true;
out:
	return ret;
}

static void dump_work_data(struct work *work)
{
int i;
	if(work==NULL)
	   return;
	DPRINTF(("======= Work 'DATA':\n"));
	for(i=0;i<sizeof(work->data);i++){
        DPRINTF(("0x%x, ",work->data[i]));
	}
	DPRINTF(("\n"));
	DPRINTF(("======= Work 'MIDSTATE':\n"));
	for(i=0;i<sizeof(work->midstate);i++){
        DPRINTF(("0x%x, ",work->midstate[i]));
	}	
	DPRINTF(("\n"));
	DPRINTF(("======= Work 'TARGET':\n"));
	for(i=0;i<sizeof(work->target);i++){
        DPRINTF(("0x%x, ",work->target[i]));
	}
	DPRINTF(("\n"));
}



/////////////////////////  Get upstream work  /////////////////////////////////

cJSON *json_rpc_call(const char *url,const char *user, const char *pass, const char *rpc_req)
{
byte_t buffer[MAX_BUFFER_SIZE+1];
int read_len;
cJSON *root=NULL, *err_val=NULL, *res_val=NULL;
httpc_conn_t *conn;
hresponse_t *res;
hpair_t *pair;
herror_t status;
char tmp[10];

	 TRACE();
//     DPRINTF(("content-length: %d", strlen(rpc_req)));	
      /* Transport via HTTP */
      if (!(conn = httpc_new()))
      {
        DPRINTF(("Unable to create HTTPC client!\n"));
        return NULL; 
      }	
      /* Set rpc call headr */
      httpc_set_basic_authorization(conn,user,pass);
      httpc_set_header(conn, HEADER_ACCEPT, "*/*");     
      httpc_set_header(conn, HEADER_CONTENT_TYPE, "application/json");	
      sprintf(tmp, "%d", (int) strlen(rpc_req));
      httpc_set_header(conn, HEADER_CONTENT_LENGTH, tmp);
      httpc_add_header(conn, "X-Mining-Extensions","longpoll midstate rollntime submitold");
      httpc_set_header(conn,HEADER_USER_AGENT,"chipminer 0.0.1");
	  /*  POST rpc */
	  if ((status = httpc_post_begin(conn, url)) != H_OK)
	  {
		httpc_close_free(conn);
		DPRINTF(("Httpc_post_begin fail !!!"));
		return NULL; 
	  }
	  if ((status = http_output_stream_write_string(conn->out, rpc_req)) != H_OK)
	  {
		httpc_close_free(conn);
		DPRINTF(("Httpc_output_stream fail !!!"));
		return NULL; 
	  } 
	  if ((status = httpc_post_end(conn, &res)) != H_OK)
	  {
		httpc_close_free(conn);
		DPRINTF(("Httpc_post_end fail !!!"));
		return NULL; 
	  }   
	  if (res == NULL || res->in == NULL){
	     DPRINTF(("Can not get response !!!"));
	     goto err_out;	
	  }
	  /*     Parse Response */
	  if (show_http_status_code){
		  DPRINTF(("HTTP Status: %d \"%s\"\n", res->errcode, res->desc));
	  }
	  if (res->errcode != 200){
		  FPRINTF(("HTTP Status Not 200 OK, Discard this response\n", res->errcode, res->desc));
		  goto err_out;
	  }
	  if (show_headers) {
		  hpair_t *pair;
		  DPRINTF(("\n ========== Begin dump res HTTP Headers ========= \n\n"));
		  for (pair = res->header; pair; pair=pair->next)
			  DPRINTF(("	%s: %s\n", pair->key, pair->value));
	  }
      /*    Read the reponse content   */
	  while(http_input_stream_is_ready(res->in)) {
		  read_len = http_input_stream_read(res->in, buffer, MAX_BUFFER_SIZE);
		  buffer[read_len] = '\0';
		  if (show_content){
		  	  DPRINTF((" Input stream read: %d\n",read_len));
		  	  DPRINTF((" ========== Begin dump res content ========= \n\n"));			 
			  DPRINTF((buffer));
			  DPRINTF(("\n"));
		  }
	  }	  
	  root = cJSON_Parse(buffer);
	  if (!root) {
		  log_error1("Res JSON decode failed !!!!!!!!\n");
		  goto err_out;
	  }   
	  if (show_json) {
		  char *out;
		  out = cJSON_Print(root);
		  DPRINTF(("\n JSON print: \n %s\n",out));
		  rt_free(out);
	  }
	  res_val = cJSON_GetObjectItem(root,GW_RESULT);  
	  err_val = cJSON_GetObjectItem(root,GW_ERROR);
	  if (!res_val ||(err_val && !(cJSON_is_null(err_val)))) {
		  if (err_val){
			  char *s;
			  s = cJSON_Print(err_val);
			  if(s){DPRINTF(("\n Err Val print: \n %s\n",s));}
			  rt_free(s);
		  }
		  else{
			  DPRINTF(("JSON-RPC call failed: unknow reason\n"));
		  }
		  if(root)cJSON_Delete(root);
		  goto err_out;
	  }
	  hresponse_free(res);   
      httpc_close_free(conn);
      return root;	  
err_out:
      hresponse_free(res);   
      httpc_close_free(conn);
      return NULL;
}


cJSON *json_rpc_call_suw(const char *url,const char *user, const char *pass, const char *rpc_req)
{
//byte_t buffer[MAX_BUFFER_SIZE+1];
int read_len;
cJSON *root=NULL, *err_val=NULL, *res_val=NULL;
httpc_conn_t *conn;
hresponse_t *res;
hpair_t *pair;
herror_t status;
char tmp[10];

	 TRACE();
//     DPRINTF(("content-length: %d", strlen(rpc_req)));	
      /* Transport via HTTP */
      if (!(conn = httpc_new()))
      {
        DPRINTF(("Unable to create HTTPC client!\n"));
        return NULL; 
      }	
      /* Set rpc call headr */
      httpc_set_basic_authorization(conn,user,pass);
      httpc_set_header(conn, HEADER_ACCEPT, "*/*");     
      httpc_set_header(conn, HEADER_CONTENT_TYPE, "application/json");	
      sprintf(tmp, "%d", (int) strlen(rpc_req));
      httpc_set_header(conn, HEADER_CONTENT_LENGTH, tmp);
      httpc_add_header(conn, "X-Mining-Extensions","longpoll midstate rollntime submitold");
      httpc_set_header(conn,HEADER_USER_AGENT,"chipminer 0.0.1");
	  /*  POST rpc */
	  if ((status = httpc_post_begin(conn, url)) != H_OK)
	  {
		httpc_close_free(conn);
		DPRINTF(("Httpc_post_begin fail !!!"));
		return NULL; 
	  }
	  if ((status = http_output_stream_write_string(conn->out, rpc_req)) != H_OK)
	  {
		httpc_close_free(conn);
		DPRINTF(("Httpc_output_stream fail !!!"));
		return NULL; 
	  } 
#if 0
	  if ((status = httpc_post_end(conn, &res)) != H_OK)
	  {
		httpc_close_free(conn);
		DPRINTF(("Httpc_post_end fail !!!"));
		return NULL; 
	  }   
	  if (res == NULL || res->in == NULL){
	     DPRINTF(("Can not get response !!!"));
	     goto err_out;	
	  }
	  /*     Parse Response */
	  if (show_http_status_code){
		  DPRINTF(("HTTP Status: %d \"%s\"\n", res->errcode, res->desc));
	  }
	  if (res->errcode != 200){
		  FPRINTF(("HTTP Status Not 200 OK, Discard this response\n", res->errcode, res->desc));
		  goto err_out;
	  }
	  if (show_headers) {
		  hpair_t *pair;
		  DPRINTF(("\n ========== Begin dump res HTTP Headers ========= \n\n"));
		  for (pair = res->header; pair; pair=pair->next)
			  DPRINTF(("	%s: %s\n", pair->key, pair->value));
	  }
      /*    Read the reponse content   */
	  while(http_input_stream_is_ready(res->in)) {
		  read_len = http_input_stream_read(res->in, buffer, MAX_BUFFER_SIZE);
		  buffer[read_len] = '\0';
		  if (show_content){
		  	  DPRINTF((" Input stream read: %d\n",read_len));
		  	  DPRINTF((" ========== Begin dump res content ========= \n\n"));			 
			  DPRINTF((buffer));
			  DPRINTF(("\n"));
		  }
	  }	  
	  root = cJSON_Parse(buffer);
	  if (!root) {
		  log_error1("Res JSON decode failed !!!!!!!!\n");
		  goto err_out;
	  }   
	  if (show_json) {
		  char *out;
		  out = cJSON_Print(root);
		  DPRINTF(("\n JSON print: \n %s\n",out));
		  rt_free(out);
	  }
	  res_val = cJSON_GetObjectItem(root,GW_RESULT);  
	  err_val = cJSON_GetObjectItem(root,GW_ERROR);
	  if (!res_val ||(err_val && !(cJSON_is_null(err_val)))) {
		  if (err_val){
			  char *s;
			  s = cJSON_Print(err_val);
			  if(s){DPRINTF(("\n Err Val print: \n %s\n",s));}
			  rt_free(s);
		  }
		  else{
			  DPRINTF(("JSON-RPC call failed: unknow reason\n"));
		  }
		  if(root)cJSON_Delete(root);
		  goto err_out;
	  }
	  hresponse_free(res); 	  
#endif	   
      httpc_close_free(conn);
      return root;	  
err_out:
      hresponse_free(res);   
      httpc_close_free(conn);
      return NULL;
}



bool guw(struct work *work)
{
cJSON *root=NULL, *res_val=NULL;
bool rc = false;  
int rpc_call_retry=0;
    FPRINTF(("\n ============= GET UPSTREAM WORK START ================= \n"));

retry:
	pthread_mutex_lock(&network_acc_lock);
	root=json_rpc_call(statis_info.current_pool,statis_info.current_user,statis_info.current_pass,GET_WORK_REQ);
	pthread_mutex_unlock(&network_acc_lock);
	if(root==NULL){
	   FPRINTF(("get_upstream_work json_rpc_call failed, retry %d times\n",rpc_call_retry));
	   rt_thread_delay(RT_TICK_PER_SECOND*1);
	   if(rpc_call_retry < PRC_CALL_RETRY_MAX){
		  rpc_call_retry++;
		  goto retry;
	   }
       return rc;
	}
	res_val = cJSON_GetObjectItem(root,GW_RESULT);  
	rc = work_decode(work,res_val);
	cJSON_Delete(root);
	if((!rc))
		 DPRINTF(("Failed to decode work in get_upstream_work\n"));
	else{
		 DPRINTF(("get_upstream_work ok\n"));
		 if(show_work_data)
		 	dump_work_data(work);
	}
	return rc;
}

#ifdef RT_USING_FINSH
#include <finsh.h>
FINSH_FUNCTION_EXPORT(guw, get work test);
#endif

/////////////////////////////   Submit Work  ////////////////////////////////

void update_hash_speed_chip(rt_tick_t starttick, rt_tick_t endtick, uint32_t nonce_bin)
{
	unsigned char *nonce_hex = (unsigned char *)&nonce_bin;
	uint32_t using_time_ms,total_time_ms;

	using_time_ms=((endtick-starttick)*(1000/RT_TICK_PER_SECOND));
	if(using_time_ms==0) using_time_ms=1;
	DPRINTF(("This using time %d ms\n" ,using_time_ms));
	statis_info.hashspeed.current_speed = ((float)((uint32_t)nonce_hex[0]*256*256*256 + (uint32_t)nonce_hex[1]*256*256 +
		                                    (uint32_t)nonce_hex[2]*256 + nonce_hex[3])/
		                                    (float)using_time_ms/1000.0);
	FPRINTF(("now speed is %dMHz\n" , statis_info.hashspeed.current_speed));
	statis_info.hashspeed.dnonce=((uint32_t)nonce_hex[0]*256*256*256 + (uint32_t)nonce_hex[1]*256*256 + (uint32_t)nonce_hex[2]*256 + nonce_hex[3]);
	statis_info.hashspeed.total_nonce = statis_info.hashspeed.dnonce + statis_info.hashspeed.total_nonce;
	statis_info.hashspeed.total_time = statis_info.hashspeed.total_time + using_time_ms;
	total_time_ms = statis_info.hashspeed.total_time;
	statis_info.total_mhs= (float)statis_info.hashspeed.total_nonce/(float)total_time_ms/1000.0;
	FPRINTF(("total nonce is %x%x, total speed is %dMhz\n" , (unsigned int)((statis_info.hashspeed.total_nonce>>31)&0xffffffff),(unsigned int)(statis_info.hashspeed.total_nonce&0xffffffff), statis_info.total_mhs));
	
}


void update_hash_speed(uint32_t nonce_bin)
{
	unsigned char *nonce_hex = (unsigned char *)&nonce_bin;
	uint32_t using_time_ms,total_time_ms;

//	statis_info.hashspeed.prevendtick = statis_info.hashspeed.endtick;
    statis_info.hashspeed.endtick = rt_tick_get();
	using_time_ms=((statis_info.hashspeed.endtick-statis_info.hashspeed.prevendtick)*(1000/RT_TICK_PER_SECOND));
	DPRINTF(("This using time %d ms\n" ,using_time_ms));
	statis_info.hashspeed.current_speed = ((float)((uint32_t)nonce_hex[0]*256*256*256 + (uint32_t)nonce_hex[1]*256*256 +
		                                    (uint32_t)nonce_hex[2]*256 + nonce_hex[3])/
		                                    (float)using_time_ms/1000.0);
	DPRINTF(("now speed is %dMHz\n" , statis_info.hashspeed.current_speed));
	statis_info.hashspeed.dnonce=((uint32_t)nonce_hex[0]*256*256*256 + (uint32_t)nonce_hex[1]*256*256 + (uint32_t)nonce_hex[2]*256 + nonce_hex[3]);
	statis_info.hashspeed.total_nonce = statis_info.hashspeed.dnonce + statis_info.hashspeed.total_nonce;
	total_time_ms=((statis_info.hashspeed.endtick - statis_info.hashspeed.starttick)*(1000/RT_TICK_PER_SECOND));
	statis_info.total_mhs= (float)statis_info.hashspeed.total_nonce/(float)total_time_ms/1000.0;
	FPRINTF(("total nonce is %x%x, total speed is %dMhz\n" , (unsigned int)((statis_info.hashspeed.total_nonce>>31)&0xffffffff),(unsigned int)(statis_info.hashspeed.total_nonce&0xffffffff), statis_info.total_mhs));
	
}


bool suw(struct work *work)
{
	char *hexstr = NULL;
	cJSON *root=NULL, *res_val=NULL;
	char *s;
	bool rc = false;
	int rpc_call_retry=0;
	uint32_t *work_nonce = (uint32_t *)(work->data + 64 + 12);
	FPRINTF(("\n ============= SUBMIT UPSTREAM WORK START ================= \n"));

	*work_nonce = htole32(work->nonce);
    FPRINTF(("SUW work_nonce: 0x%x\n",*work_nonce));
	
     endian_flip128(work->data, work->data);
	/* build hex string */
	hexstr = bin2hex(work->data, sizeof(work->data));

	/* build JSON-RPC request */
	s = rt_strdup("{\"method\": \"getwork\", \"params\": [ \"");
	s = realloc_strcat(s, hexstr);
	s = realloc_strcat(s, "\" ], \"id\":1}");
	s = realloc_strcat(s, "\n");
	DPRINTF(("DBG: sending submit RPC call: %s\n",s));

	/* issue JSON-RPC request */
retry:
	pthread_mutex_lock(&network_acc_lock);
    root = json_rpc_call_suw(statis_info.current_pool,statis_info.current_user,statis_info.current_pass,s);
    pthread_mutex_unlock(&network_acc_lock);
	if (unlikely(!root)) {
#if 0		
		FPRINTF(("submit_upstream_work json_rpc_call failed, retry %d times\n",rpc_call_retry));
		rt_thread_delay(RT_TICK_PER_SECOND*1);
		if(rpc_call_retry < PRC_CALL_RETRY_MAX){
		   rpc_call_retry++;
           goto retry;
		}
		else
#endif			
		{
		   rt_free(s);
		   rc = false;
		   goto out;
		}
	} 
	rt_free(s);
	res_val = cJSON_GetObjectItem(root,GW_RESULT);	
	if (res_val && (cJSON_is_true(res_val))) {
		DPRINTF(("PROOF OF WORK RESULT: true !!!\n"));
        //update_hash_speed(*work_nonce);
		rc = true;
	}
	else{
		DPRINTF(("PROOF OF WORK RESULT: false !!!\n"));
		res_val = cJSON_GetObjectItem(root, "reject-reason");
		s = cJSON_Print(res_val);
		if(s){
		  DPRINTF(("\n reject-reason: \n %s\n",s));
	      rt_free(s);
		}
		rc = false;
	}
	cJSON_Delete(root);
out:
//	update_hash_speed(*work_nonce);
	rt_free(hexstr);
	return rc;
}

////////////////////////////////CHIP Miner//////////////////////////////////////

static void rev(unsigned char *s, rt_size_t l)
{
	rt_size_t i, j;
	unsigned char t;

	for (i = 0, j = l - 1; i < j; i++, j--) {
		t = s[i];
		s[i] = s[j];
		s[j] = t;
	}
}

static int chip_gets(unsigned char *buf, rt_device_t device, struct timeval *tv_finish, int read_count)
{
	rt_size_t ret = 0;
	unsigned int rc = 0;
	int read_amount = CHIP_READ_SIZE;
	bool first = true;

	// Read reply 1 byte at a time to get earliest tv_finish
	while (true) {
		ret = rt_device_read(chip,0,buf,CHIP_READ_SIZE);
		if (ret < 0)
			return CHIP_GETS_ERROR;

		if (ret >= read_amount)
			return CHIP_GETS_OK;

		if (ret > 0) {
			buf += ret;
			read_amount -= ret;
			first = false;
			continue;
		}		
		rc++;
		if (rc >= read_count) {
			DPRINTF(("Chip Read: No data in %d seconds\n",(rc/RT_TICK_PER_SECOND)));
			return CHIP_GETS_TIMEOUT;
		}
		rt_thread_delay(1);
        #ifdef HAVE_IWDG
        IWDG_feed();
        #endif
   }
}


static bool chip_detect()
{

//	struct timeval tv_start, tv_finish;
	rt_err_t result = RT_EOK;

	// Block 171874 nonce = (0xa2870100) = 0x000187a2
	// N.B. golden_ob MUST take less time to calculate
	//	than the timeout set in icarus_open()
	//	This one takes ~0.53ms on Rev3 Icarus
	const char golden_ob[] =
		"4679ba4ec99876bf4bfe086082b40025"
		"4df6c356451471139a3afa71e48f544a"
		"00000000000000000000000000000000"
		"0000000087320b1a1426674f2fa722ce";

	const char golden_nonce[] = "000187a2";
	const uint32_t golden_nonce_val = 0x000187a2;
	unsigned char ob_bin[64], nonce_bin[CHIP_READ_SIZE];
	char *nonce_hex;

	DPRINTF(("\n ====== Chip Detect: Attempting to open =======\n"));
	if((chip = rt_device_find(CHIP_MINER_HW))==RT_NULL){
       DPRINTF(("Chip Device can not find !!!!!\n"));
       return false;
	}
	if((result=rt_device_open(chip, RT_DEVICE_OFLAG_RDWR))!=RT_EOK){
       DPRINTF(("Chip Device can not open !!!!!,error='%L'\n",result));
       return false;
	}		
	hex2bin(ob_bin, golden_ob, sizeof(ob_bin));
#if 1
	rt_device_write(chip,0,ob_bin, sizeof(ob_bin));
#else
    rt_device_write(chip,0,golden_ob, sizeof(golden_ob));
#endif
	memset(nonce_bin, 0, sizeof(nonce_bin));
	//rt_thread_delay(RT_TICK_PER_SECOND*2);
	chip_gets(nonce_bin, chip, NULL, RT_TICK_PER_SECOND * 2);
//	rt_device_read(chip,0,nonce_bin,4);
	rt_device_close(chip);

	nonce_hex = bin2hex(nonce_bin, sizeof(nonce_bin));
	if (strncmp(nonce_hex, golden_nonce, 8)) {
		FPRINTF((
			"Chip Detect: "
			"Test failed: get %s, should: %s\n",
			nonce_hex, golden_nonce));
		rt_free(nonce_hex);
		return false;
	}
	FPRINTF((
		"Chip Detect: "
		"Test succeeded: got %s\n",
			nonce_hex));
	rt_free(nonce_hex);
    return true;
}

#ifdef RT_USING_FINSH
#include <finsh.h>
FINSH_FUNCTION_EXPORT(chip_detect, chip detect test);
#endif

void flush_chip(rt_device_t chip)
{
// TODO: USE ERROR NO 
char buf[8];
	rt_device_read(chip,0,buf,128);
}

#if 1
/*
 * GPIO Configuration for ChipMiner
 */
static void chip_reset_high(void)
{
	GPIO_InitTypeDef GPIO_InitStructure;
	struct chip_reset_pin crp;

	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_10MHz;
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;

	crp.GPIOx = GPIOE;
    crp.GPIO_Pin = GPIO_Pin_2;
	RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOE, ENABLE);

    GPIO_InitStructure.GPIO_Pin = crp.GPIO_Pin;
    GPIO_SetBits(crp.GPIOx, crp.GPIO_Pin);
    GPIO_Init(crp.GPIOx, &GPIO_InitStructure);
	
}

static void chip_reset_low(void)
{
	GPIO_InitTypeDef GPIO_InitStructure;
	struct chip_reset_pin crp;

	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_10MHz;
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;

	crp.GPIOx = GPIOE;
    crp.GPIO_Pin = GPIO_Pin_2;
	RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOE, ENABLE);

    GPIO_InitStructure.GPIO_Pin = crp.GPIO_Pin;
    GPIO_ResetBits(crp.GPIOx, crp.GPIO_Pin);
    GPIO_Init(crp.GPIOx, &GPIO_InitStructure);	
}

void pin_set(int val)
{
 if(val==1){
   chip_reset_high();
 }
 else{
   chip_reset_low();
 }
}

tClockTable clocktable[MAX_CLOCK] =
{
 CLOCK_200M,200,0,0,0,672,
 CLOCK_225M,225,1,0,1,596,
 CLOCK_250M,250,1,0,0,536,
 CLOCK_275M,275,0,1,1,488,
 CLOCK_300M,300,0,1,0,448,
 CLOCK_350M,350,1,1,0,384,
 CLOCK_400M,400,1,1,1,336,
};


static void chip_set_clock(eClock clock)
{
	GPIO_InitTypeDef GPIO_InitStructure;
	struct chip_reset_pin crp;

////////////////////////   PD2   //////////////////////////////////	
	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_10MHz;
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;

	crp.GPIOx = GPIOD;
	crp.GPIO_Pin = GPIO_Pin_2;
	RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOD, ENABLE);

	GPIO_InitStructure.GPIO_Pin = crp.GPIO_Pin;
	if(clocktable[clock].PD2==0){
	   GPIO_ResetBits(crp.GPIOx, crp.GPIO_Pin);
	}
	else{
	   GPIO_SetBits(crp.GPIOx, crp.GPIO_Pin);
	}
	GPIO_Init(crp.GPIOx, &GPIO_InitStructure);
	
///////////////////////   PD3   /////////////////////////////////  

	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_10MHz;
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;

	crp.GPIOx = GPIOD;
    crp.GPIO_Pin = GPIO_Pin_3;
	RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOD, ENABLE);

    GPIO_InitStructure.GPIO_Pin = crp.GPIO_Pin;
	if(clocktable[clock].PD3==0){
	   GPIO_ResetBits(crp.GPIOx, crp.GPIO_Pin);
	}
	else{
	   GPIO_SetBits(crp.GPIOx, crp.GPIO_Pin);
	}

    GPIO_Init(crp.GPIOx, &GPIO_InitStructure);


///////////////////////   PD4   /////////////////////////////////// 
	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_10MHz;
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;

	crp.GPIOx = GPIOD;
    crp.GPIO_Pin = GPIO_Pin_4;
	RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOD, ENABLE);

    GPIO_InitStructure.GPIO_Pin = crp.GPIO_Pin;
    if(clocktable[clock].PD4==0){
	   GPIO_ResetBits(crp.GPIOx, crp.GPIO_Pin);
	}
	else{
	   GPIO_SetBits(crp.GPIOx, crp.GPIO_Pin);
	}
    GPIO_Init(crp.GPIOx, &GPIO_InitStructure);
	
}




static void chip_pin_config(void)
{
	GPIO_InitTypeDef GPIO_InitStructure;
	struct chip_reset_pin crp;
//////////////////////////////////////////////////////////	LOW
	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_10MHz;
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;

	crp.GPIOx = GPIOD;
	crp.GPIO_Pin = GPIO_Pin_2;
	RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOD, ENABLE);

	GPIO_InitStructure.GPIO_Pin = crp.GPIO_Pin;
	GPIO_ResetBits(crp.GPIOx, crp.GPIO_Pin);//GPIO_SetBits(crp.GPIOx, crp.GPIO_Pin);
	GPIO_Init(crp.GPIOx, &GPIO_InitStructure);
	
////////////////////////////////////////////////////////  HIGH

	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_10MHz;
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;

	crp.GPIOx = GPIOD;
    crp.GPIO_Pin = GPIO_Pin_3;
	RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOD, ENABLE);

    GPIO_InitStructure.GPIO_Pin = crp.GPIO_Pin;
    GPIO_SetBits(crp.GPIOx, crp.GPIO_Pin);
    GPIO_Init(crp.GPIOx, &GPIO_InitStructure);


////////////////////////////////////////////////////////// LOW
	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_10MHz;
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;

	crp.GPIOx = GPIOD;
    crp.GPIO_Pin = GPIO_Pin_4;
	RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOD, ENABLE);

    GPIO_InitStructure.GPIO_Pin = crp.GPIO_Pin;
    GPIO_ResetBits(crp.GPIOx, crp.GPIO_Pin);
    GPIO_Init(crp.GPIOx, &GPIO_InitStructure);
	
}



#ifdef RT_USING_FINSH
#include <finsh.h>
FINSH_FUNCTION_EXPORT(pin_set, set chip reset pin);
#endif

void chip_reset()
{
	chip_reset_low();  
//	rt_thread_delay(1);
	chip_reset_high();  
}

void chip_reset2()
{
int i,n=0;
	chip_reset_low();  
	for(i=0;i<1000;i++){n++;}
	chip_reset_high();  
}


#endif


static bool chip_scanhash(struct work *work)
{
	rt_size_t ret;
	rt_err_t result = RT_EOK;
	unsigned char ob_bin[64], nonce_bin[CHIP_READ_SIZE];
	char *ob_hex;
	uint32_t nonce;
	int read_count;
	rt_tick_t starttick,endtick;
	FPRINTF(("\n ====== Chip Scanhash START =======\n"));
	if((chip = rt_device_find(CHIP_MINER_HW))==RT_NULL){
       DPRINTF(("Chip Device can not find !!!!!\n"));
       return false;
	}
	if((result=rt_device_open(chip, RT_DEVICE_OFLAG_RDWR))!=RT_EOK){
       DPRINTF(("Chip Device can not open !!!!!,error='%L'\n",result));
       return false;
	}	
	//flush_chip(chip);
	memset(ob_bin, 0, sizeof(ob_bin));
	memcpy(ob_bin, work->midstate, 32);
	memcpy(ob_bin + 52, work->data + 64, 12);
	rev(ob_bin, 32);
	rev(ob_bin + 52, 12);

	ret=rt_device_write(chip,0,ob_bin, sizeof(ob_bin));
	if (ret!= sizeof(ob_bin)) {
		rt_device_close(chip);
		DPRINTF(("Comms write error !!!!!!"));
		return false;	/* This should never happen */
	}
	if (show_chip_data) {
		ob_hex = bin2hex(ob_bin, sizeof(ob_bin));
		DPRINTF(("Chip sent: %s\n",ob_hex));
		rt_free(ob_hex);
	}

	/* Icarus will return 4 bytes (CHIP_READ_SIZE) nonces or nothing */
	memset(nonce_bin, 0, sizeof(nonce_bin));
	read_count= (((float)chip_settings.settings.wait_time/1000)*RT_TICK_PER_SECOND);///2;
    DPRINTF(("Chip read count =%d\n",read_count));
	starttick=rt_tick_get();
	ret = chip_gets(nonce_bin, chip, NULL, read_count);
	endtick=rt_tick_get();
	chip_reset();
	FPRINTF(("Chip Gets time use = %d\n",(endtick-starttick)));
	if (ret == CHIP_GETS_ERROR || ret == CHIP_GETS_TIMEOUT) {
		work->nonce=0;
		rt_device_close(chip);
		FPRINTF(("Comms gets error !!!!!!\n"));
		//update_hash_speed_chip(starttick,endtick,0);
		return false;
	}  
	memcpy((char *)&nonce, nonce_bin, sizeof(nonce_bin));
	DPRINTF(("Chip read: 0x%x\n",nonce));
    nonce = swab32(nonce);
	work->nonce=nonce;
    update_hash_speed_chip(starttick,endtick,nonce);
	rt_device_close(chip);
	return true;

#if 0
	////////////////////// suw //////////////////////////////////
	starttick=rt_tick_get();
	if(suw(work, nonce) == false){
 	   DPRINTF(("Failed to submit work !!!!\n"));
	   endtick=rt_tick_get();
	   FPRINTF(("SUW time use = %d\n",(endtick-starttick)));
	   //rt_device_close(chip);
	   return false;
	}
	else{
	   DPRINTF(("submit work ok\n"));
	   endtick=rt_tick_get();
	   FPRINTF(("SUW time use = %d\n",(endtick-starttick)));
	   //rt_device_close(chip);
	   return true;
	}
	return false;	
#endif	
}

#ifdef RT_USING_FINSH
#include <finsh.h>
FINSH_FUNCTION_EXPORT(chip_scanhash, chip scanhash test);
#endif

#ifndef HAVE_WORK_QUEUE
void miner(uint32_t count)
{
	rt_uint16_t i;
	struct work *work;
	rt_tick_t starttick,endtick;	
	   FPRINTF(("\n ============= MINER BEGIN =============== \n"));
	   statis_info.hashspeed.prevendtick = rt_tick_get();
	   while (1)
	   {
			TRACE();
			   /// fill work que
	        for(i=0;i<MAX_WORK_QUEUE_LEN;i++){ 
			    starttick=rt_tick_get();
				while(guw(&(miner_work[i]))!=true){
				  TRACE_MEM();
				}
				endtick=rt_tick_get();
			    FPRINTF(("GUW time use = %d\n",(endtick-starttick)));
				statis_info.total_getworks++;  
		    }
			   /// scanhash work que
	        for(i=0;i<MAX_WORK_QUEUE_LEN;i++){ 
				chip_scanhash(&(miner_work[i]));
		    }
			   /// submit work que
	        for(i=0;i<MAX_WORK_QUEUE_LEN;i++){ 
				chip_scanhash(&(miner_work[i]));
			    starttick=rt_tick_get();
                suw(&(miner_work[i]));        
	            endtick=rt_tick_get();
	            FPRINTF(("SUW time use = %d\n",(endtick-starttick)));
		    }		
		}
}

#else

void miner(uint32_t count)
{
rt_uint16_t mb_entry;
struct work *free_work;
rt_tick_t starttick,endtick;

   FPRINTF(("\n ============= MINER BEGIN =============== \n"));
   statis_info.hashspeed.prevendtick = rt_tick_get();
   while (1)
   {
     if(rt_mb_recv(workq_free_mbox, (rt_uint32_t*)&free_work, RT_WAITING_FOREVER) == RT_EOK)
    {  
        TRACE();
#ifdef HAVE_IWDG
	   IWDG_feed();
#endif
		starttick=rt_tick_get();
        while(guw(free_work)!=true){
		  TRACE_MEM();
          #ifdef HAVE_IWDG
            IWDG_feed();
          #endif		  
        }
		endtick=rt_tick_get();
	  	FPRINTF(("GUW time use = %d\n",(endtick-starttick)));		
	    statis_info.total_getworks++;  
	    rt_mb_control(workq_free_mbox, 0x02, &mb_entry);
		FPRINTF(("Free mbox have = %d\n",mb_entry));
		rt_mb_control(workq_mid_mbox, 0x02, &mb_entry);
		FPRINTF(("Mid mbox have = %d\n",mb_entry));		
	    rt_mb_control(workq_full_mbox, 0x02, &mb_entry);
		FPRINTF(("Full mbox have = %d\n",mb_entry));
		rt_mb_send_wait(workq_mid_mbox, (rt_uint32_t)free_work, RT_WAITING_FOREVER);     	
	}
   }
}

void scanhash_thread(void* parameter)
{ 
struct work *mid_work;
   FPRINTF(("\n ============= SCAN HASH BEGIN =============== \n"));
   while(1)
   {
   	 TRACE();
   	 if(rt_mb_recv(workq_mid_mbox, (rt_uint32_t*)&mid_work, RT_WAITING_FOREVER) == RT_EOK)
     {  
       TRACE();
       if(chip_scanhash(mid_work)==true){
	   	  rt_mb_send_wait(workq_full_mbox, (rt_uint32_t)mid_work, RT_WAITING_FOREVER); 
       }
	   else{
	      rt_mb_send_wait(workq_free_mbox, (rt_uint32_t)mid_work, RT_WAITING_FOREVER); 
	   }
	 } 
   }  
}

void submit_thread(void* parameter)
{ 
struct work *full_work;
rt_tick_t starttick,endtick;
   FPRINTF(("\n ============= SUBMIT BEGIN =============== \n"));
   while(1)
   {
   	 TRACE();
   	 if(rt_mb_recv(workq_full_mbox, (rt_uint32_t*)&full_work, RT_WAITING_FOREVER) == RT_EOK)
     {  
       TRACE();
	   starttick=rt_tick_get();
       if(suw(full_work)==true){
	      statis_info.total_accepted++;
		  FPRINTF(("\n ========================================= \n 	  MINER STATUS!!!  GET %d, ACCEPTED %d	  \n ========================================= \n",
						statis_info.total_getworks, statis_info.total_accepted));
       } 
	   endtick=rt_tick_get();
	   FPRINTF(("SUW time use = %d\n",(endtick-starttick)));	
	   rt_mb_send_wait(workq_free_mbox, (rt_uint32_t)full_work, RT_WAITING_FOREVER);     	
	 } 
   }  
}


#endif

#ifdef RT_USING_FINSH
#include <finsh.h>
FINSH_FUNCTION_EXPORT(miner, chip miner function);
#endif



/////////////////////////////////     Web server //////////////////////////////////////////

//#define HAVE_WEB_SRV

#ifdef HAVE_WEB_SRV
static int simple_authenticator(hrequest_t *req, const char *user, const char *password)
{

	log_info3("logging in user=\"%s\" password=\"%s\"", user, password);

	if (strcmp(user, WEB_SERVER_AUTH_USER)) {

		log_warn2("user \"%s\" unkown", user);
		return 0;
	}

	if (strcmp(password, WEB_SERVER_AUTH_PASS)) {

		log_warn1("wrong password");
		return 0;
	}

	return -1;
}

static void default_service(httpd_conn_t *conn, hrequest_t *req)
{

	httpd_send_header(conn, 404, "Not found");
	hsocket_send(conn->sock,
		"<html>"
			"<head>"
				"<title>Default error page</title>"
			"</head>"
			"<body>"
				"<h1>Default error page</h1>"
				"<div>");

	hsocket_send(conn->sock, req->path);

	hsocket_send(conn->sock, " can not be found"
		       		"</div>"
			"</body>"
		"</html>");

	return;
}	

uint32_t __inline get_up_seconds()
{
	return (rt_tick_get()- power_on_tick)/RT_TICK_PER_SECOND ;
}
uint32_t get_up_time(char* up_time_str)
{
  	rt_tick_t rt_now_tick;
	uint32_t sec,days,hours,minutes,mod;
    rt_now_tick = rt_tick_get(); 
	sec= (rt_now_tick - power_on_tick)/RT_TICK_PER_SECOND ;
	days = sec / (SPD);
	mod = sec % (SPD);
	hours = mod / 3600;
	mod = mod % 3600;
    minutes = mod / 60;
	mod = mod % 60;
	if(up_time_str){
      sprintf(up_time_str,UP_TIME_TEMPL,days,hours,minutes,mod);
	}
	return 0;
}


void build_default_settings(tSettings * set)
{
  if(set==NULL)
	 return;
  set->MAGIC_CODE=SETTING_MAGIC_CODE;
  strcpy(set->pool_url,SETTING_DEFAULT_POOL_URL);
  strcpy(set->username,SETTING_DEFAULT_USER);
  strcpy(set->password,SETTING_DEFAULT_PASSWORD);
  strcpy(set->ip,SETTING_DEFAULT_IP);
  strcpy(set->mask,SETTING_DEFAULT_NETMASK);
  strcpy(set->gateway,SETTING_DEFAULT_GW);
  strcpy(set->DNS1,SETTING_DEFAULT_DNS1);
  set->clock=SETTING_DEFAULT_CHIP_CLOCK;
  set->wait_time=clocktable[set->clock].wait_time;
}


static void dump_settings()
{
tSettings * set = &(chip_settings.settings);
	if(set==NULL)
	   return;
	FPRINTF(("======= dump_settings =======\n"));
    FPRINTF(("Magic code :0x%x, \n",set->MAGIC_CODE));
    FPRINTF(("pool url :%s \n",set->pool_url));
	FPRINTF(("user name :%s \n",set->username));
	FPRINTF(("password :%s \n",set->password));
	FPRINTF(("Chip clock :%d \n",clocktable[set->clock].clock_real));
	FPRINTF(("wait time ms :%d \n",set->wait_time));
	FPRINTF(("\n"));
}

#ifdef RT_USING_FINSH
#include <finsh.h>
FINSH_FUNCTION_EXPORT(dump_settings, dump settings);
#endif


static void dump_stinfo()
{
tStatisInfo * info = &statis_info;
	FPRINTF(("======= dump_statis info =======\n"));
	FPRINTF(("total_mhs :%dMHz, \n",info->total_mhs));
	FPRINTF(("now speed is %dMHz\n" , info->hashspeed.current_speed));
	FPRINTF(("total_getworks :%d, \n",info->total_getworks));
	FPRINTF(("total_accepted :%d, \n",info->total_accepted));
	FPRINTF(("total_rejected :%d, \n",info->total_rejected));
	FPRINTF(("chip_detect_error :%d, \n",info->chip_detect_error));
	get_up_time(info->up_time);		
	FPRINTF(("up_time :%s, \n",info->up_time));
	FPRINTF(("current_pool :%s, \n",info->current_pool));
	FPRINTF(("current_user :%s, \n",info->current_user));
	FPRINTF(("current_pass :%s, \n",info->current_pass));
	FPRINTF(("\n"));
}

#ifdef RT_USING_FINSH
#include <finsh.h>
FINSH_FUNCTION_EXPORT(dump_stinfo, dump statis info);
#endif

void flash_erase()
{
int *t;
	FLASH_Unlock();
//    rt_kprintf("data write 0x%x!\n" , SETTING_MAGIC_CODE);
	FLASH_ErasePage(SETTING_PAGE_ADDR);
//	FLASH_ProgramWord(0x0803F800,SETTING_MAGIC_CODE);
	FLASH_Lock();
	t = (int *)(0x0803F800);
	rt_kprintf("data read 0x%x!\n" , *t);
}

#ifdef RT_USING_FINSH
#include <finsh.h>
FINSH_FUNCTION_EXPORT(flash_erase, flash write read test);
#endif

void flash_test()
{
int *t;
	FLASH_Unlock();
//    rt_kprintf("data write 0x%x!\n" , SETTING_MAGIC_CODE);
	FLASH_ErasePage(SETTING_PAGE_ADDR);
//	FLASH_ProgramWord(0x0803F800,SETTING_MAGIC_CODE);
	FLASH_Lock();
	t = (int *)(SETTING_PAGE_ADDR);
	rt_kprintf("data read 0x%x!\n" , *t);
}

#ifdef RT_USING_FINSH
#include <finsh.h>
FINSH_FUNCTION_EXPORT(flash_test, flash write read test);
#endif



static void save_settings()
{
int i;
FLASH_Status sts;
    FLASH_Unlock();
	if((sts=FLASH_ErasePage(SETTING_PAGE_ADDR))== FLASH_COMPLETE){
       for(i=0;i<(sizeof(tSettings)/sizeof(uint32_t));i++){
	   	//  DPRINTF(("write i=%d, data=0x%x \n" ,i,(chip_settings.words[i])));
          sts=FLASH_ProgramWord((SETTING_PAGE_ADDR+i*sizeof(uint32_t)),chip_settings.words[i]); 
          if(sts!= FLASH_COMPLETE){
             FPRINTF(("FLASH program error(%d) !!!! \n",sts));
			 goto err_out;
		  }
		  else{
		  	#if 0
		  	uint32_t *p;
            p = (uint32_t *)(SETTING_PAGE_ADDR+i*sizeof(uint32_t));
            DPRINTF(("read i=%d, data=0x%x \n" ,i,(*p)));
			#endif
		  }
	   }
	}
	else{
       FPRINTF(("FLASH_ErasePage error(%d) !!!! \n",sts));
	   goto err_out;
	}
	FLASH_Lock();
	DPRINTF(("save_settings successful !!!! \n"));
	return;
  
err_out:
	FLASH_Lock();
	FPRINTF(("save_settings error(%d) !!!! \n",sts));
}

void dns_info_from_setting(struct ip_addr *addr)
{
    if(addr != RT_NULL)
    {
       ipaddr_aton(chip_settings.settings.DNS1, addr);
    }
}

void network_info_from_setting(struct ip_addr *ipaddr, struct ip_addr *netmask, struct ip_addr *gw)
{
    if(ipaddr != RT_NULL)
    {
       ipaddr_aton(chip_settings.settings.ip, ipaddr);
    }
	if(netmask != RT_NULL)
    {
       ipaddr_aton(chip_settings.settings.mask, netmask);
    }
	if(gw != RT_NULL)
    {
       ipaddr_aton(chip_settings.settings.gateway, gw);
    }	
}



static void load_settings()
{
int i;
uint32_t magic;
uint32_t *p;
   p = (uint32_t *)SETTING_PAGE_ADDR;
   magic = *(p);
   DPRINTF(("\n load magic = 0x%x !!!! \n",magic));
   if(magic == SETTING_MAGIC_CODE){
   	 for(i=0;i<(sizeof(tSettings)/sizeof(uint32_t));i++){
	   chip_settings.words[i]= *(p + i);
	  // DPRINTF(("read i=%d, data=0x%x \n" ,i, chip_settings.words[i]));
	 }
   }
   else{
   	 build_default_settings(&(chip_settings.settings));
	 save_settings();
 	 FPRINTF(("load & save default settings! \n"));
   }
   dump_settings();
   DPRINTF(("load_settings successful !!!! \n"));
   return;
}

#ifdef RT_USING_FINSH
#include <finsh.h>
FINSH_FUNCTION_EXPORT(load_settings, load current setting);
#endif


static void update_statisinfo(tStatisInfo *statis)
{
	statis->chip_version = SETTING_CHIP_VERSION;
	get_base_network_info(statis->ip, statis->mask, statis->gateway, statis->DNS1,statis->DNS2);
	statis->webserver_port = 10000;
    get_up_time(statis->up_time);
    statis->pool_url=chip_settings.settings.pool_url;
	statis->username=chip_settings.settings.username;
	statis->password=chip_settings.settings.password;
}

////////////////////////////////// Form parser ///////////////////////////////////

typedef struct cgiFormEntryStruct {
    char *attr;
	char *value;
  struct cgiFormEntryStruct *next;
} cgiFormEntry;

typedef enum {
	cgiEscapeRest,
	cgiEscapeFirst,
	cgiEscapeSecond
} cgiEscapeState;

static cgiFormEntry *cgiFormEntryFirst=NULL;

static void cgiFreeResources() {
	cgiFormEntry *c = cgiFormEntryFirst;
	cgiFormEntry *n;
	while (c) {
		n = c->next;
		free(c->attr);
		free(c->value);
		free(c);
		c = n;
	}
	cgiFormEntryFirst = NULL;
}

char* cgi_get_value(char* key) {
	cgiFormEntry *c = cgiFormEntryFirst;
	cgiFormEntry *n;
	while (c) {
		n = c->next;
		if(strcmp(key,c->attr)==0){
       return c->value;
    }
		c = n;
	}
	return NULL;
}

int cgiUnescapeChars(char **sp, char *cp, int len) {
	char *s;
	cgiEscapeState escapeState = cgiEscapeRest;
	int escapedValue = 0;
	int srcPos = 0;
	int dstPos = 0;
	s = (char *) malloc(len + 1);
	if (!s) {
		return -1;
	}
	while (srcPos < len) {
		int ch = cp[srcPos];
		switch (escapeState) {
			case cgiEscapeRest:
			if (ch == '%') {
				escapeState = cgiEscapeFirst;
				if(cp[srcPos+1]=='4' && cp[srcPos+2]=='0'){  //@
                   escapedValue='@'; 
				   s[dstPos++] = escapedValue;
				   escapeState = cgiEscapeRest;
				   srcPos = srcPos+2;
				}
			} else if (ch == '+') {
				s[dstPos++] = ' ';
			} else {
				s[dstPos++] = ch;	
			}
			break;
			case cgiEscapeFirst:
			escapedValue =((ch-0x30) << 4);	
			//printf("1. ch=0x%x, escapedValue=0x%0x\n",ch,escapedValue);
			escapeState = cgiEscapeSecond;
			break;
			case cgiEscapeSecond:
			escapedValue +=((ch-0x37));
			//printf("2. ch=0x%x, escapedValue=0x%0x\n",ch,escapedValue);
			s[dstPos++] = escapedValue;
			escapeState = cgiEscapeRest;
			break;
		}
		srcPos++;
	}
	s[dstPos] = '\0';
	*sp = s;
	return 0;
}		

static int cgiParseFormInput(char *data, int length) {
	/* Scan for pairs, unescaping and storing them as they are found. */
	int pos = 0;
	cgiFormEntry *n;
	cgiFormEntry *l = 0;
	while (pos != length) {
		int foundEq = 0;
		int foundAmp = 0;
		int start = pos;
		int len = 0;
		char *attr;
		char *value;
		while (pos != length) {
			if (data[pos] == '=') {
				foundEq = 1;
				pos++;
				break;
			}
			pos++;
			len++;
		}
		if (!foundEq) {
			break;
		}
		if (cgiUnescapeChars(&attr, data+start, len)
			!= 0) {
			return -1;
		}	
		start = pos;
		len = 0;
		while (pos != length) {
			if (data[pos] == '&') {
				foundAmp = 1;
				pos++;
				break;
			}
			pos++;
			len++;
		}
		/* The last pair probably won't be followed by a &, but
			that's fine, so check for that after accepting it */
		if (cgiUnescapeChars(&value, data+start, len)
			!= 0) {
			free(attr);
			return -1;
		}	
		/* OK, we have a new pair, add it to the list. */
		n = (cgiFormEntry *) malloc(sizeof(cgiFormEntry));	
		if (!n) {
			free(attr);
			free(value);
			return -1;
		}
		n->attr = attr;
		n->value = value;
		n->next = 0;
		if (!l) {
			cgiFormEntryFirst = n;
		} else {
			l->next = n;
		}
		l = n;
		if (!foundAmp) {
			break;
		}			
	}
	return 0;
}

///////////////////////////////////////////////////////////////////////////////

void update_current_pool(char* dst_pool, char* src_pool,
	                           char* dst_user, char* src_user,
	                           char* dst_pass, char* src_pass)
{
    strcpy(dst_pool,src_pool);
	strcpy(dst_user,src_user);
    strcpy(dst_pass,src_pass);
}


static void root_service(httpd_conn_t *conn, hrequest_t *req)
{
char buffer[256];
uint32_t read_len;
uint32_t clock_read;

	if (req->method == HTTP_REQUEST_POST) {
//		httpd_send_header(conn, 200, "OK");
		/*	  Read the reponse content	 */
		while(http_input_stream_is_ready(req->in)) {
			read_len = http_input_stream_read(req->in, buffer, 256);
			buffer[read_len] = '\0';
			if (show_content){
				DPRINTF((" ========== Begin dump update setting content ========= \n\n")); 		   
				DPRINTF((buffer));
				DPRINTF(("\n"));
			}
		}
		////////// Parse input settings ///////////////
	    cgiParseFormInput(buffer,read_len);
		strcpy(chip_settings.settings.ip,cgi_get_value("CRIP"));
		strcpy(chip_settings.settings.mask,cgi_get_value("CMSK"));
		strcpy(chip_settings.settings.gateway,cgi_get_value("CGTW"));
		strcpy(chip_settings.settings.DNS1,cgi_get_value("PDNS"));		
		strcpy(chip_settings.settings.pool_url,cgi_get_value("PURL"));
		strcpy(chip_settings.settings.username,cgi_get_value("USER"));
		strcpy(chip_settings.settings.password,cgi_get_value("PASS"));
		chip_settings.settings.wait_time=atoi(cgi_get_value("WATM"));
		clock_read=atoi(cgi_get_value("CLCK"));	
        if(clock_read>MAX_CLOCK || clock_read<(CLOCK_200M+1)){
           chip_settings.settings.clock=CLOCK_200M;	   
		}	
		else{
           chip_settings.settings.clock=clock_read-1;
		}
		chip_settings.settings.wait_time=clocktable[chip_settings.settings.clock].wait_time;
		cgiFreeResources();	
		/////////////////////////////////////////
        dump_settings(&(chip_settings.settings));
        save_settings();
		rt_thread_delay(1);
		rt_hw_cpu_reset();
#if 0
		while(statis_info.scanhash_run==true){
		      rt_thread_delay(1);
		}
		restart_miner=true;
#endif		
        update_current_pool(statis_info.current_pool, chip_settings.settings.pool_url,
		                statis_info.current_user, chip_settings.settings.username,
		                statis_info.current_pass, chip_settings.settings.password);	
		// TODO: Add other reset chip operations  here, future should use mutex   		
        restart_miner=false;
	}
	httpd_send_header(conn, 200, "OK");
	update_statisinfo(&statis_info);
    sprintf(MAIN_page, MAIN_PAGE_TEMPL, 
        //"    <TD align=right>Total MHS:</TD> "                                                        
        statis_info.total_mhs,                                                
        //"    <TD align=right>Received:</TD>  "
//        statis_info.total_getworks,
        //"    <TD align=right>Accepted:</TD>  "
//         statis_info.total_accepted,
        //"    <TD align=right>Up Time:</TD>"
        statis_info.up_time,
        //"<BR>Current Server:%s" 
        statis_info.current_pool,
        //"<BR>Clock selected: %d" 
        chip_settings.settings.clock+1,
        //"<BR>Chip: %d "
        statis_info.chip_version,
//"    <TD align=right>IP</TD>                                           "
//"    <TD align=left><INPUT name=JMIP value=%s size=30><BR></TD></TR>   "
       statis_info.ip,

//"    <TD align=right>Mask</TD>                                         "
//"    <TD align=left><INPUT name=JMSK value=%s size=30><BR></TD></TR>   "
       statis_info.mask,

//"    <TD align=right>Gateway</TD>                                      "
//"    <TD align=left><INPUT name=JGTW value=%s size=30><BR></TD></TR>   "
       statis_info.gateway, 

//"    <TD align=right>WEB Port</TD>                                     "
//"    <TD align=left><INPUT name=WPRT value=10000 size=30><BR></TD></TR>"
      statis_info.webserver_port, 
        
//"    <TD align=right>Primary DNS</TD>                                  "
//"    <TD align=left><INPUT name=PDNS value=%s size=30><BR></TD></TR>   "
       statis_info.DNS1, 

//"    <TD align=right>Secondary DNS</TD>                                "
//"    <TD align=left><INPUT name=SDNS value=%s size=30><BR></TD></TR>   "
//       statis_info.DNS2,

//"    <TD align=right>Server addresses</TD>                             "
//"    <TD align=left><INPUT name=MURL value=%s size=30><BR></TD></TR>   " 
       statis_info.pool_url,
       
//"    <TD align=right>User</TD>                                    "
//"    <TD align=left><INPUT name=USER value=%s size=30><BR></TD></TR>   " 
       statis_info.username,
       
//"    <TD align=right>Password</TD>                                    "
//"    <TD align=left><INPUT name=PASS value=%s size=30><BR></TD></TR>   " 
       statis_info.password,
//"    <TD align=right>WaitTime(ms)</TD>"                                     
//"    <TD align=left><INPUT name=WATM value=%d size=30><BR></TD></TR>   " 
       chip_settings.settings.wait_time,
//"	 <TD align=right>Clock(1~5)</TD>"									
//"	 <TD align=left><INPUT name=CLCK value=%d size=30><BR></TD></TR>"
        (chip_settings.settings.clock+1)  
    );	
	hsocket_send(conn->sock,MAIN_page);
	
  return;
}


void web_server_thread_entry(void* parameter)
{

    TRACE();
	if (httpd_init(0, NULL)) {
		DPRINTF(("Can not init web server httpd !!!\n"));
		return ;
	}
#if 0	
	if (!httpd_register_secure("/", root_service, simple_authenticator)) {

		DPRINTF(("Can not register root service !!!\n"));
		return ;
	}
#else
    if (!httpd_register("/", root_service)) {

		DPRINTF(("Can not register root service !!!\n"));
		return ;
	}

#endif
	if (!httpd_register_default("/error", default_service)) {

		DPRINTF(("Can not register default service"));
	}
	if (httpd_run()) {
		FPRINTF(("can not run httpd !!! \n"));
	}
	TRACE();
	httpd_destroy();
}


void chip_miner_init()
{
int i;
   TRACE();
#ifdef TEST_MEM
    memset(NOT_USE_ARRAY,0,NOT_USE_MEM);
#endif
	memset(&statis_info,0,sizeof(tStatisInfo));
	power_on_tick = rt_tick_get();
	load_settings();
	update_current_pool(statis_info.current_pool, chip_settings.settings.pool_url,
		                statis_info.current_user, chip_settings.settings.username,
		                statis_info.current_pass, chip_settings.settings.password);
	pthread_mutex_init(&network_acc_lock, NULL);
#ifdef HAVE_WORK_QUEUE
	workq_free_mbox= rt_mb_create(WORK_FREE_MBOX_NAME, MAX_WORK_QUEUE_LEN, RT_IPC_FLAG_FIFO);
    workq_mid_mbox= rt_mb_create(WORK_MID_MBOX_NAME, MAX_WORK_QUEUE_LEN, RT_IPC_FLAG_FIFO);
	workq_full_mbox= rt_mb_create(WORK_FULL_MBOX_NAME, MAX_WORK_QUEUE_LEN, RT_IPC_FLAG_FIFO);
    /// fill work free mbox firstly
	for(i=0;i<MAX_WORK_QUEUE_LEN;i++){  
	   rt_mb_send_wait(workq_free_mbox, (rt_uint32_t)&(miner_work[i]), RT_WAITING_FOREVER);
	}
#endif
    chip_set_clock(chip_settings.settings.clock);
    chip_reset2();
}


#endif

#if  0//def TEST_MEM
void tcpclient(const char *url, int port)
{
    char *recv_data=NULL;
    struct hostent *host;
    int sock, bytes_received;
    struct sockaddr_in server_addr;

	
    /* 通过函数入口参数url获得host地址（如果是域名，会做域名解析） */
    host = gethostbyname(url);

    /* 分配用于存放接收数据的缓冲 */
#if 1
	recv_data = rt_malloc(1024);
    if (recv_data == RT_NULL)
    {
        rt_kprintf("No memory\n");
        return;
    }
#endif
    /* 创建一个socket，类型是SOCKET_STREAM，TCP类型 */
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        /* 创建socket失败 */
        rt_kprintf("Socket error\n");

        /* 释放接收缓冲 */
        rt_free(recv_data);
        return;
    }
#if 1
    /* 初始化预连接的服务端地址 */
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr = *((struct in_addr *)host->h_addr);
    rt_memset(&(server_addr.sin_zero), 0, sizeof(server_addr.sin_zero));
	rt_kprintf("target addr is %x : %x\n" , server_addr.sin_addr , server_addr.sin_port);

    /* 连接到服务端 */
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1)
    {
        /* 连接失败 */
        rt_kprintf("Connect error\n");

		lwip_close(sock);
        /*释放接收缓冲 */
        rt_free(recv_data);
        return;
    }
	rt_kprintf("Connect ok\n");
#endif
	lwip_close(sock);
    /* 释放接收缓冲 */
    rt_free(recv_data);
#if 0
    while (1)
    {
		send(sock, send_data, strlen(send_data), 0);
        /* 从sock连接中接收最大BUFSZ - 1字节数据 */
        bytes_received = recv(sock, recv_data, BUFSZ - 1, 0);
        if (bytes_received <= 0)
        {
            /* 接收失败，关闭这个连接 */
            lwip_close(sock);

            /* 释放接收缓冲 */
            rt_free(recv_data);
			rt_kprintf("recv error\n");
            break;
        }
		rt_kprintf("recv ok\n");
        /* 有接收到数据，把末端清零 */
        recv_data[bytes_received] = '\0';

        if (strcmp(recv_data , "q") == 0 || strcmp(recv_data , "Q") == 0)
        {
            /* 如果是首字母是q或Q，关闭这个连接 */
            lwip_close(sock);

            /* 释放接收缓冲 */
            rt_free(recv_data);
            break;
        }
        else
        {
            /* 在控制终端显示收到的数据 */
            rt_kprintf("\nRecieved data = %s " , recv_data);
        }

        /* 发送数据到sock连接 */
        send(sock, send_data, strlen(send_data), 0);
    }
#endif	
    return;
}

#endif


///////////////////// common RT ///////////////////////////
void rt_init_thread_entry(void* parameter)
{
    {
        extern void rt_platform_init(void);
        rt_platform_init();
    }
#ifdef RT_USING_COMPONENTS_INIT
    /* initialization RT-Thread Components */
    rt_components_init();
#endif
    /* Filesystem Initialization */
#if defined(RT_USING_DFS) && defined(RT_USING_DFS_ELMFAT)
    {
        /* mount sd card fat partition 1 as root directory */
        if (dfs_mount("sd0", "/", "elm", 0, 0) == 0)
        {
            rt_kprintf("File System initialized!\n");
        }
        else
        {
            rt_kprintf("File System initialzation failed!\n");
        }
    }
#endif /* RT_USING_DFS && RT_USING_DFS_ELMFAT */
		
#ifdef RT_USING_LWIP
        /* register ethernetif device */
        eth_system_device_init();

        rt_hw_stm32_eth_init();
        /* re-init device driver */
        rt_device_init_all();

	    /// load setting here, because we will use the network info
        chip_miner_init();

        /* init lwip system */
        lwip_sys_init();
#endif 	

 #ifdef RT_USING_FINSH  
        /* init finsh */  
        finsh_system_init();               
        finsh_set_device("uart2");         
 #endif 
#ifdef RT_LWIP_DHCP
//        rt_thread_delay(50);  //100
#endif        
 
/////////////Network  Memory leak test ///////////
#if 0
		 while(1){
		   TRACE_MEM();
		   tcpclient("199.83.50.51", 8332);
		   rt_thread_delay(RT_TICK_PER_SECOND*(1));
		 }
#endif
//////////// Miner Begin ///////////////////////

#ifdef HAVE_IWDG
        IWDG_init();
#endif

#ifndef HAVE_WORK_QUEUE 
        while(1){
			if(chip_detect()){
			   statis_info.hashspeed.starttick = rt_tick_get();
			   miner(MINER_FOREVER);
			}
			else{
	          statis_info.chip_detect_error++;	
			  rt_thread_delay(1);			  
			}
        }
#else        
		sys_thread_new("scanhash", scanhash_thread, NULL, 1024, 10);
        sys_thread_new("submit", submit_thread, NULL, 1024*4, 16);
		while(1){
			if(chip_detect()){
			   statis_info.hashspeed.starttick = rt_tick_get();
			   miner(MINER_FOREVER);
			}
			else{
			  statis_info.chip_detect_error++;	
			  rt_thread_delay(1);			  
			}
		}
#endif
}


int rt_application_init(void)
{
    rt_thread_t init_thread;
#ifdef HAVE_WEB_SRV
    rt_thread_t webserver_thread;
#endif	
    FPRINTF(("\n\n********* MINER SW Version: %s *********\n",MINER_SW_VERSION));
    FPRINTF(("\n********* MINER SW Build Time: %s %s *********\n\n",__DATE__,__TIME__));


#ifdef HAVE_WORK_QUEUE
    init_thread = rt_thread_create("miner",
                                   rt_init_thread_entry, RT_NULL,
                                   1024*7, 16, 20);
#else
    init_thread = rt_thread_create("miner",
                                   rt_init_thread_entry, RT_NULL,
                                   1024*7, 12, 20);
#endif

#ifdef HAVE_WEB_SRV
    webserver_thread = rt_thread_create("websrv",
                                   web_server_thread_entry, RT_NULL,
                                   1024*4, 16, 20);
#endif

    if (init_thread != RT_NULL)
    {
        rt_thread_startup(init_thread);
    }
    if (webserver_thread != RT_NULL)
    {
        rt_thread_startup(webserver_thread);
    }
    return 0;
}

/*@}*/
