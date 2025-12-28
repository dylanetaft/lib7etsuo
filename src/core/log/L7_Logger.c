#include <lib7etsuo/core/log/L7_Logger.h>
#include <string.h> 
#include <pthread.h>
#include <stdio.h>
#include <time.h>

static pthread_mutex_t _log_mutex = PTHREAD_MUTEX_INITIALIZER;
static L7LogCallback _log_callback = NULL;
static void *_log_callback_userdata = NULL;


/* stderr for ERROR/FATAL, stdout otherwise */
static FILE *
_L7_Log_get_stream (L7LogLevel level)
{
  return level >= L7_LOG_ERROR ? stderr : stdout;
}

  static char *
  _L7_Log_format_timestamp (char *outbuf, size_t outlen)
  {
    
    time_t raw;
    struct tm tm_buf;
    int time_ok = 0;

    raw = time (NULL);

  #ifdef _WIN32
    time_ok = (localtime_s (&tm_buf, &raw) == 0);
  #else
    time_ok = (localtime_r (&raw, &tm_buf) != NULL);
  #endif

    if (!time_ok
        || strftime (outbuf, outlen, L7_LOG_TIMESTAMP_FORMAT, &tm_buf) == 0)
      {
        
        //will copy: null terminator  
        if (outlen >=sizeof(L7_LOG_DEFAULT_TIMESTAMP))
            memcpy (outbuf, L7_LOG_DEFAULT_TIMESTAMP, sizeof(L7_LOG_DEFAULT_TIMESTAMP)); 
        else
            memset(outbuf,0,outlen);
      }

    return outbuf;
  }



/* Default logging callback */
static void
_default_logger (void *userdata, L7LogLevel level, const char *component,
                const char *message)
{
  char ts[L7_LOG_TIMESTAMP_BUFSIZE];

  (void)userdata;
  pthread_mutex_lock (&_log_mutex); //fprintf is not technically threadsafe
  fprintf (_L7_Log_get_stream (level), "%s [%s] %s: %s\n",
           _L7_Log_format_timestamp (ts, sizeof (ts)),
           L7_Log_getlevelname(level), component ? component : "(unknown)",
           message ? message : "(null)");
  pthread_mutex_unlock (&_log_mutex);
}


const char *L7_Log_getlevelname (L7LogLevel level) {
    if (level < L7_LOG_TRACE || level > L7_LOG_FATAL) {
        return "UNKNOWN";
    }
    return L7LogLevelNames[level];

}
void
L7_Log_setcallback (L7LogCallback callback, void *userdata)
{
  pthread_mutex_lock (&_log_mutex);
  _log_callback = callback;
  _log_callback_userdata = userdata;
  pthread_mutex_unlock (&_log_mutex);
}

L7LogCallback
L7_Log_getcallback (void **userdata)
{
  L7LogCallback callback;
  pthread_mutex_lock (&_log_mutex);
  callback = _log_callback ? _log_callback : _default_logger;
  if (userdata)
    *userdata = _log_callback_userdata;
  pthread_mutex_unlock (&_log_mutex);

  return callback;
}


void L7_Log_emit(L7LogLevel level, const char *component,
                 const char *message) {
  //TODO: Reimplement should log, this is often done at define level
  L7LogCallback callback = L7_Log_getcallback(NULL);
  callback(_log_callback_userdata, level, component, message);



}

void L7_Log_apply_truncation(char *b_in, size_t b_in_size, char *b_out,                                                  
                              size_t b_out_size) {                                                                       
                                                                                                                         
   if (b_in == NULL || b_out == NULL) {                                                                                  
      // Null input or output buffer                                                                                     
     if (b_out != NULL && b_out_size > 0) {                                                                              
        b_out[0] = '\0';                                                                                                 
      }                                                                                                                  
      return;                                                                                                            
    }                                                                                                                    
    if (b_in_size == 0 || b_out_size == 0) {                                                                             
      // Invalid input or output buffer size                                                                             
      if (b_out_size > 0) {                                                                                              
        b_out[0] = '\0';                                                                                                 
      }                                                                                                                  
      return;                                                                                                            
    }                                                                                                                    
    
    
    if (b_in_size <= b_out_size) {                                                                                       
      // No truncation needed                                                                                            
      memmove(b_out, b_in, b_in_size);                           
      b_out[b_in_size] = '\0';                      
      return;
    } 
    
  
    if (b_out_size < sizeof(L7_LOG_TRUNCATION_MARKER)) {
      // Output buffer too small to hold truncation marker
      b_out[0] = '\0';
      return;
    }
    

    size_t copy_len = b_out_size - L7_LOG_TRUNCATION_MARKER_LEN - 1;
    memmove(b_out, b_in, copy_len);
    memmove(b_out + copy_len,
           L7_LOG_TRUNCATION_MARKER,
           L7_LOG_TRUNCATION_MARKER_LEN);
    b_out[b_out_size - 1] = '\0';
}
