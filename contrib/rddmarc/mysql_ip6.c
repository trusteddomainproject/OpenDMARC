/*
 * $Id: mysql_ip6.c,v 1.1 2010/01/25 17:29:14 johnl Exp $
 * MySQL library functions for ipv6 conversion
 *
 * v6 internal format is 16 byte string or binary
 *
 * string = inet_6top(bin16)   turn binary address into string rep
 * bin16 = inet_pto6(string)   turn string rep of address into binary
 *
 * cc -I/usr/local/include/mysql -fPIC -shared -o mysql_ip6.so mysql_ip6.c
 */

#include <my_global.h>
#include <my_sys.h>
#include <string.h>
#include <mysql.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

my_bool inet_6top_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *inet_6top(UDF_INIT *initid, UDF_ARGS *args, char *result,
	       unsigned long *length, char *is_null, char *error);

my_bool inet_pto6_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *inet_pto6(UDF_INIT *initid, UDF_ARGS *args, char *result,
	       unsigned long *length, char *is_null, char *error);

/*
 * INET_6TOP( binary 16 ) -> string
 */

my_bool
inet_6top_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
  if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT) {
    strcpy(message,"INET_6TOP() takes one 16-byte argument");
    return 1;
  }
  initid->max_length = 40;	/* max length of v6 string address */
  return 0;
}

char *
inet_6top(UDF_INIT *initid, UDF_ARGS *args, char *result,
	       unsigned long *length, char *is_null, char *error)
{
  char *p;

  if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT
      || (args->args[0] && args->lengths[0] != 16) ) {
    *error = 1;
    return NULL;
  }

  if(!args->args[0]) {		/* NULL argument */
    *is_null = 1;
    return NULL;
  }

  p = (char *)inet_ntop(AF_INET6, args->args[0], result, 255); /* result buffer is at least that long */
  if(!p) {
    *error = 1;
    return NULL;
  }

  *length = strlen(result);
  return result;
}

/*
 * INET_PTO6( string ) -> binary 16
 */
my_bool
inet_pto6_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
  if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT)
  {
    strcpy(message,"INET_PTO6() takes one string argument");
    return 1;
  }
  initid->max_length = 16;	/* length of v6 address */
  return 0;
}

char *
inet_pto6(UDF_INIT *initid, UDF_ARGS *args, char *result,
	       unsigned long *length, char *is_null, char *error)
{
  int i;
  char buf[256];


  if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT) {
    *error = 1;
    return NULL;
  }

  if(!args->args[0]) {		/* NULL argument */
    *is_null = 1;
    return NULL;
  }
  if(args->lengths[0] >= sizeof(buf)) { /* ridiculous argument */
    *error = 1;
    return NULL;
  }

  /* need nul terminated string */
  strncpy(buf, args->args[0], args->lengths[0]);
  buf[args->lengths[0]] = 0;

  i = inet_pton(AF_INET6, buf, result);

  if(i != 1) {			/* bad input */
    *is_null = 1;
    return NULL;
  }

  *length = 16;
  return result;
}
