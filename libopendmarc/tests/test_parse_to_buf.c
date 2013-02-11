#include "../opendmarc_internal.h"
#ifndef OPENDMARC_POLICY_C
# define OPENDMARC_POLICY_C
#endif /* ! OPENDMARC_POLICY_C */
#include "../dmarc.h"

int
main(int argc, char **argv)
{
	char * record = "v=DMARC1; p=none; rf=afrf; fo=1:s rua=mailto:dmarc-a@abuse.net; ruf=mailto:dmarc-f@abuse.net";
	int	pass, fails, count;
	DMARC_POLICY_T *pctx;
	OPENDMARC_STATUS_T status;
	char	small_buf[10];
	char	big_buf[BUFSIZ * 4];
	
	pass = fails = count = 0;
	pctx = opendmarc_policy_connect_init("1.2.3.4", 0);
	if (pctx == NULL)
	{
		(void) fprintf(stderr, "opendmarc_policy_connect_init: %s\n", strerror(errno));
		return 1;
	}
	status = opendmarc_policy_parse_dmarc(pctx, "abuse.net", record);
	if (status == DMARC_PARSE_OKAY)
	{
		pass += 1;
	}
	else
	{
		printf("\tDMARC Policy Parse: \"%s\" FAIL\n", record);
		fails += 1;
	}
	if (opendmarc_policy_to_buf(NULL, NULL, 0) == EINVAL)
	{
		pass += 1;
	}
	else
	{
		printf("\tDMARC Policy Parse To NULL Buffer: FAIL\n");
		fails += 1;
	}
	if (opendmarc_policy_to_buf(pctx, small_buf, sizeof small_buf) == E2BIG)
	{
		pass += 1;
	}
	else
	{
		printf("\tDMARC Policy Parse To Small Buffer: FAIL\n");
		fails += 1;
	}
	if (opendmarc_policy_to_buf(pctx, big_buf, sizeof big_buf) == 0)
	{
		pass += 1;
	}
	else
	{
		printf("\tDMARC Policy Parse To Big Buffer: FAIL\n");
		fails += 1;
	}

	pctx = opendmarc_policy_connect_shutdown(pctx);
	printf("DMARC Policy Parse To Buffer: pass=%d, fail=%d\n", pass, fails);
	return fails;
}
