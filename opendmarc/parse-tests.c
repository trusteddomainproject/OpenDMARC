#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "parse.h"

int
main() {
	u_char **users, **domains;

	int status = dmarcf_mail_parse_multi((unsigned char*)strdup("From: \"A, B\" <c@d.e>, abc@def.geh"), &users, &domains);
	if (status) return status;
	status = strcmp((char*)domains[0], "d.e") + strcmp((char*)domains[1], "def.geh") + strcmp((char*)users[0], "c") + strcmp((char*)users[1], "abc") + (users[2] != NULL) + (domains[2] != NULL);
	if (status) return status;

	status = dmarcf_mail_parse_multi((unsigned char*)strdup("From: abc@def.geh, \"A, B\" <c@d.e>"), &users, &domains);
	if (status) return status;
	status = strcmp((char*)domains[0], "def.geh") + strcmp((char*)domains[1], "d.e") + strcmp((char*)users[0], "abc") + strcmp((char*)users[1], "c") + (users[2] != NULL) + (domains[2] != NULL);
	if (status) return status;

	status = dmarcf_mail_parse_multi((unsigned char*)strdup("From: \"A, B\" <c@d.e>"), &users, &domains);
	if (status) return status;
	status = strcmp((char*)domains[0], "d.e") + strcmp((char*)users[0], "c") + strcmp((char*)users[0], "c") + (users[1] != NULL) + (domains[1] != NULL);
	if (status) return status;

	return status;
}
