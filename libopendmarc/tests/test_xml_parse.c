#include "../opendmarc_internal.h"
#include "../dmarc.h"

typedef struct {
	char *fname;
	int   outcome;
} TEST_T;

int
main(int argc, char **argv)
{
	TEST_T *xmlp;
	TEST_T xml_files[] = {
		/* 1 */ {"testfiles/nosuchfile.xml", ENOENT},
		/* 2 */ {"testfiles/good.com!example.com!1337270400!1337356799.xml", 0},
		/* 3 */ {"testfiles/bad.com!example.com!1337140800!1337227200.xml", 0},
			{NULL, 0},
	};
	u_char **	ary;
	char *	srcdir;
	char 	ebuf[256];
	int	pass, fails, count;
	
	srcdir = getenv("srcdir");
	if (srcdir != NULL)
	{
		if (chdir(srcdir) != 0)
		{
			perror(srcdir);
			return 1;
		}
	}

	pass = fails = count = 0;
	for (xmlp = xml_files; xmlp != NULL && xmlp->fname != NULL; ++xmlp)
	{
		count += 1;
		ary = opendmarc_xml_parse(xmlp->fname, ebuf, sizeof ebuf);
		if (ary == NULL && errno != xmlp->outcome)
		{
			(void) printf("\t%s\n%s", xmlp->fname, ebuf);
			++fails;
			continue;
		}
		ary = opendmarc_util_clearargv(ary);
		++pass;
	}
	printf("Parse XML File test: pass=%d, fail=%d\n", pass, fails);
	return fails;
}
