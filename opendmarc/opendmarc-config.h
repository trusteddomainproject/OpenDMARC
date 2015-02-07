/*
**  Copyright (c) 2012-2015, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _OPENDMARC_CONFIG_H_
#define _OPENDMARC_CONFIG_H_

/* macros */
#ifndef FALSE
# define FALSE	0
#endif /* ! FALSE */
#ifndef TRUE
# define TRUE	1
#endif /* ! TRUE */

/* config definition */
struct configdef dmarcf_config[] =
{
	{ "AuthservID",			CONFIG_TYPE_STRING,	FALSE },
	{ "AuthservIDWithJobID",	CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "AutoRestart",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "AutoRestartCount",		CONFIG_TYPE_INTEGER,	FALSE },
	{ "AutoRestartRate",		CONFIG_TYPE_STRING,	FALSE },
	{ "Background",			CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "BaseDirectory",		CONFIG_TYPE_STRING,	FALSE },
	{ "ChangeRootDirectory",	CONFIG_TYPE_STRING,	FALSE },
	{ "CopyFailuresTo",		CONFIG_TYPE_STRING,	FALSE },
	{ "DNSTimeout",			CONFIG_TYPE_INTEGER,	FALSE },
	{ "EnableCoredumps",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "FailureReports",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "FailureReportsBcc",		CONFIG_TYPE_STRING,	FALSE },
	{ "FailureReportsOnNone",	CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "FailureReportsSentBy",	CONFIG_TYPE_STRING,	FALSE },
	{ "HistoryFile",		CONFIG_TYPE_STRING,	FALSE },
	{ "IgnoreAuthenticatedClients",	CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "IgnoreHosts",		CONFIG_TYPE_STRING,	FALSE },
	{ "IgnoreMailFrom",		CONFIG_TYPE_STRING,	FALSE },
	{ "MilterDebug",		CONFIG_TYPE_INTEGER,	FALSE },
	{ "PidFile",			CONFIG_TYPE_STRING,	FALSE },
	{ "PublicSuffixList",		CONFIG_TYPE_STRING,	FALSE },
	{ "RecordAllMessages",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "RequiredHeaders",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "RejectFailures",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "ReportCommand",		CONFIG_TYPE_STRING,	FALSE },
	{ "Socket",			CONFIG_TYPE_STRING,	FALSE },
	{ "SoftwareHeader",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "SPFIgnoreResults",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "SPFSelfValidate",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "Syslog",			CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "SyslogFacility",		CONFIG_TYPE_STRING,	FALSE },
	{ "TestDNSData",		CONFIG_TYPE_STRING,	FALSE },
	{ "TrustedAuthservIDs",		CONFIG_TYPE_STRING,	FALSE },
	{ "UMask",			CONFIG_TYPE_INTEGER,	FALSE },
	{ "Userid",			CONFIG_TYPE_STRING,	FALSE },
	{ NULL,				(u_int) -1,		FALSE }
};

#endif /* _OPENDMARC_CONFIG_H_ */
