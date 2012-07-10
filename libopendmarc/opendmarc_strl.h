/*
**  Copyright (c) 2009, 2012, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _DMARC_STRL_H_
#define _DMARC_STRL_H_

/* system includes */
#include <sys/types.h>

/* OpenDMARC includes */
#include "build-config.h"

/* mappings */
#if HAVE_STRLCAT == 0
# define strlcat(x,y,z)	dmarc_strlcat((x), (y), (z))
#endif /* HAVE_STRLCAT == 0 */

#if HAVE_STRLCPY == 0
# define strlcpy(x,y,z)	dmarc_strlcpy((x), (y), (z))
#endif /* HAVE_STRLCPY == 0 */

#endif /* _DMARC_STRL_H_ */
