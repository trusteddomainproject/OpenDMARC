/***************************************************
** $Id: opendmarc_hash.c,v 1.2 2010/12/03 23:06:48 bcx Exp $
** Code contributed by Bryan Costales 
****************************************************/

#include "opendmarc_internal.h"

/********************************************************************
** OPENDMARC_HASH_SET_CALLBACK -- Set the callback for freeing the data
**
**	Parameters:
**		ctx		-- Hash table context
**		callback	-- address of freeing function
**	Returns:
**		void		-- nothing
**	Side Effects:
**		None.
**	Notes:
**		The free function must be declared as:
**			void *funct(void *arg);
*/
void
opendmarc_hash_set_callback(OPENDMARC_HASH_CTX *hctx, void (*callback)(void *))
{
	if (hctx == NULL)
		return;
	hctx->freefunct = callback;
	return;
}

/********************************************************************
** OPENDMARC_HASH_STRING -- Convert a string into its hash value.
**
**	Parameters:
**		string	-- string to hash
**		limit	-- size of the hash table
**	Returns:
**		unsigned integer of hash value
**		if str == NULL hashes ""
**	Side Effects:
**		None.
**	Notes:
**		Generally for internal use only.
*/
static size_t
opendmarc_hash_string(char *str, size_t limit)
{
	size_t  hash;
	size_t  highorder;
	int 	c;
	char *	s;

	if (str == NULL)
		s = "";
	else
		s = str;

	/*
	 * Changed to a more modern CRC hash.
	 */
	hash = 5381;
	highorder = hash & 0xf8000000;
	do
	{
		c = (int)(*s);
		if (c == 0)
			break;
		hash = hash << 5;
		hash = hash ^ (highorder >> 27);
		hash = hash ^ c;
		highorder = hash & 0xf8000000;
		++s;
	} while (c != 0);
	return hash % limit;
}

/********************************************************************
** OPENDMARC_HASH_INIT -- Allocate and receive a context pointer
**
**	Parameters:
**		tablesize	-- size of the internal hash table
**	Returns:
**		Address of type OPENDMARC_HASH_CTX *
**		NULL on error and sets errno.
**	Side Effects:
**		Allocates memory.
**		Initializes tablesize number of mutexes
**	Notes:
**		If tablesize is zero, defaults to (2048)
**		Tablesize should be a power of two, if not, it
**		is silently adjusted to a power of two.
**	If you want a callback to free your data, call
**	opendmarc_hash_set_callback() immediately after this call.
*/
OPENDMARC_HASH_CTX *
opendmarc_hash_init(size_t tablesize)
{
	size_t i;
	unsigned int p2;
	OPENDMARC_HASH_CTX *hctx;

	hctx = malloc(sizeof(OPENDMARC_HASH_CTX));
	if (hctx == NULL) 
	{
		if (errno == 0)
			errno = ENOMEM;
		return NULL;
	}

	if (tablesize == 0)
		hctx->tablesize = OPENDMARC_DEFAULT_HASH_TABLESIZE;
	else
		hctx->tablesize = tablesize;

	hctx->freefunct = NULL;

	/* 
	 * If buckets is too small, make it min sized. 
	 */
	if (hctx->tablesize < OPENDMARC_MIN_SHELVES)
		hctx->tablesize = OPENDMARC_MIN_SHELVES;

	/* 
	 * If it's too large, cap it. 
	 */
	if (hctx->tablesize > OPENDMARC_MAX_SHELVES)
		hctx->tablesize = OPENDMARC_MAX_SHELVES;

	/* 
	 * If it's is not a power of two in size, round up. 
	 */
	if ((hctx->tablesize & (hctx->tablesize - 1)) != 0) 
	{
		for (p2 = 0; hctx->tablesize != 0; p2++)
			hctx->tablesize >>= 1;

		if (p2 <= OPENDMARC_MAX_SHELVES_LG2)
			hctx->tablesize = OPENDMARC_DEFAULT_HASH_TABLESIZE;
		else
			hctx->tablesize = 1 << p2;
	}

	hctx->table = calloc(hctx->tablesize, sizeof(OPENDMARC_HASH_SHELF));
	if (hctx->table == NULL) 
	{
		if (errno == 0)
			errno = ENOMEM;
		(void) free(hctx);
		return NULL;
	}
	for (i = 0; i < hctx->tablesize; i++)
	{
# if HAVE_PTHREAD_H || HAVE_PTHREAD
		(void) pthread_mutex_init(&(hctx->table[i].mutex), NULL);
# endif
		hctx->table[i].bucket = NULL;
	}

	return hctx;
}

/********************************************************************
** OPENDMARC_HASH_FREEBUCKET -- Free a bucket.
**
**	Parameters:
**		b	-- pointer to a bucket
**	Returns:
**		NULL always.
**		errno is non-zero on error
**	Side Effects:
**		Frees memory.
**	Notes:
**		Intended for internal use only.
**		Does not unlink b from linked list.
**		NO NOT mutex lock here.
*/
static OPENDMARC_HASH_BUCKET *
ghash_freebucket(OPENDMARC_HASH_CTX *hctx, OPENDMARC_HASH_BUCKET *b)
{
	if (b == NULL)
		return NULL;
	if (b->key != NULL)
	{
		(void) free(b->key);
		b->key = NULL;
	}
	if (b->data != NULL)
	{
		if (hctx != NULL && hctx->freefunct != NULL)
		{
			(hctx->freefunct)(b->data);
			b->data = NULL;
		}
		else
		{
			(void) free(b->data);
			b->data = NULL;
		}
	}
	(void) free(b);
	b = NULL;
	return NULL;
}

/********************************************************************
** OPENDMARC_HASH_SHUTDOWN -- Give up and free a hash table.
**
**	Parameters:
**		hctx	-- A hash context from ghash_init()
**	Returns:
**		NULL always.
**		errno is non-zero on error
**	Side Effects:
**		Frees memory.
**	Notes:
**		None
*/
OPENDMARC_HASH_CTX *
opendmarc_hash_shutdown(OPENDMARC_HASH_CTX *hctx)
{
	int i;
	OPENDMARC_HASH_BUCKET *t, *b;

	if (hctx == NULL)
	{
		errno = EINVAL;
		return NULL;
	}

	if (hctx->table == NULL || hctx->tablesize == 0)
	{
		errno = EINVAL;
		return NULL;
	}

	for (i = 0; i < hctx->tablesize; i++) 
	{
# if HAVE_PTHREAD_H || HAVE_PTHREAD
		(void) pthread_mutex_destroy(&(hctx->table[i].mutex));
# endif
		if ((hctx->table[i].bucket) == NULL)
			continue;
		
		b = hctx->table[i].bucket;
		do
		{
			t = b->next;
			b = ghash_freebucket(hctx, b);
			b = t;

		} while (b != NULL);
	}
	(void) free(hctx->table);
	hctx->table = NULL;
	(void) free(hctx);
	hctx = NULL;
	errno = 0;
	return NULL;
}

/********************************************************************
** OPENDMARC_HASH_LOOKUP -- Look up a key and get its data
**
**	Parameters:
**		hctx	-- A hash context from ghash_init()
**		string	-- The string to lookup
**		data	-- Data for update only (NULL for plain lookup)
**		datalen -- Size in bytes of the data blob
**	Returns:
**		Address of data on success (search or update)
**		NULL and sets non-zero errno on error
**	Side Effects:
**		Allocates memory on update.
**	Notes:
**		If data is NULL, just lookup string and return data if found.
**		If data not NULL, insert if string not found, but if found,
**			replace the old data with the new.
*/
void *
opendmarc_hash_lookup(OPENDMARC_HASH_CTX *hctx, char *string, void *data, size_t datalen)
{
	uint32_t hashval;
	OPENDMARC_HASH_BUCKET *b, *n;

	if (data != NULL && datalen == 0)
	{
		errno = EINVAL;
		return NULL;
	}

	if (string == NULL)
	{
		errno = EINVAL;
		return NULL;
	}

	if (hctx == NULL || hctx->table == NULL || hctx->tablesize == 0)
	{
		errno = EINVAL;
		return NULL;
	}


	hashval = opendmarc_hash_string(string, hctx->tablesize);

# if HAVE_PTHREAD_H || HAVE_PTHREAD
	(void) pthread_mutex_lock(&(hctx->table[hashval].mutex));
# endif
	 b = hctx->table[hashval].bucket;
	 if (b != NULL)
	 {
		do
		{
			if (b->key != NULL && strcasecmp(string, b->key) == 0)
			{
				if (data != NULL)
				{
					if (hctx->freefunct != NULL)
						(hctx->freefunct)(b->data);
					else
						(void) free(b->data);

					b->data = calloc(1, datalen);
					if (b->data == NULL)
					{
# if HAVE_PTHREAD_H || HAVE_PTHREAD
						(void) pthread_mutex_unlock(&(hctx->table[hashval].mutex));
# endif
						errno = ENOMEM;
						return NULL;
					}
					memcpy(b->data, data, datalen);
					(void) time(&(b->timestamp));
				}
# if HAVE_PTHREAD_H || HAVE_PTHREAD
				(void) pthread_mutex_unlock(&(hctx->table[hashval].mutex));
# endif
				errno = 0;
				return b->data;
			}
			b = b->next;
		} while (b != NULL);
	 }
	 if (data == NULL)
	 {
# if HAVE_PTHREAD_H || HAVE_PTHREAD
		(void) pthread_mutex_unlock(&(hctx->table[hashval].mutex));
# endif
	 	errno = 0;
	 	return NULL;
	 }

	 /*
	  * Not found, so we inert it.
	  */
	 n = calloc(1, sizeof(OPENDMARC_HASH_BUCKET));
	 if (n == NULL)
	 {
# if HAVE_PTHREAD_H || HAVE_PTHREAD
		(void) pthread_mutex_unlock(&(hctx->table[hashval].mutex));
# endif
		errno = ENOMEM;
		return NULL;
	 }
	 n->next = n->previous = NULL;
	 n->key = strdup(string);
	 if (n->key == NULL)
	 {
		(void) free(n);
		n = NULL;
# if HAVE_PTHREAD_H || HAVE_PTHREAD
		(void) pthread_mutex_unlock(&(hctx->table[hashval].mutex));
# endif
		errno = ENOMEM;
		return NULL;
	 }
	 n->data = calloc(1, datalen);
	 if (n->data == NULL)
	 {
		(void) free(n->key);
		n->key = NULL;
		(void) free(n);
		n = NULL;
# if HAVE_PTHREAD_H || HAVE_PTHREAD
		(void) pthread_mutex_unlock(&(hctx->table[hashval].mutex));
# endif
		errno = ENOMEM;
		return NULL;
	 }
	 memcpy(n->data, data, datalen);
	 (void) time(&(n->timestamp));

	 b = hctx->table[hashval].bucket;
	 if (b == NULL)
	 {
	 	hctx->table[hashval].bucket = n;
# if HAVE_PTHREAD_H || HAVE_PTHREAD
		(void) pthread_mutex_unlock(&(hctx->table[hashval].mutex));
# endif
		errno = 0;
	 	return n->data;
	 }
	 while (b->next != NULL)
	 	b = b->next;
	 b->next = n;
	 n->previous = b;
# if HAVE_PTHREAD_H || HAVE_PTHREAD
	(void) pthread_mutex_unlock(&(hctx->table[hashval].mutex));
# endif

	errno = 0;
	return n->data;
}
 
/********************************************************************
** OPENDMARC_HASH_DROP -- Remove a key/data from the hash table
**
**	Parameters:
**		hctx	-- A hash context from ghash_init()
**		string	-- The string to remove
**	Returns:
**		Zero on success
**		Returns non-zero errno on error
**	Side Effects:
**		Frees memory
**	Notes:
**		If string not in the table, returns zero anyway.
*/
int
opendmarc_hash_drop(OPENDMARC_HASH_CTX *hctx, char *string)
{
	uint32_t hashval;
	OPENDMARC_HASH_BUCKET *b;

	if (string == NULL)
	{
		return errno = EINVAL;
	}

	if (hctx == NULL || hctx->table == NULL || hctx->tablesize == 0)
	{
		return errno = EINVAL;
	}

	hashval = opendmarc_hash_string(string, hctx->tablesize);

# if HAVE_PTHREAD_H || HAVE_PTHREAD
	(void) pthread_mutex_lock(&(hctx->table[hashval].mutex));
# endif
	 b = hctx->table[hashval].bucket;
	 if (b != NULL)
	 {
		do
		{
			if (b->key != NULL && strcmp(string, b->key) == 0)
			{
				if (b->previous != NULL)
					b->previous->next = b->next;
				if (b->next != NULL)
					b->next->previous = b->previous;
				b = ghash_freebucket(hctx, b);
# if HAVE_PTHREAD_H || HAVE_PTHREAD
				(void) pthread_mutex_unlock(&(hctx->table[hashval].mutex));
# endif
				return errno = 0;
			}
			b = b->next;
		} while (b != NULL);
	 }
# if HAVE_PTHREAD_H || HAVE_PTHREAD
	(void) pthread_mutex_unlock(&(hctx->table[hashval].mutex));
# endif
	return errno = 0;
}
 
/********************************************************************
** OPENDMARC_HASH_EXPIRE -- Remove old data from the hash table
**
**	Parameters:
**		hctx	-- A hash context from ghash_init()
**		age	-- Maximum age to retain
**	Returns:
**		Zero on success
**		Returns non-zero errno on error
**	Side Effects:
**		Frees memory
**	Notes:
**		The age is in seconds. All entries older than
**		age are removed from the table.
*/
int
opendmarc_hash_expire(OPENDMARC_HASH_CTX *hctx, time_t age)
{
	OPENDMARC_HASH_BUCKET *b, *t;
	time_t 		now;
	int		i;

	if (age == 0)
	{
		return errno = EINVAL;
	}

	if (hctx == NULL || hctx->table == NULL || hctx->tablesize == 0)
	{
		return errno = EINVAL;
	}

	(void) time(&now);
	for (i = 0; i < hctx->tablesize; i++)
	{

# if HAVE_PTHREAD_H || HAVE_PTHREAD
		(void) pthread_mutex_lock(&(hctx->table[i].mutex));
# endif
		 b = hctx->table[i].bucket;
		 if (b != NULL)
		 {
			do
			{
				t = b->next;
				if ((now - b->timestamp) > age)
				{
					if (b->previous != NULL)
						b->previous->next = b->next;
					if (b->next != NULL)
						b->next->previous = b->previous;
					if (b == hctx->table[i].bucket)
						hctx->table[i].bucket = t;
					b = ghash_freebucket(hctx, b);
				}
				b = t;
			} while (b != NULL);
		 }
# if HAVE_PTHREAD_H || HAVE_PTHREAD
		(void) pthread_mutex_unlock(&(hctx->table[i].mutex));
# endif
	}
	return errno = 0;
}
 
