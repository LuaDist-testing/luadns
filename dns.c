/*
 ** LuaDNS
 ** Copyright DarkGod 2007
 **
 */

#include <netinet/in.h>
#include <resolv.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#define DNS_MAXNAME 1024
#define DN_EXPAND_ARG4_TYPE char *


enum { RESET_NEXT, RESET_ANSWERS, RESET_AUTHORITY, RESET_ADDITIONAL };

typedef struct {
	unsigned char  name[DNS_MAXNAME];      /* domain name */
	int     type;                   /* record type */
	int     size;                   /* size of data */
	unsigned char *data;                   /* pointer to data */
} dns_record;

typedef struct {
	int     rrcount;                /* count of RRs in the answer */
	unsigned char *aptr;                   /* pointer in the answer while scanning */
	dns_record srr;                 /* data from current record in scan */
} dns_scan;

static dns_record *dns_next_rr(int anslen, unsigned char *ans, dns_scan *dnss, int reset)
{
	HEADER *h = (HEADER *)ans;
	int namelen;

	/* Reset the saved data when requested to, and skip to the first required RR */

	if (reset != RESET_NEXT)
	{
		dnss->rrcount = ntohs(h->qdcount);
		dnss->aptr = ans + sizeof(HEADER);

		/* Skip over questions; failure to expand the name just gives up */

		while (dnss->rrcount-- > 0)
		{
			namelen = dn_expand(ans, ans + anslen,
				dnss->aptr, (DN_EXPAND_ARG4_TYPE) &(dnss->srr.name), DNS_MAXNAME);
			if (namelen < 0) { dnss->rrcount = 0; return NULL; }
			dnss->aptr += namelen + 4;    /* skip name & type & class */
		}

		/* Get the number of answer records. */

		dnss->rrcount = ntohs(h->ancount);

		/* Skip over answers if we want to look at the authority section. Also skip
		 the NS records (i.e. authority section) if wanting to look at the additional
		 records. */

		if (reset == RESET_ADDITIONAL) dnss->rrcount += ntohs(h->nscount);

		if (reset == RESET_AUTHORITY || reset == RESET_ADDITIONAL)
		{
			while (dnss->rrcount-- > 0)
			{
				namelen = dn_expand(ans, ans + anslen,
					dnss->aptr, (DN_EXPAND_ARG4_TYPE) &(dnss->srr.name), DNS_MAXNAME);
				if (namelen < 0) { dnss->rrcount = 0; return NULL; }
				dnss->aptr += namelen + 8;            /* skip name, type, class & TTL */
				GETSHORT(dnss->srr.size, dnss->aptr); /* size of data portion */
				dnss->aptr += dnss->srr.size;         /* skip over it */
			}
			dnss->rrcount = (reset == RESET_AUTHORITY)
			? ntohs(h->nscount) : ntohs(h->arcount);
		}
	}

	/* The variable dnss->aptr is now pointing at the next RR, and dnss->rrcount
	 contains the number of RR records left. */

	if (dnss->rrcount-- <= 0) return NULL;

	/* If expanding the RR domain name fails, behave as if no more records
	 (something safe). */

	namelen = dn_expand(ans, ans + anslen, dnss->aptr,
		(DN_EXPAND_ARG4_TYPE) &(dnss->srr.name), DNS_MAXNAME);
	if (namelen < 0) { dnss->rrcount = 0; return NULL; }

	/* Move the pointer past the name and fill in the rest of the data structure
	 from the following bytes. */

	dnss->aptr += namelen;
	GETSHORT(dnss->srr.type, dnss->aptr); /* Record type */
	dnss->aptr += 6;                      /* Don't want class or TTL */
	GETSHORT(dnss->srr.size, dnss->aptr); /* Size of data portion */
	dnss->srr.data = dnss->aptr;          /* The record's data follows */
	dnss->aptr += dnss->srr.size;         /* Advance to next RR */

	/* Return a pointer to the dns_record structure within the dns_answer. This is
	 for convenience so that the scans can use nice-looking for loops. */

	return &(dnss->srr);
}

int MX(lua_State *L)
{
	const char *host = luaL_checkstring (L, 1);
	unsigned char buf[1024];
	int len, nb = 1;
	HEADER *reply_header;
	dns_scan dnss;
	dns_record *rr;

	if (res_init() == -1) return 0;
	if ((len = res_search(host, C_IN, T_MX, buf, 1024)) == -1) return 0;
	reply_header = (HEADER *) buf;

	lua_newtable(L);
	for (rr = dns_next_rr(len, buf, &dnss, RESET_ANSWERS); rr != NULL; rr = dns_next_rr(len, buf, &dnss, RESET_NEXT))
	{
		if (rr->type == T_MX)
		{
			char data[1024];
			unsigned char *s;
			int prio;
			s = rr->data;
			GETSHORT(prio, s); /* Size of data portion */

			dn_expand(buf, buf + len, s, data, 1024);

			lua_pushnumber(L, nb++);
			lua_newtable(L);
			lua_pushstring(L, "priority");
			lua_pushnumber(L, prio);
			lua_settable(L, -3);
			lua_pushstring(L, "host");
			lua_pushstring(L, data);
			lua_settable(L, -3);
			lua_settable(L, -3);
		}
	}

	return 1;
}

/*
** Assumes the table is on top of the stack.
*/
static void set_info (lua_State *L)
{
	lua_pushliteral (L, "_COPYRIGHT");
	lua_pushliteral (L, "Copyright (C) 2007 DarkGod");
	lua_settable (L, -3);
	lua_pushliteral (L, "_DESCRIPTION");
	lua_pushliteral (L, "LuaDNS allows lua applications to call specific DNS informations");
	lua_settable (L, -3);
	lua_pushliteral (L, "_VERSION");
	lua_pushliteral (L, "LuaDNS 1.0.0");
	lua_settable (L, -3);
}

static const struct luaL_reg dnslib[] =
{
	{"MX", MX},
	{NULL, NULL},
};

int luaopen_dns (lua_State *L)
{
	luaL_openlib(L, "dns", dnslib, 0);
	set_info(L);
	return 1;
}
