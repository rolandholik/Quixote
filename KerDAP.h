/**************************************************************************
 * (C)Copyright 2003, The Open Hurderos Foundation. All rights reserved.
 **************************************************************************/


/* Include files. */
#include <syslog.h>
#include <stdint.h>

#include <ldap.h>

#if defined(DMALLOC)
#include "dmalloc.h"
#endif


/* Numeric library identifier. */
#define KerDAP_LIBID 2


/* Numeric object identifiers. */
#define KerDAP_Hash_OBJID	1
#define KerDAP_BEAF_OBJID	2
#define KerDAP_IDfusion_OBJID	3


/* Location of the master configuration file. */
#define CONFIG "/opt/Hurderos/etc/KerDAP.conf"


/* Cryptographic function prototypes. */
#define SHA1_BINARY	0
#define SHA1_ASCII	1

#define OITSIZE		20
#define INTRINSIC_IDENTITY_SIZE	20

#if 0
#define DN "dc=test,dc=hurderos,dc=com"
#endif

/*
 * The constant to define that the krb5_authdata structure is Hurderos
 * authorization information.  This needs to be coordinated with other
 * authorization constant types in krb5.h
 */
#define KRB5_AUTHDATA_HURDEROS 70

/*
 * The following contstants define the different types of Hurderos
 * authorization information that may be defined.
 */
#define HURDAUTH_USER_IDENTITY			1
#define HURDAUTH_SERVICE_IDENTITY		2
#define HURDAUTH_SERVICE_INSTANCE_IDENTITY	3


/* Type definitions. */

/*
 * The following is the basic identity object which all the KerDAP library
 * routines function on.
 *
 * HURTODO
 * This needs to change into an opaque type definition.
 */
enum idstatus {DISABLED, ENABLED};

typedef struct identity Identity;

typedef struct ldapinfo Ldapinfo;

typedef struct krb5info Krb5info;

typedef struct cacheinfo Cacheinfo;

typedef struct authinfo Authinfo;

typedef struct configinfo *Config;

struct svcinfo
{
	char *oit;
	char *svcname;
	enum idstatus status;
};

struct identity {
	char *iid;
	char *uid;
	char *pwd;
	char *oit;
	enum idstatus status;

	struct svcinfo *svcinfo;

	Ldapinfo *ldapinfo;

	Krb5info *krb5info;

	Cacheinfo *cacheinfo;

	Config config;

	int debug;
};

	
/* Function prototypes. */

/* authorization.c */
extern Authinfo *KerDAP_Authz_User_Identity(Identity *);
extern Authinfo *KerDAP_Authz_Service_Identity(struct svcinfo *);
extern Authinfo *KerDAP_Authz_Svcinstance_Identity(Authinfo *, Authinfo *, \
						   krb5_keyblock *);
extern unsigned int KerDAP_Authz_Marshall_Size(Authinfo *);
extern void *KerDAP_Authz_Marshall(Authinfo *);
extern Authinfo *KerDAP_Authz_Init_Authdata(krb5_authdata *);
extern struct svcinfo * KerDAP_Authz_Define_Service(Authinfo *);
extern int KerDAP_Authz_Lookup_Service(Identity *);
extern int KerDAP_Authz_Lookup_Service_Instance(Identity *);
extern int KerDAP_Server_Auth(char *, char *, char *);
extern int KerDAP_Service_Auth(Identity *, struct svcinfo *);
extern void KerDAP_Authz_Dump(Authinfo *);
extern void KerDAP_Authz_Destroy(Authinfo *);

/* auth-krb5.c */
extern int KerDAP_KRB5_Authenticate(Identity *);
extern int KerDAP_KRB5_Init(Identity *);
extern int KerDAP_KRB5_Search(Identity *, char *, char *);
extern int KerDAP_KRB5_Get_Credentials(Identity *, char *, char *, char *);
int KerDAP_KRB5_Enabled(Identity *);
extern void KerDAP_KRB5_Dump(Identity *);
extern int KerDAP_KRB5_Destroy(Identity *);

/* config.c */
extern Config KerDAP_Config_Init(void);
extern int KerDAP_Config_Parse(Config, char *);
extern char * KerDAP_Config_Get(Config, char *);
extern void KerDAP_Config_Destroy(Config);
extern void KerDAP_Config_Dump(Config);

/* hmac.c */
extern char *KerDAP_SHA1(int mode, unsigned char *, int);
extern char *KerDAP_HMAC_SHA1(unsigned char *, int,  unsigned char *, int);

/* hash.c */
extern char *KerDAP_SHA1(int, unsigned char *, int );
extern char *KerDAP_Bin_To_Ascii(uint8_t *);
extern unsigned char *KerDAP_Asc_Bin(char *);

/* identity.c */
extern Identity * KerDAP_Identity_Init(void);
extern int KerDAP_Identity_IID_Search(Identity *, char *, const char *);
extern int KerDAP_Identity_KRB5_Search(Identity *, char *, char *);
extern int KerDAP_Identity_Set_Service(Identity *, char *);
extern int KerDAP_Identity_Cache_ID(Identity *, char *);
extern void KerDAP_Identity_DumpUser(Identity *);
extern int KerDAP_Identity_Enabled(Identity *);
extern void KerDAP_Identity_Destroy(Identity *);

/* kadm-stub.c */
extern void * kdb2_dbopen(char *, int, int, int, void *);
extern int kdb2_bt_rseq(void *, void *, void *, void *, unsigned int);

/* kerdap.c */
extern char *IID_Login(char *, char *);
extern char *IID_Service_Login(char *, char *, char *);
extern char *IID_Server_Login(char *, char *, char *,  char *);
extern char *IID_Authorize(char *, char *);
extern char *IID_To_Uid(char *);
extern char *POSIX_To_IID(char *);
extern char *Get_Uid(void);
extern char *Get_Principal(void);

/* keygrab.c */
extern char * KerDAP_ascii_service_keygrab(char *, char *, char *, char *);
extern unsigned char * KerDAP_binary_service_keygrab(char *, char *, char *, \
						     char *);
extern void KerDAP_set_key_realm(char *);

/* ldap.c */
extern int KerDAP_LDAP_Init(Identity *);
extern int KerDAP_Init_LDAP_Simple(void);
extern int KerDAP_LDAP_Open(Identity *);
extern char **KerDAP_Get_Attribute(Identity *, char *);
extern int KerDAP_LDAP_Lookup(Identity *, char *);
extern int KerDAP_LDAP_Search(Identity *, char *, char *);
extern char * KerDAP_LDAP_Server_Principal(Identity *);
extern void KerDAP_LDAP_Destroy(Identity *);
extern void KerDAP_LDAP_Dump(Identity *);

extern int KerDAP_Set_LDAPhost(char *);
extern int KerDAP_Search_LDAP(char *, char*);
extern int KerDAP_Base_Search(char *, char *);
extern int KerDAP_LDAP_Add(char *, LDAPMod **);
extern int KerDAP_LDAP_Delete(char *);
extern int KerDAP_LDAP_Modify(char *, LDAPMod **);
extern void KerDAP_LDAP_Close(void);

/* cache.c */
extern Cacheinfo * KerDAP_Cache_Init(void);
extern char * KerDAP_Cache_SetID(Identity *);
extern int KerDAP_Cache_SetName(struct cacheinfo *, char *);
extern char * KerDAP_Cache_User_Credential(Identity *);
extern char * KerDAP_Cache_User_Authorization(Identity *);
extern int KerDAP_Cache_Save_User_Authorization(Identity *);
extern char * KerDAP_Cache_Service_Credential(Identity *);
extern int KerDAP_Cache_Flush_User(Identity *);
extern int KerDAP_Cache_Flush_Service(Identity *);
extern int KerDAP_Cache_User_Authentication_Valid(Identity *);
extern void KerDAP_Cache_Destroy(Identity *);
extern void KerDAP_Cache_Dump(Identity *);
