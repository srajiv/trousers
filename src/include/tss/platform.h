/*
 *
 * There are platform dependent and general defines.
 *
 */

/*
 *
 * On Windows platforms the types are:
 *
 */

#ifdef _WINDOWS_ // --- This should be used on Windows platforms
typedef  unsigned char  BYTE;
typedef  signed char    TSS_BOOL;  // Make specific to TSS to avoid potential conflicts
typedef  unsigned short UINT16;
typedef  unsigned long  UINT32;
typedef  unsigned short UNICODE;
typedef  void*          PVOID;
#endif

// On Linux platforms the types are:

#ifdef __GNUC__
typedef unsigned char  BYTE;
typedef signed char    TSS_BOOL;  // Make specific to TSS to avoid potential conflicts
typedef unsigned short UINT16;
typedef unsigned int   UINT32;
typedef wchar_t        UNICODE;
typedef void*          PVOID;
#endif

