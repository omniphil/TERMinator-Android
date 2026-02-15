SRC_ROOT	:=	..
WINVER ?= 0xA00
WINNT ?= 0xA00
WIN32_IE ?= 0xA00
NTDDI ?= 0x0A000006
include ${SRC_ROOT}/build/Common.gmake

ifdef NEED_BITMAP
 OBJS += $(CIOLIB_INTERPOLATE_OBJS)
endif

ifdef WITHOUT_OOII
 CFLAGS	+= -DWITHOUT_OOII=1
else
 OBJS += $(MTOBJODIR)$(DIRSEP)ooii$(OFILE)
 OBJS += $(MTOBJODIR)$(DIRSEP)ooii_logons$(OFILE)
 OBJS += $(MTOBJODIR)$(DIRSEP)ooii_cmenus$(OFILE)
 OBJS += $(MTOBJODIR)$(DIRSEP)ooii_bmenus$(OFILE)
 OBJS += $(MTOBJODIR)$(DIRSEP)ooii_sounds$(OFILE)
endif

ifeq ($(os),sunos)    # Solaris
 LDFLAGS += -lnsl -lrt -lcurses
 CFLAGS	+=	-DNEED_CFMAKERAW
endif

ifdef WITHOUT_CRYPTLIB
 CFLAGS += -DWITHOUT_CRYPTLIB
 CRYPT_LDFLAGS :=
 CRYPT_DEPS :=
 CRYPT_LIBS :=
else
 OBJS += $(MTOBJODIR)$(DIRSEP)ssh$(OFILE)
 OBJS += $(MTOBJODIR)$(DIRSEP)telnets$(OFILE)
 CFLAGS	+=	$(CRYPT_CFLAGS) $(SFTP-MT_CFLAGS)
 CRYPT_LDFLAGS += $(SFTP-MT_LDFLAGS)
 EXTRA_LIBS	+=	$(CRYPT_LIBS) $(SFTP-MT_LIBS)
 STATIC_CRYPTLIB	:= true
 CRYPT_LIBS += $(CRYPT_LIB)
endif

ifndef WITHOUT_JPEG_XL
 ifdef win
  CFLAGS += -I${3RDP_ROOT}/win32.release/libjxl/include -DJXL_THREADS_STATIC_DEFINE -DJXL_STATIC_DEFINE -DDLLIFY
  LDFLAGS += -L${3RDP_ROOT}/${os}.release/libjxl/lib -static-libstdc++ -static-libgcc
  EXTRA_LIBS += -ljxl
  EXTRA_LIBS += -ljxl_threads
  EXTRA_LIBS += -lbrotlidec
  EXTRA_LIBS += -lbrotlicommon
  EXTRA_LIBS += -lhwy
  EXTRA_LIBS += -mdll
  CFLAGS += -DWITH_JPEG_XL -DWITH_STATIC_JXL
  CFLAGS += -DWITH_JPEG_XL_THREADS
  OBJS += $(MTOBJODIR)$(DIRSEP)libjxl$(OFILE)
  OBJS += $(MTOBJODIR)$(DIRSEP)conn_conpty$(OFILE)
 else
  ifeq ($(shell pkg-config libjxl --exists && echo YES), YES)
   CFLAGS += $(shell pkg-config libjxl --cflags)
   CFLAGS += -DWITH_JPEG_XL
   OBJS += $(MTOBJODIR)$(DIRSEP)libjxl$(OFILE)
   ifeq ($(shell pkg-config libjxl_threads --exists && echo YES), YES)
    CFLAGS += $(shell pkg-config libjxl_threads --cflags)
    CFLAGS += -DWITH_JPEG_XL_THREADS
   endif
  else
   ifeq ($(os),darwin)
    CFLAGS += -I$(3RDP_ROOT)/$(os).release/libjxl/include -DJXL_THREADS_STATIC_DEFINE -DJXL_STATIC_DEFINE
    LDFLAGS += -L$(3RDP_ROOT)/$(os).release/libjxl/lib
    EXTRA_LIBS += -ljxl
    EXTRA_LIBS += -ljxl_threads
    EXTRA_LIBS += -lbrotlidec
    EXTRA_LIBS += -lbrotlicommon
    EXTRA_LIBS += -lhwy
    CFLAGS += -DWITH_JPEG_XL -DWITH_STATIC_JXL
    CFLAGS += -DWITH_JPEG_XL_THREADS
    OBJS += $(MTOBJODIR)$(DIRSEP)libjxl$(OFILE)
   endif
  endif
 endif
endif

$(MTOBJODIR)$(DIRSEP)conn$(OFILE): $(CRYPT_LIBS)
$(MTOBJODIR)$(DIRSEP)ssh$(OFILE): $(CRYPT_LIBS)
$(MTOBJODIR)$(DIRSEP)syncterm$(OFILE): $(CRYPT_LIBS) $(CIOLIB-MT)
$(MTOBJODIR)$(DIRSEP)telnets$(OFILE): $(CRYPT_LIBS)
$(CIOLIB_INTERPOLATE_OBJS): $(CIOLIB-MT_BUILD)

ifeq ($(os),darwin)
 OBJS += $(MTOBJODIR)$(DIRSEP)DarwinWrappers$(OFILE)
 EXTRA_LIBS += -framework Foundation
 STATIC_CRYPTLIB ?= 1
endif

ifdef STATIC_CRYPTLIB
 CFLAGS += -DSTATIC_CRYPTLIB
endif

DESTDIR	?=
PREFIX	?= /usr/local
DESKTOPDIR ?= $(PREFIX)/share/applications

CFLAGS	+=	-DPREFIX=\"${DESTDIR}${PREFIX}\"
CFLAGS	+=	-DTELNET_NO_DLL
ifeq ($(PREFIX),/usr)
 SYSTEM_LIST_DIR ?= /etc
else
 SYSTEM_LIST_DIR ?= ${PREFIX}/etc
endif
MANPREFIX ?= $(PREFIX)/share
CFLAGS	+=	-DSYSTEM_LIST_DIR=\"${SYSTEM_LIST_DIR}\"

CFLAGS	+=	$(UIFC-MT_CFLAGS) $(CIOLIB-MT_CFLAGS) $(XPDEV-MT_CFLAGS) $(ENCODE_CFLAGS) $(HASH_CFLAGS) -I../sbbs3 -I../comio
LDFLAGS	+=	$(UIFC-MT_LDFLAGS) $(CIOLIB-MT_LDFLAGS) $(XPDEV-MT_LDFLAGS) $(ENCODE_LDFLAGS) $(HASH_LDFLAGS) $(CRYPT_LDFLAGS)

vpath %.c ../sbbs3 ../uifc ../comio

ifdef DEBUG
 INSTALL_EXE	?=	install
else
 INSTALL_EXE	?=	install -s
endif
INSTALL_DATA	?=	install -m 0644

ifdef win
 OBJS	+= $(MTOBJODIR)$(DIRSEP)comio_win32$(OFILE) \
           $(MTOBJODIR)$(DIRSEP)modem$(OFILE) \
           $(MTOBJODIR)$(DIRSEP)comio$(OFILE) \
           $(MTOBJODIR)$(DIRSEP)syncterm_res$(OFILE)
 BUILD_DEPENDS += $(MTOBJODIR)$(DIRSEP)ciolib_res$(OFILE) \
           $(MTOBJODIR)$(DIRSEP)syncterm_res$(OFILE)
else
 ifneq ($(os),haiku)
  OBJS	+= $(MTOBJODIR)$(DIRSEP)comio_nix$(OFILE) \
           $(MTOBJODIR)$(DIRSEP)modem$(OFILE) \
           $(MTOBJODIR)$(DIRSEP)comio$(OFILE)
 endif
endif
OBJS += $(MTOBJODIR)$(DIRSEP)conn_pty$(OFILE)
ifndef bcc
 ifneq ($(os),sunos)
  ifneq ($(os),darwin)
   ifneq ($(os),haiku)
    ifndef win
     EXTRA_LIBS   +=  -lutil
    endif
   endif
  endif
 endif
endif

ifdef win
 EXTRA_LIBS += -luuid
endif

$(MTOBJODIR)$(DIRSEP)ciolib_res$(OFILE): ${CIOLIB-MT}
	cd ${MTOBJODIR} && $(AR) -x ../${CIOLIB-MT} ciolib_res$(OFILE)

webget: webget.o $(CRYPT_DEPS) $(EXEODIR) $(OBJS) $(BUILD_DEPENDS)
	@echo Linking $@
	${QUIET}$(CXX) $(LDFLAGS) $(MT_LDFLAGS) $(OBJS) webget.o -o $@ $(UIFC-MT_LIBS) $(EXTRA_LIBS) $(CIOLIB-MT_LIBS) $(XPDEV-MT_LIBS) $(ENCODE_LIBS) $(HASH_LIBS)
