# webcli.makefile - Makefile fragment for Web, CLI, and MIBway projects
#
# Copyright (c) 2007-2009, 2011-2013 Wind River Systems, Inc.
#
# The right to copy, distribute, modify or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#
# Description:
# This is the WebCLI managed build extension makefile fragment.
# Incorporates the WebCLI build into the managed build of Wind River Workbench.
#
# modification history
# -------------------------
# 01l,15jan13,r_w  using config.webcli to check the existence of mibway
#                  for RTP build.(WIND00398732)
# 01k,03dec12,r_w  check the existence of mibway for RTP build.(WIND00391562)
# 01j,16oct12,shi  add rules to update wm_filesys.c. (WIND00381871)
# 01i,31jul12,lan  add ipssl2/config to included path. (WIND00366431)
# 01h,28feb12,lan  add ipssh/config to included path. (WIND00335699)
# 01g,15mar11,r_w  fix defect WIND00256425, If there are build erros,
#                  stop build and remove WEBCLI_CONFIG_CHECK_FILE
# 01f,31oct09,m_z  WIND00188837
# 01e,24dec08,y_z  add endian for new rombuild program
# 01d,31oct08,y_z  add RTP library path
# 01c,23oct08,y_z  add some headfile's dir
# 01b,09may08,h_y  fix project build produces errors if you try 
#                  to generate includes.(WIND00092649)
# 01a,21sep07,asl  fix Defect WIND00105359
# 16mar07, ten     changed backplane file generation to be conditional 
#                  on .wmb.marker file. Also keep an empty wm_filesys.c 
#		   if no web, as a place holder for next build
#

export WIND_HOME_FS := $(subst \,/,$(WIND_HOME))
WEBCLI_BASE = $(shell sh $(WIND_HOME_FS)/wrenv.sh -o print_path '$$(WIND_COMPONENTS)' $(COMP_WEBCLI))
export WEBCLI_BASE := $(subst \,/,$(WEBCLI_BASE))
export COMPONENTS_DIR := $(patsubst %/$(COMP_WEBCLI),%,$(WEBCLI_BASE))
WEBCLI_CONFIG_FILE := $(PRJ_ROOT_DIR)/config.webcli
WEBCLI_CONFIG_CHECK_FILE := $(PRJ_ROOT_DIR)/webcli_flags.h
WEBCLI_ROMBUILD_FILE := $(PRJ_ROOT_DIR)/wm_filesys.c
WEBCLI_CONFIG_FILE_BASE := $(shell basename $(PRJ_ROOT_DIR))
WRVX_COMPBASE := $(subst \,/,$(WRVX_COMPBASE))
WEBCLI_CONFIG_SOURCES := $(PRJ_ROOT_DIR)/$(WEBCLI_CONFIG_FILE_BASE).rcp \
	 $(PRJ_ROOT_DIR)/$(WEBCLI_CONFIG_FILE_BASE).ccp \
	 $(PRJ_ROOT_DIR)/$(WEBCLI_CONFIG_FILE_BASE).wcp \
	 $(PRJ_ROOT_DIR)/$(WEBCLI_CONFIG_FILE_BASE).mcp
export ADDED_INCLUDES += -I$(WEBCLI_BASE)/target/h/wrn/wm/common \
	 -I$(WEBCLI_BASE)/target/h/wrn/wm/backplane \
	 -I$(WEBCLI_BASE)/target/h/wrn/wm/wmm \
	 -I$(WEBCLI_BASE)/target/h/wrn/wm/cli \
	 -I$(WEBCLI_BASE)/target/h/wrn/wm/http \
	 -I$(WEBCLI_BASE)/target/h/wrn/wm/rc \
	 -I$(WEBCLI_BASE)/target/h/wrn/wm/common/zlib/vxWorks \
	 -I$(WEBCLI_BASE)/target/h \
	 -I$(WEBCLI_BASE)/target/src \
	 -I$(WEBCLI_BASE)/target/src/wrn/wm \
	 -I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcrypto/include \
	 -I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcrypto/config \
	 -I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcrypto/openssl-3_0_13/include \
	 -I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipssl2/openssl-3_0_13/ssl \
	 -I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipssl2/openssl-3_0_13/include \
	 -I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipssl2/config \
	 -I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcom/include \
	 -I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcom/config \
	 -I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcom/port/vxworks/include \
	 -I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcom/port/vxworks/config \
	 -I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipssh/config \
	 -I$(PRJ_ROOT_DIR) 

export ADDED_INCLUDES += $(shell cat $(PRJ_ROOT_DIR)/webcli_includes.txt)
export ADDED_LIBS += $(shell cat $(PRJ_ROOT_DIR)/webcli_libs.txt)

ifeq ($(PROJECT_TYPE),RTP)
INCLUDEMIBWAY := $(shell grep "<snmp>" $(WEBCLI_CONFIG_FILE))
ifneq ($(INCLUDEMIBWAY),)
export ADDED_LIBS += $(VSB_DIR)/usr/lib/$(VX_CPU_FAMILY)/$(CPU)/$(subst $(TOOL_FAMILY),common,$(TOOL))/libsnmp.a
export ADDED_LIBS += $(VSB_DIR)/usr/lib/$(VX_CPU_FAMILY)/$(CPU)/$(subst $(TOOL_FAMILY),common,$(TOOL))/libepcommon.a
endif
endif

#read target's endian information from BUILD_SPEC to generate correct rombuild file
#default rombuild's endian is little
ENDIAN := l
#le : l 
ifneq ($(findstring le,$(BUILD_SPEC)),)  
ENDIAN := l
else
#be : b 
ifneq ($(findstring be,$(BUILD_SPEC)),)  
ENDIAN := b
else
#PPC : be 
ifneq ($(findstring PPC,$(BUILD_SPEC)),)
ENDIAN := b
else
#MIPS with out le : be
ifneq ($(findstring MIPS,$(BUILD_SPEC)),)
ENDIAN := b
endif
endif
endif
endif

$(WEBCLI_CONFIG_CHECK_FILE) : $(WEBCLI_CONFIG_FILE)
	@_PWD=`pwd`;\
	cd $(PRJ_ROOT_DIR);\
	for csavefile in _dummy_ `find . -type f | grep "\.c\.save$$"`; do\
		if [ "$$csavefile" = "_dummy_" ]; then\
			continue ;\
		fi;\
		mv "$$csavefile" `echo "$$csavefile" | sed 's/\.c\.save/\.c/g'`;\
	done;\
	echo "Checking configuration $(WEBCLI_CONFIG_FILE)";\
	LAUNCHER=`which launchEclipseApplication.sh`;\
	sh "$$LAUNCHER" com.windriver.ide.cfg.webcli.WebCLIChecker -v -f $(WEBCLI_CONFIG_FILE);\
	if [ 0 != $$? ]; then\
		echo "Your project contains one or more errors; correct this before building.";\
		rm -f $(WEBCLI_CONFIG_CHECK_FILE);\
		exit -1;\
	fi;\
	echo "The configuration is valid.";\
	echo "generating $(COMP_WEBCLI) configuration files";\
	webcliprj -bln $(WEBCLI_CONFIG_FILE) $(WEBCLI_CONFIG_FILE_BASE) $(WEBCLI_CONFIG_FILE_BASE);\
	if [ 0 != $$? ]; then\
		echo "Unable to convert your project for processing.";\
		rm -f $(WEBCLI_CONFIG_CHECK_FILE);\
		exit -1;\
	fi;\
	DO_IT=1;\
	if [ -f $(WEBCLI_CONFIG_FILE_BASE).rcp.cmp ]; then\
		diff $(WEBCLI_CONFIG_FILE_BASE).rcp $(WEBCLI_CONFIG_FILE_BASE).rcp.cmp > webcli.diff;\
		if [ 0 = $$? ]; then\
			DO_IT=0;\
		fi;\
	fi;\
	if [ "$$DO_IT" = "1" ]; then\
		echo "generating $(COMP_WEBCLI) rcp configuration sources";\
		wmbbd -wmb $(WEBCLI_CONFIG_FILE_BASE).rcp;\
		if [ 0 != $$? ]; then\
		  	echo "Stop build. Error in generating rcp configuration sources.";\
		  	rm -f $(WEBCLI_CONFIG_CHECK_FILE);\
		  	exit -1;\
		fi;\
	fi;\
	if [ ! -f $(WEBCLI_CONFIG_FILE_BASE).wmb.marker ]; then\
		if [ -f wmb_$(WEBCLI_CONFIG_FILE_BASE).c ]; then\
			mv wmb_$(WEBCLI_CONFIG_FILE_BASE).c wmb_$(WEBCLI_CONFIG_FILE_BASE).c.save;\
			echo "extern int _webcli_stub_nonempty_int_;" > wmb_$(WEBCLI_CONFIG_FILE_BASE).c;\
		fi;\
	fi;\
	if [ -f $(WEBCLI_CONFIG_FILE_BASE).ccp.marker ]; then\
		DO_IT=1;\
		if [ -f $(WEBCLI_CONFIG_FILE_BASE).ccp.cmp ]; then\
			diff $(WEBCLI_CONFIG_FILE_BASE).ccp $(WEBCLI_CONFIG_FILE_BASE).ccp.cmp > webcli.diff;\
			if [ 0 = $$? ]; then\
				DO_IT=0;\
			fi;\
		fi;\
		if [ "$$DO_IT" = "1" ]; then\
			echo "generating $(COMP_WEBCLI) ccp configuration sources";\
			wmcbd -wmc $(WEBCLI_CONFIG_FILE_BASE).ccp;\
			if [ 0 != $$? ]; then\
		  	echo "Stop build. Error in generating ccp configuration sources.";\
		  	rm -f $(WEBCLI_CONFIG_CHECK_FILE);\
		  	exit -1;\
		  fi;\
		fi;\
	else\
		if [ -f wmc_$(WEBCLI_CONFIG_FILE_BASE).c ]; then\
			mv wmc_$(WEBCLI_CONFIG_FILE_BASE).c wmc_$(WEBCLI_CONFIG_FILE_BASE).c.save;\
			echo "extern int _webcli_stub_nonempty_int_;" > wmc_$(WEBCLI_CONFIG_FILE_BASE).c;\
		fi;\
	fi;\
	if [ -f $(WEBCLI_CONFIG_FILE_BASE).wcp.marker ]; then\
		DO_IT=1;\
		if [ -f $(WEBCLI_CONFIG_FILE_BASE).wcp.cmp ]; then\
			diff $(WEBCLI_CONFIG_FILE_BASE).wcp $(WEBCLI_CONFIG_FILE_BASE).wcp.cmp > webcli.diff;\
			if [ 0 = $$? ]; then\
				DO_IT=0;\
			fi;\
		fi;\
		if [ "$$DO_IT" = "1" ]; then\
			echo "generating $(COMP_WEBCLI) wcp configuration sources";\
			wmwbd $(WEBCLI_CONFIG_FILE_BASE).wcp;\
			if [ 0 != $$? ]; then\
		  	echo "Stop build. Error in file 'wmw_httpconf.h' or 'wmw_httpconf.c' or 'wmw_full_demo.xml'.";\
		  	rm -f $(WEBCLI_CONFIG_CHECK_FILE);\
		  	exit -1;\
		  fi;\
		fi;\
	else\
		if [ -f wmw_httpconf.c ]; then\
			mv wmw_httpconf.c wmw_httpconf.c.save;\
			echo "extern int _webcli_stub_nonempty_int_;" > wmw_httpconf.c;\
		fi;\
		if [ -f $(WEBCLI_CONFIG_FILE_BASE).wcp ]; then \
			mv $(WEBCLI_CONFIG_FILE_BASE).wcp $(WEBCLI_CONFIG_FILE_BASE).wcp_bak;\
		fi;\
	fi;\
	for configfile in $(WEBCLI_CONFIG_SOURCES); do\
		rm -f "$$configfile".marker;\
		rm -f "$$configfile".cmp;\
		if [ -f "$$configfile" ]; then\
			cp "$$configfile" "$$configfile".cmp;\
		fi;\
	done;\
	rm -f webcli.diff;\
	cd "$$_PWD"

$(WEBCLI_ROMBUILD_FILE) : $(WEBCLI_CONFIG_CHECK_FILE)
	@_PWD=`pwd`;\
	cd $(PRJ_ROOT_DIR);\
	echo "build wm_filesys";\
	if [ -f $(WEBCLI_CONFIG_FILE_BASE).wcp ]; then \
		echo "ENDIAN is $(ENDIAN)";\
		rombuild -e$(ENDIAN) $(WEBCLI_CONFIG_FILE_BASE).wcp;\
		if [ 0 != $$? ]; then\
			echo "Stop build. Error in building wm_filesys.c";\
			rm -f $(WEBCLI_CONFIG_CHECK_FILE);\
			if [ ! -f $(WEBCLI_ROMBUILD_FILE) ]; then\
				echo "extern int _webcli_stub_nonempty_int_;" > $(WEBCLI_ROMBUILD_FILE);\
			fi;\
			exit -1;\
		fi;\
	else\
		echo "extern int _webcli_stub_nonempty_int_;" > $(WEBCLI_ROMBUILD_FILE);\
	fi;\
	cd "$$_PWD" 

webcli_config : $(WEBCLI_CONFIG_CHECK_FILE) $(WEBCLI_ROMBUILD_FILE) 

webcli_clean :
	@echo "removing $(COMP_WEBCLI) comparison files";\
	for configfile in $(WEBCLI_CONFIG_SOURCES); do\
		rm -f "$$configfile".cmp;\
	done;\
	rm -f $(WEBCLI_CONFIG_CHECK_FILE)

pre_recursion generate_sources :: webcli_config

external_clean :: webcli_clean
