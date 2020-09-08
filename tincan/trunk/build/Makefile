include config.mk

.PHONY : all vars mkdirs clean help

## all : default rule to create ipop-tincan executable
all : mkdirs $(TARGET)

## vars : prints variables
vars :
	@echo HDR_FILES: $(HDR_FILES)
	@echo SRC_FILES: $(SRC_FILES)
	@echo OBJ_FILES: $(OBJ_FILES)

## mkdirs : creates the output directories	if it does not exist
mkdirs :
	if [ ! -d $(OBJ_DIR) ]; then  mkdir -p $(OBJ_DIR); fi

$(TARGET) : $(OBJ_FILES) $(LOBJ_FILES)
	#$(CC) -fuse-ld=/usr/bin/ldd 
	$(CC) -v -o $@ $^ -L $(EXT_LIB_DIR) $(LIBS) 

## ../src/file.obj : comiples the specified object file
$(OBJ_DIR)/%.o : $(SRC_DIR)/%.cc $(HDR_FILES)	
	$(CC) -iquote $(INC_DIR) -isystem $(EXT_INC_DIR) -isystem $(RTC_INC_DIR) $(defines) $(cflags_cc) -c $< -o $@


$(LOBJ_FILES) : $(LSRC_FILES) $(INC_DIR_LNX)/tapdev_lnx.h
	$(CC) -iquote $(INC_DIR) -isystem $(EXT_INC_DIR) -isystem $(RTC_INC_DIR) -iquote $(INC_DIR_LNX) $(defines) $(cflags_cc) -c $< -o $@

## clean : removes output dir and generated files
clean:
	rm -rf $(OUT)

## help : prints help
help : Makefile
	@sed -n 's/^##//p' $<
