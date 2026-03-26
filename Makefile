.PHONY: help configure build all clean distclean clean-data

BUILD_DIR := build
DB_FILE := server/deploy/storage/sqlite_data/sfs.db
STORAGE_DIR := server/deploy/storage/sfs_storage

help:
	@echo "Targets:"
	@echo "  make configure   Generate the CMake build directory"
	@echo "  make build       Build the project"
	@echo "  make all         Configure and build"
	@echo "  make clean       Remove compiled artifacts from the current build directory"
	@echo "  make distclean   Remove the entire build directory and compile_commands symlink"
	@echo "  make clean-data  Remove local SQLite/storage runtime data"

configure:
	cmake -S . -B $(BUILD_DIR)

build:
	cmake --build $(BUILD_DIR)

all: configure build

clean:
	@if [ -f "$(BUILD_DIR)/Makefile" ]; then \
		cmake --build $(BUILD_DIR) --target clean; \
	else \
		echo "No build directory to clean."; \
	fi

distclean:
	rm -rf $(BUILD_DIR)
	rm -f compile_commands.json

clean-data:
	rm -f $(DB_FILE)
	rm -rf $(STORAGE_DIR)
	mkdir -p $(dir $(DB_FILE)) $(STORAGE_DIR)
