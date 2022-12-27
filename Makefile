BUILD_NAME = firewall
BUILD_PATH = ./build


builder:
	pp -o $(BUILD_PATH)/$(BUILD_NAME) firewall.pl
