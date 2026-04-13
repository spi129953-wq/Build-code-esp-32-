cmake_minimum_required(VERSION 3.5)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(wifi_web_tool)

# Thêm SPIFFS để lưu web files
set(COMPONENT_REQUIRES spiffs)

# Thêm component web_interface
set(EXTRA_COMPONENT_DIRS components)
