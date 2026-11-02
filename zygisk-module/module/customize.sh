#!/system/bin/sh

# 模块没有额外文件，只统一权限即可。
set_perm_recursive "$MODPATH" 0 0 0755 0644

ui_print "- Hide Memory Traces 已安装"
ui_print "  作用：把匿名可执行段改名为 ART 代码缓存名"
ui_print "  不改权限、不改内容、不改 VMA 数量"
