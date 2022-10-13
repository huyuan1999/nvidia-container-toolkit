最新的 NVIDIA Container Toolkit 修改版，实现兼容低版本 docker（docker 1.13, runc 1.0.0-rc2）的能力

在 compatible 中添加 Compatible 接口，定义了 Decode 和 Encode 方法

在 fileSpec 结构体方法的 Load 和 flushTo 中分别调用 Decode 和 Encode 以实现抹平 runc 版本变化带来的结构体内容变化

