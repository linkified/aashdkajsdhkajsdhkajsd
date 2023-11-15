#pragma once

#ifndef MAIN_H
#define MAIN_H

#include "Common.h"
#include "App.h"

#ifndef NDEBUG
int main(); 
#else
INT WINAPI wWinMain(
    _In_ HINSTANCE   hInstance,
    _In_opt_ HINSTANCE   hPrevInstance,
    _In_ PWSTR       lpCmdLine,
    _In_ int         nCmdShow
);
#endif

bool autoRun();

namespace os {
    string genGUID();
    string GetHWID();
    string getVolumeSerial();
}

#endif