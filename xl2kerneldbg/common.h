#pragma once
#include "r0_newfunc.h"

#include "Get_SSDT.h"

class common
{
public:
	static KIRQL WPOFFx64();
	static void WPONx64(KIRQL irql);

};