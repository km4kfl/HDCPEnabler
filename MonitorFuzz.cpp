#include "AppExceptions.h"
#include "MonitorFuzz.h"

#include <cstdlib>

PhysicalMonitorArray::PhysicalMonitorArray(int count) : count(count) {
	vec = std::vector<PHYSICAL_MONITOR>(count);
}

HANDLE PhysicalMonitorArray::GetMonitorHandle(int index) {
	if (index >= vec.size()) {
		return NULL;
	}

	return vec[index].hPhysicalMonitor;
}

PhysicalMonitorArray::~PhysicalMonitorArray() {
	DeallocateResources();
}

void PhysicalMonitorArray::DeallocateResources() {
	if (vec.size() > 0)
		DestroyPhysicalMonitors(count, vec.data());
}

PhysicalMonitorArray& PhysicalMonitorArray::operator=(PhysicalMonitorArray&& other) noexcept {
	if (vec.size() > 0) {
		DeallocateResources();
	}

	vec = other.vec;
	count = other.count;

	other.vec = std::vector<PHYSICAL_MONITOR>(0);
	other.count = 0;
	return *this;
}

BOOL PhysicalMonitorArray::FetchPhysicalMonitorsFromHMONITOR(HMONITOR h_monitor) {
	return GetPhysicalMonitorsFromHMONITOR(h_monitor, count, vec.data());
}

MonitorFuzz::MonitorFuzz() : 
	phy_monitors(0), 
	initialized(false),
	red_cur_drive(0),
	red_max_drive(0),
	red_min_drive(0),
	green_cur_drive(0),
	green_max_drive(0),
	green_min_drive(0),
	blue_cur_drive(0),
	blue_max_drive(0),
	blue_min_drive(0)
	{
}

static BOOL monitor_enum_proc(
	HMONITOR h_monitor,
	HDC h_dc,
	LPRECT lprect,
	LPARAM lparam
) {
	*((HMONITOR*)lparam) = h_monitor;
	return TRUE;
}

void MonitorFuzz::ResetMonitor() {
	Initialize();

	HANDLE phy_monitor = phy_monitors.GetMonitorHandle(0);

	BOOL_THROW(RestoreMonitorFactoryDefaults(phy_monitor));
}

void MonitorFuzz::RandomlyOffsetDrive(float adjust_amount) {
	// Attempts initialization if not already done. Lazy init.
	Initialize();

	HANDLE phy_monitor = phy_monitors.GetMonitorHandle(0);

	// It can be ZERO and VALID at the same time.
	//BOOL_THROW(phy_monitor != NULL);

	DWORD red_low = (DWORD)((float)red_cur_drive * (1.0 - adjust_amount));
	DWORD red_high = (DWORD)((float)red_cur_drive * (1.0 + adjust_amount));
	DWORD green_low = (DWORD)((float)green_cur_drive * (1.0 - adjust_amount));
	DWORD green_high = (DWORD)((float)green_cur_drive * (1.0 + adjust_amount));
	DWORD blue_low = (DWORD)((float)blue_cur_drive * (1.0 - adjust_amount));
	DWORD blue_high = (DWORD)((float)blue_cur_drive * (1.0 + adjust_amount));

	//BOOL_THROW(red_high > 0);
	//BOOL_THROW(green_high > 0);
	//BOOL_THROW(blue_high > 0);

	red_low = red_low < red_min_drive ? red_min_drive : red_low;
	green_low = green_low < green_min_drive ? green_min_drive : green_low;
	blue_low = blue_low < blue_min_drive ? blue_min_drive : blue_low;
	red_high = red_high > red_max_drive ? red_max_drive : red_high;
	green_high = green_high > green_max_drive ? green_max_drive : green_high;
	blue_high = blue_high > blue_max_drive ? blue_max_drive : blue_high;

	DWORD red_delta = red_high - red_low;
	DWORD green_delta = green_high - green_low;
	DWORD blue_delta = blue_high - blue_low;

	float red_ratio = (float)std::rand() / (float)RAND_MAX;
	float green_ratio = (float)std::rand() / (float)RAND_MAX;
	float blue_ratio = (float)std::rand() / (float)RAND_MAX;

	DWORD red_new_drive = red_low + (DWORD)(red_delta * red_ratio);
	DWORD green_new_drive = green_low + (DWORD)(green_delta * green_ratio);
	DWORD blue_new_drive = blue_low + (DWORD)(blue_delta * blue_ratio);

	BOOL_THROW(SetMonitorRedGreenOrBlueDrive(
		phy_monitor,
		MC_DRIVE_TYPE::MC_RED_DRIVE,
		red_new_drive
	));

	BOOL_THROW(SetMonitorRedGreenOrBlueDrive(
		phy_monitor,
		MC_DRIVE_TYPE::MC_GREEN_DRIVE,
		green_new_drive
	));

	BOOL_THROW(SetMonitorRedGreenOrBlueDrive(
		phy_monitor,
		MC_DRIVE_TYPE::MC_BLUE_DRIVE,
		blue_new_drive
	));
}

void MonitorFuzz::Initialize() {
	if (initialized) {
		return;
	}

	DWORD phy_monitor_count = 0;
	BOOL res = FALSE;
	HMONITOR h_monitor = NULL;

	BOOL_THROW(EnumDisplayMonitors(
		NULL, NULL, monitor_enum_proc, (LPARAM)&h_monitor
	));

	BOOL_THROW(h_monitor != NULL);

	BOOL_THROW(GetNumberOfPhysicalMonitorsFromHMONITOR(
		h_monitor, &phy_monitor_count
	));

	BOOL_THROW(phy_monitor_count > 0);

	// Grab the physical monitor handles (type HANDLE) associated
	// with the HMonitor handle. I'm guessing HMonitor is a virtual
	// type monitor. This is wrapped for safety. See relevant class.
	phy_monitors = PhysicalMonitorArray(phy_monitor_count);
	BOOL_THROW(phy_monitors.FetchPhysicalMonitorsFromHMONITOR(h_monitor));

	HANDLE phy_monitor = phy_monitors.GetMonitorHandle(0);

	// The handle can be valid AND zero/NULL. Don't check it.
	//BOOL_THROW(phy_monitor != NULL);

	BOOL_THROW(GetMonitorRedGreenOrBlueDrive(
		phy_monitor,
		MC_DRIVE_TYPE::MC_RED_DRIVE,
		&red_min_drive,
		&red_cur_drive,
		&red_max_drive
	));

	BOOL_THROW(GetMonitorRedGreenOrBlueDrive(
		phy_monitor,
		MC_DRIVE_TYPE::MC_GREEN_DRIVE,
		&green_min_drive,
		&green_cur_drive,
		&green_max_drive
	));

	BOOL_THROW(GetMonitorRedGreenOrBlueDrive(
		phy_monitor,
		MC_DRIVE_TYPE::MC_BLUE_DRIVE,
		&blue_min_drive,
		&blue_cur_drive,
		&blue_max_drive
	));

	initialized = true;
}