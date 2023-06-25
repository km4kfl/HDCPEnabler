#pragma once

#include <vector>
#include <highlevelmonitorconfigurationapi.h>

class PhysicalMonitorArray {
private:
	std::vector<PHYSICAL_MONITOR> vec;
	int count;
public:
	PhysicalMonitorArray(const PhysicalMonitorArray& other) = delete;
	PhysicalMonitorArray& operator=(PhysicalMonitorArray& other) = delete;
	PhysicalMonitorArray& operator=(PhysicalMonitorArray&& other) noexcept;
	PhysicalMonitorArray(int count);
	HANDLE GetMonitorHandle(int index);
	void DeallocateResources();
	BOOL FetchPhysicalMonitorsFromHMONITOR(HMONITOR h_monitor);
	~PhysicalMonitorArray();
};

class MonitorFuzz
{
private:
	PhysicalMonitorArray phy_monitors;
	DWORD red_min_drive, red_cur_drive, red_max_drive;
	DWORD green_min_drive, green_cur_drive, green_max_drive;
	DWORD blue_min_drive, blue_cur_drive, blue_max_drive;
	bool initialized;
	void Initialize();
public:
	MonitorFuzz();
	void ResetMonitor();
	void RandomlyOffsetDrive(float adjust_amount);
};

