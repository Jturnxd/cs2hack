#include "memory.h"
#include <cmath>
#include <thread>
#include <iostream>

uint64_t memory::get_proc_baseaddr()
{
	return proc.baseaddr;
}

process_status memory::get_proc_status()
{
	return status;
}

void memory::check_proc()
{
	if (status == process_status::FOUND_READY)
	{
		short c;
		read<short>(proc.baseaddr, c);

		if (c != 0x5A4D)
		{
			status = process_status::FOUND_NO_ACCESS;
			close_proc();
		}
	}
}

void memory::open_proc(const char* name)
{
        if(!conn)
        {
                ConnectorInventory *inv = inventory_scan();
                if (!inv) {
                        std::cerr << "memflow: failed to scan inventory" << std::endl;
                        status = process_status::FOUND_NO_ACCESS;
                        return;
                }

                conn = inventory_create_connector(inv, "qemu_procfs", "");
                inventory_free(inv);

                if (!conn) {
                        std::cerr << "memflow: cannot create qemu_procfs connector" << std::endl;
                        status = process_status::FOUND_NO_ACCESS;
                        return;
                }
        }

        if (conn)
        {
                if(!kernel)
                {
                        kernel = kernel_build(conn);
                        if (!kernel) {
                                std::cerr << "memflow: kernel_build failed" << std::endl;
                                status = process_status::FOUND_NO_ACCESS;
                                return;
                        }
                }

                if(kernel)
                {
                        Kernel *tmp_ker = kernel_clone(kernel);
                        if (!tmp_ker) {
                                std::cerr << "memflow: kernel_clone failed" << std::endl;
                                status = process_status::FOUND_NO_ACCESS;
                                return;
                        }

                        proc.hProcess = kernel_into_process(tmp_ker, name);
                }

                if (proc.hProcess)
                {
                        Win32ModuleInfo *module = process_module_info(proc.hProcess, name);

                        if (module)
                        {
                                OsProcessModuleInfoObj *obj = module_info_trait(module);
                                proc.baseaddr = os_process_module_base(obj);
                                os_process_module_free(obj);
                                mem = process_virt_mem(proc.hProcess);
                                if (!mem) {
                                        std::cerr << "memflow: failed to get virtual memory handle" << std::endl;
                                        status = process_status::FOUND_NO_ACCESS;
                                        close_proc();
                                        return;
                                }
                                status = process_status::FOUND_READY;
                        }
                        else
                        {
                                std::cerr << "memflow: process module info unavailable" << std::endl;
                                status = process_status::FOUND_NO_ACCESS;
                                close_proc();
                        }
                }
                else
                {
                        std::cerr << "memflow: process handle not found" << std::endl;
                        status = process_status::NOT_FOUND;
                }
        }
        else
        {
                std::cerr << "memflow: connector unavailable" << std::endl;
                status = process_status::FOUND_NO_ACCESS;
        }
}

void memory::close_proc()
{
	if (proc.hProcess)
	{
		process_free(proc.hProcess);
		virt_free(mem);	
	}

	proc.hProcess = 0;
	proc.baseaddr = 0;
	mem = 0;
}

uint64_t memory::get_module_address(const char* proc_name, const char* module_name){
        if (!kernel) {
                std::cerr << "memflow: kernel not initialized for module lookup" << std::endl;
                return 0;
        }

        Kernel *tmp_kernel = kernel_clone(kernel);
        if (!tmp_kernel) {
                std::cerr << "memflow: kernel_clone failed for module lookup" << std::endl;
                return 0;
        }

        auto cs2_process = kernel_into_process(tmp_kernel, proc_name);
        if (!cs2_process) {
                std::cerr << "memflow: failed to open process for module lookup" << std::endl;
                return 0;
        }

        auto info = process_module_info(cs2_process, module_name);
        if (!info) {
                std::cerr << "memflow: module info not found for " << module_name << std::endl;
                return 0;
        }

        auto mod_info = module_info_trait(info);
        uint64_t module_base_addr = os_process_module_base(mod_info);
        os_process_module_free(mod_info);
        return module_base_addr;
}
