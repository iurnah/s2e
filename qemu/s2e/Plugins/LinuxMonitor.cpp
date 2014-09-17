/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Currently maintained by:
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

/**
 *  This plugin provides the means of manually specifying the location
 *  of modules in memory.
 *
 *  This allows things like defining portions of the BIOS.
 *
 *  RESERVES THE CUSTOM OPCODE 0xAA
 */

extern "C" {
#include "config.h"
#include "qemu-common.h"
}


#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/ConfigFile.h>
#include <s2e/Plugins/Opcodes.h>
#include "LinuxMonitor.h"

#include <sstream>

using namespace std;

using namespace s2e;
using namespace s2e::plugins;

S2E_DEFINE_PLUGIN(LinuxMonitor, "Plugin for monitoring raw module events", "Interceptor");

LinuxMonitor::~LinuxMonitor()
{

}

void LinuxMonitor::initialize()
{
    std::vector<std::string> Sections;
    Sections = s2e()->getConfig()->getListKeys(getConfigKey());

    bool ok = false;
    m_kernelStart = s2e()->getConfig()->getInt(getConfigKey() + ".kernelStart", 0xc0000000, &ok);
    if (!ok) {
        s2e()->getWarningsStream() << "You should specify " << getConfigKey() << ".kernelStart\n";
    }

    s2e()->getCorePlugin()->onCustomInstruction.connect(
            sigc::mem_fun(*this, &LinuxMonitor::onCustomInstruction));
}

/* To handle the configure from opcode in init_env.c, i.e. s2e_rawmon_loadmodule2() */
void LinuxMonitor::opLoadModule(S2EExecutionState *state)
{
    target_ulong pModuleConfig;
    bool ok = true;

    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]),
                                         &pModuleConfig, sizeof(pModuleConfig));
    if(!ok) {
        s2e()->getWarningsStream(state)
            << "LinuxMonitor: Could not read the module descriptor address from the guest\n";
        return;
    }

    OpcodeModuleConfig moduleConfig;
    ok &= state->readMemoryConcrete(pModuleConfig, &moduleConfig, sizeof(moduleConfig));
    if(!ok) {
        s2e()->getWarningsStream(state)
            << "LinuxMonitor: Could not read the module descriptor from the guest\n";
        return;
    }

	//TODO:changet he module names in order to match the meaning of it.
    ModuleDescriptor moduleDescriptor;
    moduleDescriptor.NativeBase = moduleConfig.nativeBase;//loadbase
    moduleDescriptor.LoadBase = moduleConfig.loadBase;//limit
    moduleDescriptor.Size = moduleConfig.size;

    if (!state->readString(moduleConfig.name, moduleDescriptor.Name)) {
        s2e()->getWarningsStream(state)
            << "LinuxMonitor: Could not read the module string\n";
        return;
    }

	// Process module has pid, while shared library doesn't, have pid zero
    moduleDescriptor.Pid = moduleConfig.kernelMode ? 0 : state->getPid();

    s2e()->getDebugStream() << "LinuxMonitor: Module " << moduleDescriptor.Name 
			<< " pid=" << hexval(moduleDescriptor.Pid)
			<< " loadbase=" << hexval(moduleDescriptor.NativeBase) 
			<< " limit=" << hexval(moduleDescriptor.LoadBase) 
			<< " size=" << hexval(moduleDescriptor.Size) << " successfully  loaded." << "\n";

    onModuleLoad.emit(state, moduleDescriptor);
}


void LinuxMonitor::onCustomInstruction(S2EExecutionState* state, uint64_t opcode)
{
    if (!OPCODE_CHECK(opcode, RAW_MONITOR_OPCODE)) {
        return;
    }

    uint8_t op = OPCODE_GETSUBFUNCTION(opcode);

    switch(op) {
    case 0: { /* opcode match s2e_rawmon_loadmodule() */
        // Module load
        // eax/r0 = pointer to module name
        // ebx/r1 = runtime load base
        // ecx/r2 = entry point
        // opLoadConfiguredModule(state);
        break;
    }
#if 0
    case 1: { /* opcode match nothing in init_env.c */
        // Specifying a new import descriptor
        // eax/r0 = dll name
        // ebx/r1 = function name
        // ecx/r2 = function pointer
        opCreateImportDescriptor(state);
        break;
    }
#endif
    case 2: { /* opcode match the s2e_rawmon_loadmodule2() */
        // Load a non-configured module.
        // ecx/r3 = pointer to OpcodeModuleConfig structure
        opLoadModule(state);
        break;
    }

    default:
        s2e()->getWarningsStream() << "Invalid LinuxMonitor opcode " << hexval(op) << '\n';
        break;
    }
}

/**********************************************************/
/**********************************************************/
/**********************************************************/
                                                   
/*
bool LinuxMonitor::getImports(S2EExecutionState *s, const ModuleDescriptor &desc, Imports &I)
{
    I = m_imports;
    return true;
}
*/

bool LinuxMonitor::getImports(S2EExecutionState *s, const ModuleDescriptor &desc, Imports &I)
{
	s2e()->getWarningsStream() << "Program PID:"<< hexval(s->getPid()) << hexval(desc.Pid) << "\n";      //add by sun for librarycall
    if (desc.Pid && s->getPid() != desc.Pid) {
        return false;
    }

    //WindowsImage Img(s, desc.LoadBase);
    //I = Img.GetImports(s);
    ImportedFunctions F;

	//original, test the dynamic linked executable,	
	F.insert(std::pair<std::string, uint64_t>("foo", 0x08048760)); //should be called from 0x8048479 and 8048619
	F.insert(std::pair<std::string, uint64_t>("read", 0x080483d0));
	F.insert(std::pair<std::string, uint64_t>("printf", 0x080483e0));

/*	
	F.insert(std::pair<std::string, uint64_t>("lseek", 0x080483f0));
	F.insert(std::pair<std::string, uint64_t>("puts", 0x08048400));
	F.insert(std::pair<std::string, uint64_t>("__gmon_start__", 0x08048410));
	F.insert(std::pair<std::string, uint64_t>("open", 0x08048420));
	F.insert(std::pair<std::string, uint64_t>("__libc_start_main", 0x08048430));
	F.insert(std::pair<std::string, uint64_t>("write", 0x08048440));
	F.insert(std::pair<std::string, uint64_t>("close", 0x08048450));
*/
	I.insert(pair<std::string, ImportedFunctions>("GLIBC_2_0", F));
	Imports::iterator st = I.find("GLIBC_2_0");
	s2e()->getWarningsStream() << st->first << "\n";      //add by sun for librarycall

    return true;
}

bool LinuxMonitor::getExports(S2EExecutionState *s, const ModuleDescriptor &desc, Exports &E)
{
    return false;
}

bool LinuxMonitor::isKernelAddress(uint64_t pc) const
{
    return false;
}

uint64_t LinuxMonitor::getPid(S2EExecutionState *s, uint64_t pc)
{
    if (pc >= m_kernelStart && s->getPid() != -1) {
        return 0;
    }
    return s->getPid();
}
