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

extern "C" {
#include <qemu-common.h>
#include <cpu-all.h>
#include <exec-all.h>
extern CPUArchState *env;
}

#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>

#include "LibraryCallMonitor.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LibraryCallMonitor, "Flags all calls to external libraries", "LibraryCallMonitor",
                  "Interceptor", "X86FunctionMonitor", "ModuleExecutionDetector");

void LibraryCallMonitor::initialize()
{
    m_functionMonitor = static_cast<X86FunctionMonitor*>(s2e()->getPlugin("X86FunctionMonitor"));
    m_monitor = static_cast<OSMonitor*>(s2e()->getPlugin("Interceptor"));
    m_detector = static_cast<ModuleExecutionDetector*>(s2e()->getPlugin("ModuleExecutionDetector"));

    ConfigFile *cfg = s2e()->getConfig();
    m_displayOnce = cfg->getBool(getConfigKey() + ".displayOnce", false);

    bool ok = false;

    //Fetch the list of modules where to report the calls
    ConfigFile::string_list moduleList =
            cfg->getStringList(getConfigKey() + ".moduleIds", ConfigFile::string_list(), &ok);

    if (!ok || moduleList.empty()) {
        s2e()->getWarningsStream() << "LibraryCallMonitor: no modules specified, tracking everything.\n";
    }

    foreach2(it, moduleList.begin(), moduleList.end()) {
        if (!m_detector->isModuleConfigured(*it)) {
            s2e()->getWarningsStream() << "LibraryCallMonitor: module " << *it
                    << " is not configured\n";
            exit(-1);
        }
        m_trackedModules.insert(*it);
    }

    m_detector->onModuleLoad.connect(
            sigc::mem_fun(*this,
                    &LibraryCallMonitor::onModuleLoad)
            );

    m_monitor->onModuleUnload.connect(
            sigc::mem_fun(*this,
                    &LibraryCallMonitor::onModuleUnload)
            );
	s2e()->getDebugStream() << "LibraryCallMonitor: Plugin initialized!!!" << '\n';
}

/* this onModuleLoad is from ModuleExecutionDetector */
void LibraryCallMonitor::onModuleLoad(
        S2EExecutionState* state,
        const ModuleDescriptor &module
        )
{
    Imports imports;

    if (!m_monitor->getImports(state, module, imports)) {
        s2e()->getWarningsStream() << "LibraryCallMonitor could not retrieve imported functions in " << module.Name << '\n';
        return;
    }

    //Unless otherwise specified, LibraryCallMonitor tracks all library calls in the system
    if (!m_trackedModules.empty()) {
        const std::string *moduleId = m_detector->getModuleId(module);
        if (!moduleId || (m_trackedModules.find(*moduleId) == m_trackedModules.end())) {
            return;
        }
    }
	//s2e()->getDebugStream() << "LibraryCallMonitor: onModuleLoad is called!!!" << '\n';
    DECLARE_PLUGINSTATE(LibraryCallMonitorState, state);

    foreach2(it, imports.begin(), imports.end()) {
        const std::string &libName = (*it).first;	/* retrive the lib name */
        const ImportedFunctions &funcs = (*it).second; /* retrive the function symbols  and the PC */
        foreach2(fit, funcs.begin(), funcs.end()) { /* to process the function symbols */
            const std::string &funcName = (*fit).first;
            std::string composedName = libName + "!";
            composedName = composedName + funcName;

            uint64_t address = (*fit).second;

            std::pair<StringSet::iterator, bool> insertRes; /* TODO: what this for */
            insertRes = m_functionNames.insert(composedName); /* the m_functionNames(unordered_set) has GLIBC_2_0!puts */

            const char *cstring = (*insertRes.first).c_str();
            plgState->m_functions[address] = cstring; /* Insert to the per state data structure (unordered_map AddressToFunctionName) */	
			//s2e()->getDebugStream() <<  "LibraryCallMonitor: address=" << address << "cstring= " << cstring << '\n';	
			
			s2e()->getMemoryTypeStream(state) << "In the Inner foreach2 loop!!! Before getCallSignal." << '\n';
            X86FunctionMonitor::CallSignal *cs = m_functionMonitor->getCallSignal(state, address, module.Pid);
			//it create a signal (first time) or look for a callSignal that
			//match the pc and eip in the m_callDescriptors from X86FunctionMonitor.
			//and connect the returned signal to the slot function onFunctionCall
            cs->connect(sigc::mem_fun(*this, &LibraryCallMonitor::onFunctionCall));
			s2e()->getMemoryTypeStream(state) << "In the Inner foreach2 loop!!! After the connection." << '\n';

			//s2e()->getDebugStream() << "LibraryCallMonitor: onFunctionCall is connected!!!" << '\n';
        }
    }
}

void LibraryCallMonitor::onFunctionCall(S2EExecutionState* state, X86FunctionMonitorState *fns)
{

	s2e()->getMemoryTypeStream(state) << "LibraryCallMonitor::onFunctionCall!!!" << '\n';
    //Only track configured modules
    uint64_t caller = state->getTb()->pcOfLastInstr;
    const ModuleDescriptor *mod = m_detector->getModule(state, caller);
    if (!mod) {
        return;
    }

    DECLARE_PLUGINSTATE(LibraryCallMonitorState, state);
    uint64_t pc = state->getPc();
/*
	bool ok = state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBP]),&ebp, sizeof(ebp));
	if(!ok){
		s2e()->getDebugStream() << "Read Base Pointer failed !!" << '\n';
	}
*/

    if (m_displayOnce && (m_alreadyCalledFunctions.find(std::make_pair(mod->Pid, pc)) != m_alreadyCalledFunctions.end())) {
        return;
    }

    LibraryCallMonitorState::AddressToFunctionName::iterator it = plgState->m_functions.find(pc);
    if (it != plgState->m_functions.end()) {
        const char *str = (*it).second;
        s2e()->getMemoryTypeStream(state) << mod->Name << "@" << hexval(mod->ToNativeBase(caller)) << " called function " << str << '\n';
		
		//TODO: query the function definition to obtain the parameter number and
		//read the stack for retrive the parameters. We can modify the imports
		//in RawMonitor to include the name of function and number of parameters
		//and parameter types.		

		uint64_t esp = state->getSp();
		uint64_t ebp = plgState->getBp(state);//readCpuRegister(CPU_OFFSET(regs[R_EBP]), 8 * CPU_REG_SIZE)a;
		//uint64_t ebp1 = state->getBp();
		//uint64_t ebp3;
		//bool	ok = state->readRegisterConcrete(env, CPU_OFFSET(regs[R_EBX]), &ebp3, sizeof(ebp3));
		s2e()->getMemoryTypeStream() << "~onFunctionCall::Base  Pointer =" << hexval(ebp) << '\n';
		s2e()->getMemoryTypeStream() << "~onFunctionCall::Stack Pointer =" << hexval(esp) << '\n';
		s2e()->getMemoryTypeStream() << "~onFunctionCall::Prog  Counter =" << hexval(pc) << '\n';
		s2e()->getMemoryTypeStream() << "------------------END-----------------" << '\n';

        onLibraryCall.emit(state, fns, *mod);

        if (m_displayOnce) {
            m_alreadyCalledFunctions.insert(std::make_pair(mod->Pid, pc));
        }
    }
}

void LibraryCallMonitor::onModuleUnload(
        S2EExecutionState* state,
        const ModuleDescriptor &module
        )
{
    m_functionMonitor->disconnect(state, module);
    return;
}

LibraryCallMonitorState::LibraryCallMonitorState()
{

}

LibraryCallMonitorState::~LibraryCallMonitorState()
{

}

uint64_t LibraryCallMonitorState::getBp(S2EExecutionState *state){
	
	return state->getBp();

}
LibraryCallMonitorState* LibraryCallMonitorState::clone() const
{
    return new LibraryCallMonitorState(*this);
}

PluginState *LibraryCallMonitorState::factory(Plugin *p, S2EExecutionState *s)
{
    return new LibraryCallMonitorState();
}

} // namespace plugins
} // namespace s2e
