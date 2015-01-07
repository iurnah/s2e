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

//#define NDEBUG

extern "C" {
#include "config.h"
#include "qemu-common.h"
extern CPUArchState *env;
}


#include <sstream>
#include <s2e/ConfigFile.h>

#include "LinuxCodeSelector.h"
#include "Opcodes.h"
#include "LinuxExecutionDetector.h"

#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/S2EExecutor.h>


using namespace s2e;
using namespace plugins;

S2E_DEFINE_PLUGIN(LinuxCodeSelector,
                  "Plugin for monitoring module execution",
                  "LinuxCodeSelector",
                  "LinuxExecutionDetector");


LinuxCodeSelector::LinuxCodeSelector(S2E *s2e) : Plugin(s2e) {

}


LinuxCodeSelector::~LinuxCodeSelector()
{

}

void LinuxCodeSelector::initialize()
{
    m_executionDetector = (LinuxExecutionDetector*)s2e()->getPlugin("LinuxExecutionDetector");
    assert(m_executionDetector);

    ConfigFile *cfg = s2e()->getConfig();

    bool ok = false;

    //Fetch the list of modules where forking should be enabled
    ConfigFile::string_list moduleList =
            cfg->getStringList(getConfigKey() + ".moduleIds", ConfigFile::string_list(), &ok);

    if (!ok || moduleList.empty()) {
        s2e()->getWarningsStream() << "You should specify a list of modules in " <<
                getConfigKey() + ".moduleIds\n";
    }

    foreach2(it, moduleList.begin(), moduleList.end()) {
        if (m_executionDetector->isModuleConfigured(*it)) {
            m_interceptedModules.insert(*it);
			s2e()->getWarningsStream() << "(conf)LinuxCodeSelector: Module " << *it << " is inserted m_interceptedModules!\n";
        }else {
            s2e()->getWarningsStream() << "(conf)LinuxCodeSelector: " <<
                    "Module " << *it << " is not configured\n";
            exit(-1);
        }
    }

    //Attach the signals from the LinuxExecutionDetector plugin
    m_executionDetector->onModuleTransition.connect(
        sigc::mem_fun(*this, &LinuxCodeSelector::onModuleTransition));

    s2e()->getCorePlugin()->onCustomInstruction.connect(
        sigc::mem_fun(*this, &LinuxCodeSelector::onCustomInstruction));
}

void LinuxCodeSelector::onModuleTransition(
        S2EExecutionState *state,
        const ModuleDescriptor *prevModule,
        const ModuleDescriptor *currentModule
        )
{

    if (!currentModule) {
		//disable forking if not interested module
        state->disableForking();
        return;
    }
	
#if 0
	if(prevModule == NULL){
		s2e()->getDebugStream(state) << "LinuxCodeSelector::onModuleTransition: prevModule=NULL" << '\n';
	}else 
		s2e()->getDebugStream(state) << "LinuxCodeSelector::onModuleTransition: prevModule=" << 
			prevModule->Name << " currentModule=" << currentModule->Name << '\n';
#endif

	if (m_interceptedModules.find(currentModule->Name) == m_interceptedModules.end()) {
		//if current module is not in interceptedModule, disableForking.
        state->disableForking(); 
        return;
    }else { //else enableForking
		state->enableForking();
	}

	//emit signal inform when Module Transition is happened
	onModuleTransitionSelector.emit(state, prevModule, currentModule);
}

void LinuxCodeSelector::onPageDirectoryChange(
        S2EExecutionState *state,
        uint64_t previous, uint64_t current
        )
{
    if (m_pidsToTrack.empty()) {
        return;
    }

    Pids::const_iterator it = m_pidsToTrack.find(current);
    if (it == m_pidsToTrack.end()) {
        state->disableForking();
        return;
    }

    //Enable forking if we track the entire address space
    if ((*it).second == true) {
        state->enableForking();
    }
}

/**
 *  Monitor privilege level changes and enable forking
 *  if execution is in a tracked address space and in
 *  user-mode.
 */
void LinuxCodeSelector::onPrivilegeChange(
        S2EExecutionState *state,
        unsigned previous, unsigned current
        )
{
    if (m_pidsToTrack.empty()) {
        return;
    }

    Pids::const_iterator it = m_pidsToTrack.find(state->getPid());
    if (it == m_pidsToTrack.end()) {
        //Not in a tracked process
        state->disableForking();
        return;
    }

    //We are inside a process that we are tracking.
    //Check now if we are in user-mode.
    if ((*it).second == false) {
        //XXX: Remove hard-coded CPL level. It is x86-architecture-specific.
        if (current == 3) { //cpl = 3 indicate user mode
            //Enable forking in user mode.
            state->enableForking(); //start Forking in libs
        } else {
            state->disableForking();
        }
#if 1 //add this else case to make the --select-process enable all fork in the process
	  //including kernel code
    }else if((*it).second == true){
		state->enableForking();
#endif
	}
}

void LinuxCodeSelector::opSelectProcess(S2EExecutionState *state)
{
    bool ok = true;
    target_ulong isUserSpace;
	//we have macro #define IS_USERSPACE regs[R_ECX]
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(IS_USERSPACE), &isUserSpace,
                                                    sizeof isUserSpace);


    if (isUserSpace) {
        //Track the current process, but user-space only
		//false here mean we are not tracking pid,
        m_pidsToTrack[state->getPid()] = false;


        if (!m_privilegeTracking.connected()) {
            m_privilegeTracking = s2e()->getCorePlugin()->onPrivilegeChange.connect(
                    sigc::mem_fun(*this, &LinuxCodeSelector::onPrivilegeChange));
        }
    } else { 
		//"true" means we are going to track this pid, i.e. whole process
		//address space.
        m_pidsToTrack[state->getPid()] = true;

        if (!m_privilegeTracking.connected()) {
            m_privilegeTracking = s2e()->getCorePlugin()->onPageDirectoryChange.connect(
                    sigc::mem_fun(*this, &LinuxCodeSelector::onPageDirectoryChange));
        } 
		/* misunderstand the code, thought it is a bug, infact, not, so comment
		 * out this section, */
		/* it actually doesn't matter whether you use the "m_privilegeTracking"
		 * or 'm_addressSpaceTracking', both will work, they didn't affect the
		 * code logic.
        if (!m_addressSpaceTracking.connected()) {
            m_addressSpaceTracking = s2e()->getCorePlugin()->onPageDirectoryChange.connect(
                    sigc::mem_fun(*this, &LinuxCodeSelector::onPageDirectoryChange));
        }
		*/

    }
}

void LinuxCodeSelector::opUnselectProcess(S2EExecutionState *state)
{
    bool ok = true;
    target_ulong pid;
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(PROC_ID), &pid,
                                         sizeof pid);

    if(!ok) {
        s2e()->getWarningsStream(state)
            << "[opCode]LinuxCodeSelector: Could not read the pid value of the process to disable.\n";
        return;
    }

    if (pid == 0) {
        pid = state->getPid();
    }

    m_pidsToTrack.erase(pid);

    if (m_pidsToTrack.empty()) {
        m_privilegeTracking.disconnect();
        m_addressSpaceTracking.disconnect();
    }
}

//when we use the select-process-code, we don't use opcode AE 00 and AE 01 for
//code selector. We only use the AE 02 for opSelectModule. This opcode just add
//the module name to the m_interceptedModules
bool LinuxCodeSelector::opSelectModule(S2EExecutionState *state)
{
    bool ok = true;
    target_ulong moduleId;
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(MOD_ID), &moduleId,
                                         sizeof moduleId);

    if(!ok) {
        s2e()->getWarningsStream(state)
            << "[opCode]LinuxCodeSelector: Could not read the module id pointer.\n";
        return false;
    }

    std::string strModuleId;
    if (!state->readString(moduleId, strModuleId)) {
        s2e()->getWarningsStream(state)
            << "[opCode]LinuxCodeSelector: Could not read the module id string.\n";
        return false;
    }

	//TODO why check configuration in LinuxExecutionDetector? modify?
    if (m_executionDetector->isModuleConfigured(strModuleId)) {
        if(m_interceptedModules.find(strModuleId) == m_interceptedModules.end()){
			//if not exist, we insert it here manually
			m_interceptedModules.insert(strModuleId);
			s2e()->getWarningsStream() << "[opCode]LinuxCodeSelector: " <<
                "Module " << strModuleId << " is insert to m_interceptedModules\n";
		}else 
			s2e()->getWarningsStream() << "[opCode]LinuxCodeSelector: " << 
				strModuleId << " is inserted to m_interceptedModules already\n" ;
    }else {
        s2e()->getWarningsStream() << "[opCode]LinuxCodeSelector: " <<
                "Module " << strModuleId << " is not configured in LinuxExecutionDetector\n";
        return false;
    }

    s2e()->getMessagesStream() << "[opCode]LinuxCodeSelector: tracking module " << 
			strModuleId << '\n';

    return true;
}

void LinuxCodeSelector::onCustomInstruction(
        S2EExecutionState *state,
        uint64_t operand
        )
{
    if (!OPCODE_CHECK(operand, CODE_SELECTOR_OPCODE)) {
        return;
    }

    uint64_t subfunction = OPCODE_GETSUBFUNCTION(operand);

    switch(subfunction) {
        //TODO:Track the currently-running process (either whole passed system or user-space only)
		//s2e_codeselector_enable_address_space(unsigned user_mode_only)
		//
		//parameter "user_mdoe_only" is stored in the ecx registers.
        case 0: {
            opSelectProcess(state);
        }
        break;

        //Disable tracking of the selected process
        //The process's id to not track is in the ecx register.
        //If ecx is 0, untrack the current process.
		//
		//s2e_codeselector_disable_address_space(unsigned user_mode_only)
		//This has never been used in the code.
        case 1: {
            opUnselectProcess(state);
        }
        break;

        //Adds the module id specified in ecx to the list
        //of modules where to enable forking.
		//this correspond to the --select-process-code option
		//
		//s2e_codeselector_select_module(const char *moduleId)
        case 2: {
            if (opSelectModule(state)) {
                tb_flush(env);
                state->setPc(state->getPc() + OPCODE_SIZE);
                throw CpuExitException();
            }
        }
        break;
    }
}
