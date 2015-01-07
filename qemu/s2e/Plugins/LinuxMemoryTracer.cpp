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
#include "config.h"
#include "qemu-common.h"
}

#include <iomanip>
#include <inttypes.h>

#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include "LinuxMemoryTracer.h"

#include <llvm/Support/CommandLine.h>
#include <llvm/Support/TimeValue.h>
extern llvm::cl::opt<bool> ConcolicMode;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LinuxMemoryTracer, "Memory tracer plugin", "LinuxMemoryTracer", 
                                     "LinuxExecutionDetector", "LinuxCodeSelector");

LinuxMemoryTracer::LinuxMemoryTracer(S2E* s2e)
        : Plugin(s2e)
{

}

void LinuxMemoryTracer::initialize()
{
	m_executionDetector = (LinuxExecutionDetector*)s2e()->getPlugin("LinuxExecutionDetector");
    assert(m_executionDetector);
	m_LinuxCodeSelector = (LinuxCodeSelector*)s2e()->getPlugin("LinuxCodeSelector");	
	//Fetch the list of modules where forking should be enabled
    ConfigFile *cfg = s2e()->getConfig();
	bool ok = false;

    ConfigFile::string_list moduleList =
            cfg->getStringList(getConfigKey() + ".moduleIds", ConfigFile::string_list(), &ok);

    if (!ok || moduleList.empty()) {
        s2e()->getWarningsStream() << "You should specify a list of modules in " <<
                getConfigKey() + ".moduleIds\n";
    }

    //Start tracking after the specified number of seconds
	timeTrigger = false;
    bool hasTimeTrigger = false;
    m_timeTrigger = s2e()->getConfig()->getInt(getConfigKey() + ".timeTrigger", 0, &hasTimeTrigger);
    m_elapsedTics = 0;

	s2e()->getWarningsStream() << "LinuxMemoryTracer: hasTimeTrigger has the value of: " << hasTimeTrigger << '\n';
    if (hasTimeTrigger) {
        m_timerConnection = s2e()->getCorePlugin()->onTimer.connect(
                sigc::mem_fun(*this, &LinuxMemoryTracer::onTimer));
    }

    foreach2(it, moduleList.begin(), moduleList.end()) {
        if (m_executionDetector->isModuleConfigured(*it)) {
            m_interceptedModules.insert(*it);
			s2e()->getWarningsStream() << "LinuxMemoryTracer: Module " << *it << " is inserted in m_interceptedModules!\n";
        }else {
            s2e()->getWarningsStream() << "LinuxMemoryTracer: Module " << *it << " is not configured\n";
            exit(-1);
        }
    }

	//we use onModuleTransitionSelector from LinuxCodeSelector to select the
    //modules we are going to trace
	m_LinuxCodeSelector->onModuleTransitionSelector.connect(sigc::mem_fun(*this, 
							&LinuxMemoryTracer::onModuleTransition));

}

void LinuxMemoryTracer::onTimer()
{

	s2e()->getWarningsStream() << "LinuxMemoryTracer::onTimer Member is called!" << '\n';
	s2e()->getDebugStream() << "LinuxMemoryTracer::onTimer Member is called!" << '\n';

    if (m_elapsedTics++ < m_timeTrigger) {
        return;
    }

	timeTrigger = true;

	m_timerConnection.disconnect();
}

// This member function connect onTranslateBlockEnd from CorePlugins to make
// sure we intercept sysenter instruction inside the module we are interested,
// and ignore all other sysenter signals.
void LinuxMemoryTracer::onModuleTransition(
        S2EExecutionState *state,
        const ModuleDescriptor *prevModule,
        const ModuleDescriptor *currentModule)
{
	//if current is in the interceptedModules, we intercept the syscalls
	if(m_interceptedModules.find(currentModule->Name) != m_interceptedModules.end()){
		if(!m_privilegeTracking.connected()){
			m_privilegeTracking = s2e()->getCorePlugin()->onPrivilegeChange.connect(
                    sigc::mem_fun(*this, &LinuxMemoryTracer::onPrivilegeChange));
			//s2e()->getDebugStream() << "LinuxSyscallMonitor::onModuleTransition: Connect the onPrivilegeChange! " << "\n";
		}
	}else{//disable intercept the syscalls.
		m_privilegeTracking.disconnect();		
		//s2e()->getDebugStream() << "LinuxSyscallMonitor::onModuleTransition: Disconnect the onPrivilegeChange! " << "\n";
	}
}

/* In onPrivilegeChange, we have detect the privilege change and enable and
 * disable the trace properly. */
void LinuxMemoryTracer::onPrivilegeChange(
        S2EExecutionState *state,
        unsigned previous, unsigned current)
{
    s2e()->getDebugStream() << "LinuxMemoryTracer::onPrivilegeChange: Enter onPrivilegeChange" << '\n';
    //s2e()->getMemoryTypeStream() << "LinuxMemoryTracer::onPrivilegeChange: Enter onPrivilegeChange" << '\n';
	
    //TODO: Have to explicitly make sure we are in the right address space
    // using onPageDirectoryChange
    //Check now if we are in user-mode.
    if (current == 3) { //cpl = 3 indicate user mode
        //Enable tracing in user mode.
		//TODO: we can use a flag to make conditional enable of tracking memory addresses
#if 0
		if(timeTrigger == true) {
			enableTracing();
			s2e()->getDebugStream() << "LinuxMemoryTracer::onPrivilegeChange: enableTracing" << '\n';
			s2e()->getMemoryTypeStream() << "LinuxMemoryTracer::onPrivilegeChange: enableTracing" << '\n';
		}
#endif
        enableTracing(); //start memory tracing in libs
        s2e()->getDebugStream() << "LinuxMemoryTracer::onPrivilegeChange: enableTracing" << '\n';
		//s2e()->getMemoryTypeStream() << "LinuxMemoryTracer::onPrivilegeChange: enableTracing" << '\n';
    } else {
        disableTracing();
        //s2e()->getDebugStream() << "LinuxMemoryTracer::onPrivilegeChange: disableTracing" << '\n';
    }
}

void LinuxMemoryTracer::enableTracing()
{
    if(!m_memoryMonitor.connected()){
        m_memoryMonitor = s2e()->getCorePlugin()->onDataMemoryAccess.connect(
                sigc::mem_fun(*this, &LinuxMemoryTracer::onDataMemoryAccess));

    s2e()->getDebugStream() << "LinuxMemoryTracer::onPrivilegeChange: disableTracing" << '\n';
    }
}

void LinuxMemoryTracer::disableTracing()
{
    m_memoryMonitor.disconnect();
}

void LinuxMemoryTracer::onDataMemoryAccess(S2EExecutionState *state,
                               klee::ref<klee::Expr> address,
                               klee::ref<klee::Expr> hostAddress,
                               klee::ref<klee::Expr> value,
                               bool isWrite, bool isIO)
{
    
	//s2e()->getDebugStream() << "LinuxMemoryTracer::onDataMemoryAccess: Enter onDataMemoryAccess" << '\n';
	DECLARE_PLUGINSTATE(LinuxMemoryTracerState, state);

    bool isAddrCste = isa<klee::ConstantExpr>(address);
    bool isValCste = isa<klee::ConstantExpr>(value);
    bool isHostAddrCste = isa<klee::ConstantExpr>(hostAddress);

    //Output to the trace entry here
    ExecutionTraceMemory e;
    e.flags = 0;
    e.pc = state->getPc();

    uint64_t concreteAddress = 0xdeadbeef;
    uint64_t concreteValue = 0xdeadbeef;
    if (ConcolicMode) {
        klee::ref<klee::ConstantExpr> ce = dyn_cast<klee::ConstantExpr>(state->concolics.evaluate(address));
        concreteAddress = ce->getZExtValue();

        ce = dyn_cast<klee::ConstantExpr>(state->concolics.evaluate(value));
        concreteValue = ce->getZExtValue();
    }

    e.address = isAddrCste ? cast<klee::ConstantExpr>(address)->getZExtValue(64) : concreteAddress;
    e.value = isValCste ? cast<klee::ConstantExpr>(value)->getZExtValue(64) : concreteValue;
    e.size = klee::Expr::getMinBytesForWidth(value->getWidth());
    e.flags = isWrite*EXECTRACE_MEM_WRITE |
                 isIO*EXECTRACE_MEM_IO;

    e.hostAddress = isHostAddrCste ? cast<klee::ConstantExpr>(hostAddress)->getZExtValue(64) : 0xDEADBEEF;

    std::string type;
    type = e.flags & EXECTRACE_MEM_WRITE ? "W" : "R";
    if(type == "W")
        //s2e()->getDebugStream() << "[" << hexval(e.address) << "]=" <<  hexval(e.value) << '\n';
    
    //m_tracer->writeData(state, &e, sizeof(e), TRACE_MEMORY);

	overWrittenAddressesCollection(state, e.address, e.flags);

	uint64_t timestamp = llvm::sys::TimeValue::now().usec();
	//TODO:fix the parameters will be in this version of function. 
	plgState->overWrittenAddressesStateCollection(timestamp, e.address, e.flags);//add timestamp inside the function call
}

void LinuxMemoryTracerState::overWrittenAddressesStateCollection(uint64_t timestamp, 
													uint64_t address, uint8_t flags)
{
	if(flags & EXECTRACE_MEM_WRITE){
		m_overWrittenAddressesState.insert(std::pair<uint64_t, uint64_t>(address, timestamp));
		//s2e()->getWarningsStream(state) << "StateID: [ " << state->getID() << " ] " << "Over Written Addresses: " << hexval(address) << '\n';	
	}
}

/* TODO: have to set the memory dump eip by annotation plugin*/
void LinuxMemoryTracer::overWrittenAddressesCollection(S2EExecutionState *state, 
													uint64_t address, uint8_t flags)
{
	if(flags & EXECTRACE_MEM_WRITE){
		m_overWrittenAddressesId.insert(std::pair<uint32_t, uint64_t>(state->getID(), address));
		//s2e()->getWarningsStream(state) << "StateID: [ " << state->getID() << " ] " << "Over Written Addresses: " << hexval(address) << '\n';	
	}
}

bool LinuxMemoryTracer::checkOverWrittenAddressesByState(
		S2EExecutionState *state,
        uint64_t address,
        uint32_t &PtrCounts,
        uint32_t &OWCounts)
{
	DECLARE_PLUGINSTATE(LinuxMemoryTracerState, state);
	if(address < 0x00ffffff){ //this is to hack the non pointer value in the captured parameters.
		return false;
    }

    PtrCounts++;
	//TODO: how to find the address and increment the counts.
	
	std::pair <std::multimap<uint64_t, uint64_t>::iterator, std::multimap<uint64_t, uint64_t>::iterator> ret;
	ret = plgState->m_overWrittenAddressesState.equal_range(address);
	for(std::multimap<uint64_t, uint64_t>::iterator it = ret.first; it != ret.second; ++it){
		if(address > 0x00ffffff && it->first == address){
			s2e()->getDebugStream() << "Caution:: OW Address: [ " << hexval(it->first) << " ] " << "timestamp: " << it->second << '\n';
            OWCounts++;
			return true;
		}
	}

	return false;
}

bool LinuxMemoryTracer::checkOverWrittenAddressesById(
        uint32_t stateId, 
        uint64_t address,
        uint32_t &PtrCounts,
        uint32_t &OWCounts)
{
	if(address < 0x00ffffff){ //this is to hack the non pointer value in the captured parameters.
		return false;
    }

    PtrCounts++;

	std::pair <std::multimap<uint32_t, uint64_t>::iterator, std::multimap<uint32_t, uint64_t>::iterator> ret;
	ret = m_overWrittenAddressesId.equal_range(stateId);
	for(overWrittenAddressesId::iterator it = ret.first; it != ret.second; ++it){
		if(address > 0x00ffffff && it->second == address){
			//s2e()->getDebugStream() << "Caution:: StateID: [ " << it->first << " ] " << "Over Written Addresses: " << it->second << '\n';
            OWCounts++;
			return true;
		}
	}

	return false;
}

bool LinuxMemoryTracer::checkOverWrittenAddressesById( uint32_t stateId, uint64_t address)
{
	if(address < 0x00ffffff) //this is to hack the non pointer value in the captured parameters.
		return false;

	std::pair <std::multimap<uint32_t, uint64_t>::iterator, std::multimap<uint32_t, uint64_t>::iterator> ret;
	ret = m_overWrittenAddressesId.equal_range(stateId);
	for(overWrittenAddressesId::iterator it = ret.first; it != ret.second; ++it){
		if(address > 0x00ffffff && it->second == address){
			//s2e()->getDebugStream() << "Caution:: StateID: [ " << it->first << " ] " << "Over Written Addresses: " << it->second << '\n';
			return true;
		}
	}

	return false;
}

LinuxMemoryTracerState* LinuxMemoryTracerState::clone() const
{
	LinuxMemoryTracerState *ret = new LinuxMemoryTracerState(*this);
	
    return ret;
}

PluginState *LinuxMemoryTracerState::factory(Plugin *p, S2EExecutionState *s)
{
	LinuxMemoryTracerState *ret = new LinuxMemoryTracerState();
    //ret->m_plugin = static_cast<LinuxSyscallMonitor*>(p);
    return ret;
}


}
}
